//! The async driver over a link that misbehaves.
//!
//! [`udt_proto`]'s own simulator covers the state machine under loss and
//! reordering, but it runs on virtual time with no sockets, so it says nothing
//! about the driver: batching, receive offload, the pacing timer against a real
//! clock, or the endpoint reader. These tests put a UDP relay between two real
//! endpoints and have it drop, delay and reorder.
//!
//! A relay rather than `tc netem` because it needs no root and runs the same on
//! every platform. netem is still worth reaching for when kernel-level fidelity
//! matters — queue disciplines, correlated loss — but it cannot run in CI here.

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use tokio::net::UdpSocket;
    use udt_async::{Endpoint, Socket};

    /// How the relay treats each datagram crossing it.
    #[derive(Clone, Copy)]
    struct RelayConfig {
        /// Fraction dropped, as a percentage.
        loss_pct: u64,
        /// Extra delay applied to a fraction of datagrams, which reorders them
        /// relative to the rest.
        jitter: Option<(u64, Duration)>,
    }

    impl RelayConfig {
        fn lossy(loss_pct: u64) -> Self {
            RelayConfig { loss_pct, jitter: None }
        }

        fn reordering(pct: u64, delay: Duration) -> Self {
            RelayConfig { loss_pct: 0, jitter: Some((pct, delay)) }
        }
    }

    /// Counters the relay keeps so a test can prove it actually interfered.
    #[derive(Default)]
    struct RelayStats {
        forwarded: AtomicU64,
        dropped: AtomicU64,
        delayed: AtomicU64,
    }

    /// Start a relay in front of `server`, returning the address to dial and
    /// its counters.
    ///
    /// Datagrams from the server go to the last address that sent us anything
    /// else, which is all the bookkeeping one connection through one relay
    /// needs.
    async fn spawn_relay(server: SocketAddr, cfg: RelayConfig) -> (SocketAddr, Arc<RelayStats>) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let stats = Arc::new(RelayStats::default());

        let task_sock = Arc::clone(&sock);
        let task_stats = Arc::clone(&stats);
        tokio::spawn(async move {
            // Deterministic enough to be reproducible, varied enough not to
            // land on a pattern that matches the protocol's own periods.
            let mut counter = 0u64;
            let mut client: Option<SocketAddr> = None;
            let mut buf = vec![0u8; 64 * 1024];

            loop {
                let Ok((n, from)) = task_sock.recv_from(&mut buf).await else { return };
                let to = if from == server {
                    match client {
                        Some(c) => c,
                        None => continue,
                    }
                } else {
                    client = Some(from);
                    server
                };

                counter = counter.wrapping_mul(6364136223846793005).wrapping_add(1);
                let roll = (counter >> 33) % 100;

                if roll < cfg.loss_pct {
                    task_stats.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                task_stats.forwarded.fetch_add(1, Ordering::Relaxed);

                match cfg.jitter {
                    Some((pct, delay)) if roll < cfg.loss_pct + pct => {
                        task_stats.delayed.fetch_add(1, Ordering::Relaxed);
                        // Held in its own task so later datagrams overtake it.
                        let datagram = buf[..n].to_vec();
                        let sock = Arc::clone(&task_sock);
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = sock.send_to(&datagram, to).await;
                        });
                    }
                    _ => {
                        let _ = task_sock.send_to(&buf[..n], to).await;
                    }
                }
            }
        });

        (addr, stats)
    }

    /// A connected pair whose traffic crosses a misbehaving relay.
    async fn relayed_pair(cfg: RelayConfig) -> (Socket, Socket, Arc<RelayStats>) {
        let server_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let listener = server_ep.listen(4).unwrap();
        let (relay_addr, stats) = spawn_relay(server_ep.local_addr(), cfg).await;

        let client_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let (server, client) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(30), listener.accept())
                    .await
                    .expect("accept timed out")
                    .expect("accept failed")
            },
            async {
                tokio::time::timeout(Duration::from_secs(30), client_ep.connect(relay_addr))
                    .await
                    .expect("connect timed out")
                    .expect("connect failed")
            }
        );
        // Endpoints stay alive as long as their connections do, so leak the
        // handles rather than letting the drop wind the readers down.
        std::mem::forget(server_ep);
        std::mem::forget(client_ep);
        (server, client, stats)
    }

    fn payload(index: usize, size: usize) -> Vec<u8> {
        let mut v = vec![0u8; size];
        v[..4].copy_from_slice(&(index as u32).to_be_bytes());
        for (i, b) in v.iter_mut().enumerate().skip(4) {
            *b = (index as u8).wrapping_add(i as u8);
        }
        v
    }

    /// Send `count` messages one way and verify every byte arrives in order.
    async fn verify_transfer(server: Socket, client: Socket, count: usize, size: usize) {
        let sender = tokio::spawn(async move {
            for i in 0..count {
                client.send(&payload(i, size)).await.expect("send failed");
            }
            client
        });

        let mut buf = vec![0u8; size * 2];
        for i in 0..count {
            let n = tokio::time::timeout(Duration::from_secs(60), server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for message {i} of {count}"))
                .expect("recv failed");
            assert_eq!(n, size, "message {i} has the wrong length");
            assert_eq!(&buf[..n], &payload(i, size)[..], "message {i} corrupted");
        }
        let _client = sender.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_completes_through_a_lossy_relay() {
        let (_server, _client, stats) = relayed_pair(RelayConfig::lossy(40)).await;
        assert!(stats.dropped.load(Ordering::Relaxed) > 0, "relay dropped nothing");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transfer_is_intact_through_two_percent_loss() {
        let (server, client, stats) = relayed_pair(RelayConfig::lossy(2)).await;
        verify_transfer(server, client, 200, 8192).await;
        assert!(stats.dropped.load(Ordering::Relaxed) > 0, "relay dropped nothing");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transfer_is_intact_through_reordering() {
        let cfg = RelayConfig::reordering(10, Duration::from_millis(4));
        let (server, client, stats) = relayed_pair(cfg).await;
        verify_transfer(server, client, 200, 8192).await;
        assert!(stats.delayed.load(Ordering::Relaxed) > 0, "relay reordered nothing");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transfer_is_intact_through_loss_and_reordering() {
        let cfg = RelayConfig { loss_pct: 2, jitter: Some((8, Duration::from_millis(3))) };
        let (server, client, stats) = relayed_pair(cfg).await;
        verify_transfer(server, client, 150, 16384).await;
        assert!(stats.dropped.load(Ordering::Relaxed) > 0);
        assert!(stats.delayed.load(Ordering::Relaxed) > 0);
    }

    /// Heavier than the rest, so it stays out of the default run.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "slow: several seconds of recovery at 10% loss"]
    async fn transfer_is_intact_through_ten_percent_loss() {
        let (server, client, stats) = relayed_pair(RelayConfig::lossy(10)).await;
        verify_transfer(server, client, 200, 8192).await;
        assert!(stats.dropped.load(Ordering::Relaxed) > 0);
    }
}
