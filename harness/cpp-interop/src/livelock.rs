//! Characterising the reported C++ out-of-order livelock.
//!
//! The claim these tests exist to check: sending out of order at full
//! throughput wedges the C++ implementation, which then spends its time
//! retransmitting packets the receiver has long since moved past.
//!
//! Loopback alone never reproduced it — it drops nothing, so the sender never
//! has to retransmit at all. These runs put a lossy relay in the path, which is
//! the missing ingredient, and report what each implementation does rather than
//! asserting: the decision on this codebase was to fix the Rust side and
//! document where the C++ diverges, so a failure here is a finding, not a
//! regression.
//!
//! All of them are `#[ignore]`d. They are diagnostics, they take seconds, and
//! the C++ ones are expected to behave badly.

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::net::UdpSocket;
    use udt_async::{Endpoint, SendOptions};

    const CHUNK: usize = 8192;
    const MSGS: usize = 400;
    /// Generous: the point is to distinguish "slow" from "not progressing".
    const BUDGET: Duration = Duration::from_secs(20);

    struct Relay {
        dropped: AtomicU64,
        forwarded: AtomicU64,
    }

    /// Drop `loss_pct` of datagrams in both directions.
    async fn spawn_relay(server: SocketAddr, loss_pct: u64) -> (SocketAddr, Arc<Relay>) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let relay = Arc::new(Relay { dropped: AtomicU64::new(0), forwarded: AtomicU64::new(0) });

        let task_sock = Arc::clone(&sock);
        let task_relay = Arc::clone(&relay);
        tokio::spawn(async move {
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
                if (counter >> 33) % 100 < loss_pct {
                    task_relay.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                task_relay.forwarded.fetch_add(1, Ordering::Relaxed);
                let _ = task_sock.send_to(&buf[..n], to).await;
            }
        });
        (addr, relay)
    }

    /// How far a transfer got, and whether it was still moving when time ran
    /// out. A livelock shows up as progress stopping while packets keep
    /// flowing.
    struct Outcome {
        delivered: usize,
        elapsed: Duration,
        finished: bool,
        relay_forwarded: u64,
        relay_dropped: u64,
    }

    impl Outcome {
        fn report(&self, label: &str) {
            let rate = if self.elapsed.as_secs_f64() > 0.0 {
                (self.delivered * CHUNK) as f64 / self.elapsed.as_secs_f64() / 1e6
            } else {
                0.0
            };
            println!(
                "[{label:<28}] {}/{} msgs in {:>6.2}s  {rate:>7.1} MB/s  \
                 relay fwd={} drop={}  {}",
                self.delivered,
                MSGS,
                self.elapsed.as_secs_f64(),
                self.relay_forwarded,
                self.relay_dropped,
                if self.finished { "completed" } else { "DID NOT COMPLETE" },
            );
        }
    }

    async fn rust_unordered_through_loss(loss_pct: u64) -> Outcome {
        let server_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let listener = server_ep.listen(4).unwrap();
        let (relay_addr, relay) = spawn_relay(server_ep.local_addr(), loss_pct).await;
        let client_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();

        let (server, client) = tokio::join!(
            async { listener.accept().await.expect("accept") },
            async { client_ep.connect(relay_addr).await.expect("connect") }
        );

        let start = Instant::now();
        let sender = tokio::spawn(async move {
            let chunk = vec![0xA5u8; CHUNK];
            for _ in 0..MSGS {
                if client.send_with(&chunk, SendOptions::new().unordered()).await.is_err() {
                    break;
                }
            }
            client
        });

        let mut delivered = 0usize;
        let mut buf = vec![0u8; CHUNK * 2];
        while delivered < MSGS && start.elapsed() < BUDGET {
            match tokio::time::timeout(Duration::from_secs(2), server.recv(&mut buf)).await {
                Ok(Ok(_)) => delivered += 1,
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
        let elapsed = start.elapsed();
        sender.abort();
        Outcome {
            delivered,
            elapsed,
            finished: delivered >= MSGS,
            relay_forwarded: relay.forwarded.load(Ordering::Relaxed),
            relay_dropped: relay.dropped.load(Ordering::Relaxed),
        }
    }

    async fn cpp_unordered_through_loss(loss_pct: u64) -> Outcome {
        use udt_compat::Endpoint as CppEndpoint;

        let server_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let listener = server_ep.listen(4).unwrap();
        let (relay_addr, relay) = spawn_relay(server_ep.local_addr().unwrap(), loss_pct).await;
        let client_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());

        let (server, client) = tokio::join!(
            async { listener.accept().await.expect("cpp accept") },
            async { client_ep.connect(relay_addr, false).await.expect("cpp connect") }
        );
        let server = Arc::new(server);
        let client = Arc::new(client);

        let start = Instant::now();
        let sender = {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                let chunk = vec![0xA5u8; CHUNK];
                for _ in 0..MSGS {
                    if client.send_with(&chunk, None, false).await.is_err() {
                        break;
                    }
                }
            })
        };

        let mut delivered = 0usize;
        let mut buf = vec![0u8; CHUNK * 2];
        while delivered < MSGS && start.elapsed() < BUDGET {
            match tokio::time::timeout(Duration::from_secs(2), server.recv(&mut buf)).await {
                Ok(Ok(_)) => delivered += 1,
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
        let elapsed = start.elapsed();
        sender.abort();
        Outcome {
            delivered,
            elapsed,
            finished: delivered >= MSGS,
            relay_forwarded: relay.forwarded.load(Ordering::Relaxed),
            relay_dropped: relay.dropped.load(Ordering::Relaxed),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "diagnostic: characterises behaviour, does not assert"]
    async fn compare_unordered_under_loss() {
        for loss in [0u64, 2, 5] {
            rust_unordered_through_loss(loss).await.report(&format!("rust unordered {loss}% loss"));
        }
        for loss in [0u64, 2, 5] {
            cpp_unordered_through_loss(loss).await.report(&format!("cpp  unordered {loss}% loss"));
        }
    }

    /// The one behavioural claim worth asserting: the Rust side keeps moving.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "slow: seconds of loss recovery"]
    async fn rust_unordered_makes_progress_under_loss() {
        let outcome = rust_unordered_through_loss(5).await;
        outcome.report("rust unordered 5% loss");
        assert!(
            outcome.finished,
            "delivered only {}/{MSGS} in {:?}",
            outcome.delivered, outcome.elapsed
        );
    }
}
