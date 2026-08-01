//! Smoke tests of the Rust implementation against **unmodified upstream UDT**.
//!
//! `udt-compat` wraps a heavily-modified fork of upstream. These tests exist to
//! catch protocol regressions introduced by those modifications, and to prove
//! the Rust implementation interoperates with stock UDT rather than only with
//! the fork.
//!
//! Upstream has no async readiness mechanism, so every upstream call blocks and
//! is hoisted onto `spawn_blocking`. Joins are wrapped in `tokio::time::timeout`
//! so a stall fails the test instead of hanging the run; `udt-orig` also sets
//! UDT-level send/receive timeouts as a second line of defence.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use udt_async::{Connection as UdtConn, Endpoint};

    /// Generous, but bounded — these paths block real OS threads.
    const T: Duration = Duration::from_secs(30);

    /// Distinct fill per message, so a dropped or reordered message is caught
    /// rather than masked by uniform bytes.
    fn pattern(i: usize) -> u8 {
        (i % 251) as u8
    }

    async fn join<T2: Send + 'static>(h: tokio::task::JoinHandle<T2>, what: &str) -> T2 {
        tokio::time::timeout(T, h)
            .await
            .unwrap_or_else(|_| panic!("{what} timed out"))
            .unwrap_or_else(|e| panic!("{what} panicked: {e}"))
    }

    // ── Pair construction ────────────────────────────────────────────────────

    /// Endpoints and listeners a test must keep alive for its whole duration.
    ///
    /// Dropping an upstream `Endpoint` closes its bound UDT socket, and closing
    /// any socket on a connection causes the peer to mark it broken and
    /// eventually garbage-collect the receive buffer — discarding messages the
    /// application had not yet read. Holding these in the test's scope keeps
    /// teardown out of the measurement.
    #[allow(dead_code)]
    struct Keepalive(Vec<Box<dyn std::any::Any + Send>>);

    /// Upstream listener + upstream connector. Proves the harness itself works
    /// before any of it is used to judge the Rust side.
    fn orig_pair() -> (udt_orig::Connection, udt_orig::Connection, Keepalive) {
        let server_ep = udt_orig::Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let listener = server_ep.listen(4).unwrap();

        let client_ep = udt_orig::Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let accept = std::thread::spawn(move || (listener.accept(), listener));

        let client = client_ep
            .connect(server_addr, false)
            .expect("upstream connect failed");
        let (server, listener) = accept.join().expect("accept thread panicked");
        let server = server.expect("upstream accept failed");
        (
            server,
            client,
            Keepalive(vec![
                Box::new(server_ep),
                Box::new(client_ep),
                Box::new(listener),
            ]),
        )
    }

    /// Upstream listener + Rust connector.
    async fn orig_listener_rust_connector() -> (Arc<udt_orig::Connection>, UdtConn, Keepalive) {
        let server_ep = udt_orig::Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let listener = server_ep.listen(4).unwrap();

        let accept = tokio::task::spawn_blocking(move || (listener.accept(), listener));

        let rust_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::time::timeout(T, rust_ep.connect(server_addr))
            .await
            .expect("rust connect timed out")
            .expect("rust connect failed");

        let (server, listener) = join(accept, "upstream accept").await;
        let server = server.expect("upstream accept failed");
        (
            Arc::new(server),
            client,
            Keepalive(vec![
                Box::new(server_ep),
                Box::new(rust_ep),
                Box::new(listener),
            ]),
        )
    }

    /// Rust listener + upstream connector.
    async fn rust_listener_orig_connector() -> (UdtConn, Arc<udt_orig::Connection>, Keepalive) {
        let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let server_addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();

        let connect = tokio::task::spawn_blocking(move || {
            let client_ep = udt_orig::Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            (client_ep.connect(server_addr, false), client_ep)
        });

        let server = tokio::time::timeout(T, listener.accept())
            .await
            .expect("rust accept timed out")
            .expect("rust accept failed");
        let (client, client_ep) = join(connect, "upstream connect").await;
        let client = client.expect("upstream connect failed");
        (
            server,
            Arc::new(client),
            Keepalive(vec![Box::new(ep), Box::new(listener), Box::new(client_ep)]),
        )
    }

    // ── Harness self-check ───────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn orig_to_orig_smoke() {
        let (server, client, _keep) = tokio::task::spawn_blocking(orig_pair).await.unwrap();
        let payload = vec![0xABu8; 4096];

        let p = payload.clone();
        let send = tokio::task::spawn_blocking(move || client.send(&p).map(|n| (n, client)));
        let recv = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 8192];
            server.recv(&mut buf).map(|n| (n, buf))
        });

        let (sent, _client) = join(send, "upstream send")
            .await
            .expect("upstream send failed");
        let (n, buf) = join(recv, "upstream recv")
            .await
            .expect("upstream recv failed");
        assert_eq!(sent, payload.len());
        assert_eq!(
            &buf[..n],
            &payload[..],
            "upstream↔upstream corrupted its own payload"
        );
    }

    // ── Handshake + echo, both directions ────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn rust_connector_upstream_listener_echo() {
        let (server, client, _keep) = orig_listener_rust_connector().await;
        let payload = vec![0x42u8; 4096];

        client.send(&payload).await.expect("rust send failed");

        let s = Arc::clone(&server);
        let recv = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 8192];
            s.recv(&mut buf).map(|n| (n, buf))
        });
        let (n, buf) = join(recv, "upstream recv")
            .await
            .expect("upstream recv failed");
        assert_eq!(
            &buf[..n],
            &payload[..],
            "upstream received wrong data from Rust"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn upstream_connector_rust_listener_echo() {
        let (server, client, _keep) = rust_listener_orig_connector().await;
        let payload = vec![0x37u8; 4096];

        let p = payload.clone();
        let c = Arc::clone(&client);
        let send = tokio::task::spawn_blocking(move || c.send(&p));
        join(send, "upstream send")
            .await
            .expect("upstream send failed");

        let mut buf = vec![0u8; 8192];
        let n = tokio::time::timeout(T, server.recv(&mut buf))
            .await
            .expect("rust recv timed out")
            .expect("rust recv failed");
        assert_eq!(
            &buf[..n],
            &payload[..],
            "Rust received wrong data from upstream"
        );
    }

    // ── Bulk transfer, every byte verified ───────────────────────────────────

    const BULK_MSGS: usize = 400;
    const BULK_CHUNK: usize = 4096;

    // NOTE on socket lifetime: the Rust write half must stay alive until the
    // peer has finished *reading*, not merely until we finish writing. Dropping
    // it closes the send channel, which the driver correctly reads as a
    // half-close and answers with a Shutdown once the send buffer drains.
    // Upstream then marks the socket broken and its GC (`m_iBrokenCounter`)
    // frees the receive buffer, discarding messages the application had not yet
    // read — so the transfer truncates even though every byte was acknowledged.
    // Hence `into_split` and holding the write half in the outer scope.

    /// Same shape as `bulk_rust_to_upstream_verified`, but upstream on both
    /// ends. This is the control: if upstream cannot sustain this pattern
    /// against itself, a Rust-side failure here is not evidence of a Rust bug.
    #[tokio::test(flavor = "multi_thread")]
    async fn bulk_upstream_to_upstream_verified() {
        let (server, client, _keep) = tokio::task::spawn_blocking(orig_pair).await.unwrap();

        let send = tokio::task::spawn_blocking(move || {
            for i in 0..BULK_MSGS {
                let chunk = vec![pattern(i); BULK_CHUNK];
                client
                    .send(&chunk)
                    .unwrap_or_else(|e| panic!("upstream send failed on message {i}: {e}"));
            }
            client
        });

        let recv = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; BULK_CHUNK * 2];
            for i in 0..BULK_MSGS {
                let n = server
                    .recv(&mut buf)
                    .unwrap_or_else(|e| panic!("upstream recv failed on message {i}: {e}"));
                assert_eq!(n, BULK_CHUNK, "message {i} wrong length");
                assert!(
                    buf[..n].iter().all(|&b| b == pattern(i)),
                    "message {i} corrupted"
                );
            }
        });

        join(recv, "upstream→upstream bulk recv").await;
        let _held = join(send, "upstream→upstream bulk send").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bulk_rust_to_upstream_verified() {
        let (server, client, _keep) = orig_listener_rust_connector().await;
        let write = std::sync::Arc::new(client);
        let write = Arc::new(write);

        let w = Arc::clone(&write);
        let sender = tokio::spawn(async move {
            for i in 0..BULK_MSGS {
                let chunk = vec![pattern(i); BULK_CHUNK];
                w.send(&chunk).await.expect("rust send failed");
            }
        });

        let recv = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; BULK_CHUNK * 2];
            for i in 0..BULK_MSGS {
                let n = server
                    .recv(&mut buf)
                    .unwrap_or_else(|e| panic!("upstream recv failed on message {i}: {e}"));
                assert_eq!(
                    n, BULK_CHUNK,
                    "message {i} arrived upstream with wrong length"
                );
                assert!(
                    buf[..n].iter().all(|&b| b == pattern(i)),
                    "message {i} corrupted in transit to upstream",
                );
            }
        });

        join(recv, "upstream bulk recv").await;
        sender.await.unwrap();
        drop(write);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bulk_upstream_to_rust_verified() {
        let (server, client, _keep) = rust_listener_orig_connector().await;

        let sender = tokio::task::spawn_blocking(move || {
            for i in 0..BULK_MSGS {
                let chunk = vec![pattern(i); BULK_CHUNK];
                client
                    .send(&chunk)
                    .unwrap_or_else(|e| panic!("upstream send failed on message {i}: {e}"));
            }
            client
        });

        let mut buf = vec![0u8; BULK_CHUNK * 2];
        for i in 0..BULK_MSGS {
            let n = tokio::time::timeout(T, server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("rust recv timed out on message {i} of {BULK_MSGS}"))
                .expect("rust recv failed");
            assert_eq!(
                n, BULK_CHUNK,
                "message {i} arrived at Rust with wrong length"
            );
            assert!(
                buf[..n].iter().all(|&b| b == pattern(i)),
                "message {i} corrupted in transit from upstream",
            );
        }
        let _held = join(sender, "upstream bulk send").await;
    }

    // ── Extended ACKs against pristine upstream ──────────────────────────────

    /// Forward datagrams to `server`, dropping `loss_pct` of them, and count the
    /// ACKs coming back that carry more than UDT's documented 24-byte body.
    async fn lossy_relay(
        server: std::net::SocketAddr,
        loss_pct: u64,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicU64>) {
        use std::sync::atomic::{AtomicU64, Ordering};
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let extended = Arc::new(AtomicU64::new(0));

        let task_sock = Arc::clone(&sock);
        let task_extended = Arc::clone(&extended);
        tokio::spawn(async move {
            let mut counter = 0u64;
            let mut client: Option<std::net::SocketAddr> = None;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let Ok((n, from)) = task_sock.recv_from(&mut buf).await else {
                    return;
                };
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
                    continue;
                }
                // Control packet (word 0 bit 31), type 2 (ACK), body past 24.
                if n > 16 + 24 {
                    let w0 = u32::from_be_bytes(buf[0..4].try_into().unwrap());
                    if w0 >> 31 == 1 && (w0 >> 16) & 0x7FFF == 2 {
                        task_extended.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let _ = task_sock.send_to(&buf[..n], to).await;
            }
        });
        (addr, extended)
    }

    /// Pristine upstream must keep working against a Rust receiver whose ACKs
    /// carry selective-acknowledgement ranges it knows nothing about.
    ///
    /// The fork is covered by `cpp_tolerates_our_extended_acks` in cpp-interop,
    /// but the fork is not upstream — this asks the same question of unmodified
    /// dorkbox/udt. Loss is what makes the Rust receiver emit ranges at all, and
    /// the counter proves some crossed the wire rather than letting the test
    /// pass while asserting nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn upstream_tolerates_our_extended_acks() {
        use std::sync::atomic::Ordering;
        const MSGS: usize = 60;

        let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let listener = ep.listen(4).unwrap();
        let (relay_addr, extended) = lossy_relay(ep.local_addr(), 5).await;

        let connect = tokio::task::spawn_blocking(move || {
            let client_ep = udt_orig::Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            (client_ep.connect(relay_addr, false), client_ep)
        });
        let server = tokio::time::timeout(T, listener.accept())
            .await
            .expect("rust accept timed out")
            .expect("rust accept failed");
        let (client, _client_ep) = join(connect, "upstream connect through relay").await;
        let client = client.expect("upstream connect failed");

        let sender = tokio::task::spawn_blocking(move || {
            for i in 0..MSGS {
                let chunk = vec![pattern(i); BULK_CHUNK];
                if client.send(&chunk).is_err() {
                    break;
                }
            }
            client
        });

        let mut buf = vec![0u8; BULK_CHUNK * 2];
        for i in 0..MSGS {
            let n = tokio::time::timeout(T, server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "upstream stopped making progress against a Rust receiver \
                         sending extended ACKs: timed out on message {i} of {MSGS}"
                    )
                })
                .expect("rust recv failed");
            assert_eq!(n, BULK_CHUNK, "message {i} arrived with the wrong length");
            assert!(
                buf[..n].iter().all(|&b| b == pattern(i)),
                "message {i} corrupted in transit from upstream",
            );
        }
        let _held = join(sender, "upstream send through relay").await;

        assert!(
            extended.load(Ordering::Relaxed) > 0,
            "no extended ACK crossed the wire, so upstream was never asked to \
             tolerate one and this test proves nothing",
        );
    }

    // ── Message boundaries ───────────────────────────────────────────────────
    //
    // Upstream computes its payload size as `MSS - 28 - 16` = 1456 bytes, while
    // the fork (and therefore this Rust implementation) uses `MSS - 48 - 16` =
    // 1436. Reassembly is driven by the per-packet boundary flags rather than
    // by size, so the two should still interoperate — these sizes straddle both
    // boundaries to prove it.

    const BOUNDARY_SIZES: &[usize] = &[
        1, 1435, 1436, 1437, // around the Rust/fork payload size
        1455, 1456, 1457, // around the upstream payload size
        2872, 2912, 5000, 65536,
    ];

    fn boundary_msg(i: usize, size: usize) -> Vec<u8> {
        (0..size).map(|b| b.wrapping_add(i) as u8).collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn message_boundaries_rust_to_upstream() {
        let (server, client, _keep) = orig_listener_rust_connector().await;
        let write = std::sync::Arc::new(client);
        let write = Arc::new(write);

        let w = Arc::clone(&write);
        let sender = tokio::spawn(async move {
            for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
                w.send(&boundary_msg(i, size))
                    .await
                    .expect("rust send failed");
            }
        });

        let recv = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 131072];
            for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
                let n = server
                    .recv(&mut buf)
                    .unwrap_or_else(|e| panic!("upstream recv failed on {size}-byte message: {e}"));
                assert_eq!(
                    n, size,
                    "upstream saw a different message length (message {i})"
                );
                assert_eq!(
                    &buf[..n],
                    &boundary_msg(i, size)[..],
                    "{size}-byte message corrupted"
                );
            }
        });

        join(recv, "upstream boundary recv").await;
        sender.await.unwrap();
        drop(write);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn message_boundaries_upstream_to_rust() {
        let (server, client, _keep) = rust_listener_orig_connector().await;

        let sender = tokio::task::spawn_blocking(move || {
            for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
                client
                    .send(&boundary_msg(i, size))
                    .unwrap_or_else(|e| panic!("upstream send failed on {size}-byte message: {e}"));
            }
            client
        });

        let mut buf = vec![0u8; 131072];
        for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
            let n = tokio::time::timeout(T, server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("rust recv timed out on {size}-byte message"))
                .expect("rust recv failed");
            assert_eq!(n, size, "Rust saw a different message length (message {i})");
            assert_eq!(
                &buf[..n],
                &boundary_msg(i, size)[..],
                "{size}-byte message corrupted"
            );
        }
        let _held = join(sender, "upstream boundary send").await;
    }
}
