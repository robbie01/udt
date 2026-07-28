#![forbid(unsafe_code)]

mod relay;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use udt_async::{Endpoint, EndpointConfig, SendOptions, Socket};

    const SMALL: &[u8] = b"hello, world!   "; // 16 bytes — single packet
    fn medium() -> Vec<u8> {
        vec![0x42u8; 4096]
    } // 3 packets at default MSS (payload=1436B)
    fn large() -> Vec<u8> {
        vec![0x7fu8; 65536]
    } // ~45 packets

    // ── Pure Rust helpers ────────────────────────────────────────────────────

    async fn new_listener_pair(listener_addr: SocketAddr) -> (Socket, Socket) {
        let ep = Endpoint::bind(listener_addr).await.unwrap();
        let server_addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();

        let (server_sock, client_sock) =
            tokio::join!(async { listener.accept().await.unwrap() }, async {
                let cep = Endpoint::bind("127.0.0.1:0").await.unwrap();
                tokio::time::timeout(Duration::from_secs(5), cep.connect(server_addr))
                    .await
                    .expect("connect timed out")
                    .expect("connect failed")
            });
        (server_sock, client_sock)
    }

    async fn echo_exchange(server: Socket, client: Socket, payload: &[u8], count: usize) {
        let mut buf = vec![0u8; 131072];
        for _ in 0..count {
            // Client → Server
            tokio::time::timeout(Duration::from_secs(5), client.send(payload))
                .await
                .expect("send timed out")
                .expect("send failed");

            let n = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
                .await
                .expect("server recv timed out")
                .expect("server recv failed");
            assert_eq!(&buf[..n], payload, "server received wrong data");

            // Server → Client echo
            tokio::time::timeout(Duration::from_secs(5), server.send(&buf[..n]))
                .await
                .expect("echo send timed out")
                .expect("echo send failed");

            let n2 = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
                .await
                .expect("client recv timed out")
                .expect("client recv failed");
            assert_eq!(&buf[..n2], payload, "client received wrong echo");
        }
    }

    // ── Scenario 1: new listener + new connector ─────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn s1_new_new_small() {
        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        echo_exchange(server, client, SMALL, 10).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s1_new_new_medium() {
        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        echo_exchange(server, client, &medium(), 5).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s1_new_new_large() {
        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        echo_exchange(server, client, &large(), 3).await;
    }

    // ── Scenario 4: rendezvous both new ──────────────────────────────────────

    async fn new_rendezvous_pair() -> (Socket, Socket) {
        let ep_a = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let ep_b = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let addr_a = ep_a.local_addr();
        let addr_b = ep_b.local_addr();

        let (sock_a, sock_b) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(5), ep_a.connect_rendezvous(addr_b))
                    .await
                    .expect("rendezvous A timed out")
                    .expect("rendezvous A failed")
            },
            async {
                tokio::time::timeout(Duration::from_secs(5), ep_b.connect_rendezvous(addr_a))
                    .await
                    .expect("rendezvous B timed out")
                    .expect("rendezvous B failed")
            }
        );
        (sock_a, sock_b)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s4_rendezvous_new_new_small() {
        let (a, b) = new_rendezvous_pair().await;
        echo_exchange(a, b, SMALL, 10).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s4_rendezvous_new_new_medium() {
        let (a, b) = new_rendezvous_pair().await;
        echo_exchange(a, b, &medium(), 5).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s4_rendezvous_new_new_large() {
        let (a, b) = new_rendezvous_pair().await;
        echo_exchange(a, b, &large(), 3).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s6_multi_connection_same_listener() {
        const N: usize = 4;

        let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let server_addr = ep.local_addr();
        let listener = ep.listen(N + 1).unwrap();

        // Spawn N clients simultaneously.
        let client_tasks: Vec<_> = (0usize..N)
            .map(|i| {
                let payload = vec![(i as u8).wrapping_add(0x41); 3000]; // 'A', 'B', 'C', 'D' repeated
                tokio::spawn(async move {
                    let cep = Endpoint::bind("127.0.0.1:0").await.unwrap();
                    let sock =
                        tokio::time::timeout(Duration::from_secs(5), cep.connect(server_addr))
                            .await
                            .expect("connect timed out")
                            .expect("connect failed");

                    // Send our distinctive payload.
                    tokio::time::timeout(Duration::from_secs(5), sock.send(&payload))
                        .await
                        .expect("send timed out")
                        .expect("send failed");

                    // Receive the echo.
                    let mut buf = vec![0u8; 131072];
                    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
                        .await
                        .expect("recv timed out")
                        .expect("recv failed");

                    assert_eq!(
                        &buf[..n],
                        &payload,
                        "client {} received wrong echo (commingling?)",
                        i
                    );
                })
            })
            .collect();

        // Accept N connections on the server side and echo each payload back.
        let mut server_tasks = Vec::new();
        for _ in 0..N {
            let server_sock = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("accept timed out")
                .expect("accept failed");

            server_tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 131072];
                let n = tokio::time::timeout(Duration::from_secs(5), server_sock.recv(&mut buf))
                    .await
                    .expect("server recv timed out")
                    .expect("server recv failed");
                tokio::time::timeout(Duration::from_secs(5), server_sock.send(&buf[..n]))
                    .await
                    .expect("server send timed out")
                    .expect("server send failed");
            }));
        }

        for t in server_tasks {
            t.await.unwrap();
        }
        for t in client_tasks {
            t.await.unwrap();
        }
    }

    // ── Scenario 6/7: many simultaneous connections on one endpoint ───────────
    //
    // Verifies that concurrent connect_rendezvous() calls on the same Endpoint
    // all go through the single endpoint mux without racing on recv_from.

    #[tokio::test(flavor = "multi_thread")]
    async fn s7_multi_rendezvous_same_endpoint() {
        const N: usize = 3;

        // Create N pairs of endpoints.  Each pair on one "side" uses the same
        // shared Endpoint ep_a; the other side has N individual Endpoints.
        let ep_a = Arc::new(Endpoint::bind("127.0.0.1:0").await.unwrap());
        let mut eps_b = Vec::with_capacity(N);
        for _ in 0..N {
            eps_b.push(Arc::new(Endpoint::bind("127.0.0.1:0").await.unwrap()));
        }

        let addr_a = ep_a.local_addr();
        let addrs_b: Vec<SocketAddr> = eps_b.iter().map(|e| e.local_addr()).collect();

        // Connect all N rendezvous pairs concurrently.
        let mut tasks_a: Vec<_> = addrs_b
            .iter()
            .enumerate()
            .map(|(i, &addr_b)| {
                let ep_a = Arc::clone(&ep_a);
                let _payload = vec![(i as u8).wrapping_add(0x61); 2000]; // 'a', 'b', 'c' repeated
                tokio::spawn(async move {
                    tokio::time::timeout(Duration::from_secs(5), ep_a.connect_rendezvous(addr_b))
                        .await
                        .expect("rendezvous A timed out")
                        .expect("rendezvous A failed")
                })
            })
            .collect();

        let mut tasks_b: Vec<_> = eps_b
            .iter()
            .enumerate()
            .map(|(i, ep_b)| {
                let ep_b = Arc::clone(ep_b);
                let payload = vec![(i as u8).wrapping_add(0x61); 2000];
                tokio::spawn(async move {
                    let sock = tokio::time::timeout(
                        Duration::from_secs(5),
                        ep_b.connect_rendezvous(addr_a),
                    )
                    .await
                    .expect("rendezvous B timed out")
                    .expect("rendezvous B failed");
                    (sock, payload)
                })
            })
            .collect();

        // Collect sockets from side A.
        let mut socks_a: Vec<Socket> = Vec::new();
        for t in tasks_a.drain(..) {
            socks_a.push(t.await.unwrap());
        }
        let pairs: Vec<(Socket, Socket, Vec<u8>)> = {
            let mut v = Vec::new();
            for (sa, tb) in socks_a.into_iter().zip(tasks_b.drain(..)) {
                let (sb, payload) = tb.await.unwrap();
                v.push((sa, sb, payload));
            }
            v
        };

        // Exchange data on each pair concurrently and verify no commingling.
        let xfer_tasks: Vec<_> = pairs
            .into_iter()
            .enumerate()
            .map(|(i, (sa, sb, payload))| {
                tokio::spawn(async move {
                    // A → B
                    tokio::time::timeout(Duration::from_secs(5), sa.send(&payload))
                        .await
                        .expect("A send timed out")
                        .expect("A send failed");
                    let mut buf = vec![0u8; 131072];
                    let n = tokio::time::timeout(Duration::from_secs(5), sb.recv(&mut buf))
                        .await
                        .expect("B recv timed out")
                        .expect("B recv failed");
                    assert_eq!(&buf[..n], &payload, "pair {} B received wrong data", i);

                    // B → A echo
                    tokio::time::timeout(Duration::from_secs(5), sb.send(&buf[..n]))
                        .await
                        .expect("B echo timed out")
                        .expect("B echo failed");
                    let n2 = tokio::time::timeout(Duration::from_secs(5), sa.recv(&mut buf))
                        .await
                        .expect("A echo recv timed out")
                        .expect("A echo recv failed");
                    assert_eq!(&buf[..n2], &payload, "pair {} A received wrong echo", i);
                })
            })
            .collect();
        for t in xfer_tasks {
            t.await.unwrap();
        }
    }

    // ── Streaming integrity ───────────────────────────────────────────────────
    //
    // Unlike the echo tests above, these keep many messages in flight at once so
    // the send buffer is driven to capacity.  Every message is verified, which
    // catches silent drops caused by send-buffer overflow.

    /// Fill pattern for message `i` — distinct per message so a dropped or
    /// reordered message is detected rather than masked by uniform bytes.
    fn pattern(i: usize) -> u8 {
        (i % 251) as u8
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stream_integrity_rust_rust() {
        const MSGS: usize = 2000;
        const CHUNK: usize = 8192;

        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;

        let sender = tokio::spawn(async move {
            for i in 0..MSGS {
                let chunk = vec![pattern(i); CHUNK];
                client.send(&chunk).await.expect("send failed");
            }
            client
        });

        let mut buf = vec![0u8; CHUNK * 2];
        for i in 0..MSGS {
            let n = tokio::time::timeout(Duration::from_secs(20), server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for message {i} of {MSGS}"))
                .expect("recv failed");
            assert_eq!(n, CHUNK, "message {i} has wrong length");
            assert!(
                buf[..n].iter().all(|&b| b == pattern(i)),
                "message {i} corrupted (expected fill {:#04x}, got {:#04x})",
                pattern(i),
                buf[0],
            );
        }
        let _client = sender.await.unwrap();
    }

    // ── Out-of-order and TTL delivery ─────────────────────────────────────────
    //
    // `send_with(buf, ttl, in_order)` exposes two opt-in relaxations of strict
    // reliable ordering:
    //
    //  * `in_order = false` lets the peer surface a message as soon as it is
    //    complete, ahead of earlier ones still missing packets.
    //  * `ttl = Some(d)` lets the sender give up on a message that has not been
    //    delivered within `d`, telling the peer to skip its sequence range.
    //
    // The C++ reference livelocks under the first at throughput: its sender
    // advances past sequence numbers with no backing block, desynchronising the
    // positional block-to-sequence mapping that retransmission depends on, and
    // its receiver silently discards anything below the ACK point with no
    // feedback at all. These tests pin down that the Rust implementation
    // sustains the same workload.

    /// Unordered sends at full rate — the shape the user reported as livelocking
    /// against C++. Every message must still arrive exactly once, intact; only
    /// the *order* is allowed to vary.
    #[tokio::test(flavor = "multi_thread")]
    async fn unordered_stream_sustains_throughput() {
        const MSGS: usize = 3000;
        const CHUNK: usize = 4096;

        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;

        let sender = tokio::spawn(async move {
            for i in 0..MSGS {
                let chunk = vec![pattern(i); CHUNK];
                client
                    .send_with(&chunk, SendOptions::new().unordered())
                    .await
                    .expect("unordered send failed");
            }
            client
        });

        // Track which fills arrived. Order is explicitly not asserted; delivery
        // of every message exactly once is.
        let mut seen = vec![0usize; 251];
        let mut buf = vec![0u8; CHUNK * 2];
        let start = std::time::Instant::now();
        for i in 0..MSGS {
            let n = tokio::time::timeout(Duration::from_secs(20), server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("unordered stream stalled after {i} of {MSGS} messages"))
                .expect("recv failed");
            assert_eq!(n, CHUNK, "message {i} has wrong length");
            let fill = buf[0];
            assert!(
                buf[..n].iter().all(|&b| b == fill),
                "message {i} is not a single fill — payloads were spliced",
            );
            seen[fill as usize] += 1;
        }
        let elapsed = start.elapsed();

        let mut expected = vec![0usize; 251];
        for i in 0..MSGS {
            expected[pattern(i) as usize] += 1;
        }
        assert_eq!(seen, expected, "message multiset differs — data lost or duplicated");
        assert!(
            elapsed < Duration::from_secs(15),
            "unordered stream took {elapsed:?}, which suggests a livelock rather than progress",
        );
        let _held = sender.await.unwrap();
    }

    /// A message whose TTL expires before it can be delivered is skipped, and
    /// the connection carries on cleanly rather than stalling on the gap.
    #[tokio::test(flavor = "multi_thread")]
    async fn expired_messages_are_skipped_without_stalling() {
        const AFTER: usize = 200;
        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;

        // A TTL of zero expires the moment the send path reconsiders the
        // message, so this deterministically exercises the drop path.
        client
            .send_with(
                &vec![0xEEu8; 8192],
                SendOptions::new().ttl(Duration::from_millis(0)).unordered(),
            )
            .await
            .expect("ttl send failed");

        let sender = tokio::spawn(async move {
            for i in 0..AFTER {
                let chunk = vec![pattern(i); 2048];
                client.send(&chunk).await.expect("send failed");
            }
            client
        });

        // Everything sent afterwards must still arrive, in order, whether or not
        // the expired message made it.
        let mut buf = vec![0u8; 16384];
        let mut got = 0usize;
        while got < AFTER {
            let n = tokio::time::timeout(Duration::from_secs(20), server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("stalled after {got} of {AFTER} follow-up messages"))
                .expect("recv failed");
            if n == 8192 && buf[0] == 0xEE {
                continue; // the TTL message beat its own deadline; fine either way
            }
            assert_eq!(n, 2048, "unexpected message length {n}");
            assert!(
                buf[..n].iter().all(|&b| b == pattern(got)),
                "follow-up message {got} out of order or corrupted",
            );
            got += 1;
        }
        let _held = sender.await.unwrap();
    }

    // ── Message boundaries ────────────────────────────────────────────────────

    /// Message sizes chosen to straddle the packet payload boundary (1436 bytes
    /// at the default MSS), so single-packet, exact-multiple and partial-tail
    /// messages are all covered.
    ///
    /// UDT is message-oriented: each `send` must surface as exactly one `recv`
    /// of the same length, never split or coalesced.
    const BOUNDARY_SIZES: &[usize] = &[
        1,     // single packet, minimal
        1435,  // one byte under a full payload
        1436,  // exactly one full payload
        1437,  // full payload + 1 → two packets, tiny tail
        2872,  // exactly two full payloads
        4308,  // exactly three full payloads
        5000,  // three full payloads + partial tail
        65536, // 45 full payloads + partial tail
    ];

    /// A LEDBAT++ connection must carry data correctly, not just back off.
    #[tokio::test(flavor = "multi_thread")]
    async fn ledbat_transfers_correctly() {
        use udt_async::CcKind;

        const MSGS: usize = 400;
        const CHUNK: usize = 4096;
        let cfg = EndpointConfig::new().congestion(CcKind::LedbatPlusPlus);

        let ep = Endpoint::bind_with("127.0.0.1:0", cfg.clone()).await.unwrap();
        let server_addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();

        let (server, client) = tokio::join!(async { listener.accept().await.unwrap() }, async {
            let cep = Endpoint::bind_with("127.0.0.1:0", cfg.clone()).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), cep.connect(server_addr))
                .await
                .expect("ledbat connect timed out")
                .expect("ledbat connect failed")
        });

        let sender = tokio::spawn(async move {
            for i in 0..MSGS {
                client.send(&vec![pattern(i); CHUNK]).await.expect("send failed");
            }
            client
        });

        let mut buf = vec![0u8; CHUNK * 2];
        for i in 0..MSGS {
            let n = tokio::time::timeout(Duration::from_secs(20), server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("ledbat stalled at message {i} of {MSGS}"))
                .expect("recv failed");
            assert_eq!(n, CHUNK, "message {i} wrong length");
            assert!(buf[..n].iter().all(|&b| b == pattern(i)), "message {i} corrupted");
        }
        let _held = sender.await.unwrap();
    }

    /// Sanity check that two flows with different controllers coexist on a real
    /// socket and neither starves.
    ///
    /// **This is not the yielding test.** Loopback has no bottleneck queue, so
    /// queuing delay never rises and a delay-based controller has nothing to
    /// yield to — a share measured here says nothing about whether it *would*.
    /// Expect LEDBAT to take a substantial fraction, and that to be correct:
    /// declining to use idle capacity would be a bug, not a virtue.
    ///
    /// The real test is `congestion::sim` in udt-proto, which models an actual
    /// bottleneck and shows LEDBAT taking a few percent of a contested link.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn ledbat_yields_to_default_flow() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use udt_async::CcKind;

        const CHUNK: usize = 64 * 1024;
        const RUN: Duration = Duration::from_secs(3);

        async fn spawn_flow(cc: CcKind, counter: Arc<AtomicUsize>, stop: Arc<AtomicUsize>) {
            let cfg = EndpointConfig::new().congestion(cc);
            let ep = Endpoint::bind_with("127.0.0.1:0", cfg.clone()).await.unwrap();
            let addr = ep.local_addr();
            let listener = ep.listen(4).unwrap();
            let (server, client) =
                tokio::join!(async { listener.accept().await.unwrap() }, async {
                    let cep = Endpoint::bind_with("127.0.0.1:0", cfg.clone()).await.unwrap();
                    cep.connect(addr).await.unwrap()
                });

            let s = Arc::clone(&stop);
            tokio::spawn(async move {
                let chunk = vec![0x5Au8; CHUNK];
                while s.load(Ordering::Relaxed) == 0 {
                    if client.send(&chunk).await.is_err() {
                        break;
                    }
                }
                client
            });

            let mut buf = vec![0u8; CHUNK * 2];
            while stop.load(Ordering::Relaxed) == 0 {
                match tokio::time::timeout(Duration::from_millis(500), server.recv(&mut buf)).await
                {
                    Ok(Ok(n)) => {
                        counter.fetch_add(n, Ordering::Relaxed);
                    }
                    _ => break,
                }
            }
            // Keep the endpoint alive for the flow's lifetime.
            drop(ep);
        }

        let stop = Arc::new(AtomicUsize::new(0));
        let udt_bytes = Arc::new(AtomicUsize::new(0));
        let led_bytes = Arc::new(AtomicUsize::new(0));

        let a = tokio::spawn(spawn_flow(CcKind::Udt, Arc::clone(&udt_bytes), Arc::clone(&stop)));
        let b = tokio::spawn(spawn_flow(
            CcKind::LedbatPlusPlus,
            Arc::clone(&led_bytes),
            Arc::clone(&stop),
        ));

        tokio::time::sleep(RUN).await;
        stop.store(1, Ordering::Relaxed);
        let _ = tokio::time::timeout(Duration::from_secs(10), a).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), b).await;

        let udt = udt_bytes.load(Ordering::Relaxed);
        let led = led_bytes.load(Ordering::Relaxed);
        println!(
            "[ledbat-yield] udt={:.1} MB  ledbat={:.1} MB  (ledbat took {:.0}% of the pair)",
            udt as f64 / 1e6,
            led as f64 / 1e6,
            100.0 * led as f64 / (udt + led).max(1) as f64,
        );
        assert!(led > 0, "LEDBAT flow moved nothing at all");
        assert!(led <= udt, "LEDBAT flow ({led} B) did not yield to the default flow ({udt} B)",);
    }

    /// Every `send` must surface as exactly one `recv` of the same length.
    #[tokio::test(flavor = "multi_thread")]
    async fn message_boundaries_preserved() {
        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;

        let sender = tokio::spawn(async move {
            for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
                let msg: Vec<u8> = (0..size).map(|b| b.wrapping_add(i) as u8).collect();
                client.send(&msg).await.expect("send failed");
            }
            client
        });

        let mut buf = vec![0u8; 131072];
        for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
            let n = tokio::time::timeout(Duration::from_secs(10), server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("timed out on {size}-byte message"))
                .expect("recv failed");
            assert_eq!(n, size, "message {i} arrived with the wrong length");
            let expected: Vec<u8> = (0..size).map(|b| b.wrapping_add(i) as u8).collect();
            assert_eq!(&buf[..n], &expected[..], "{size}-byte message corrupted");
        }
        let _held = sender.await.unwrap();
    }

    // ── Connection setup latency ──────────────────────────────────────────────

    async fn time_n<F, Fut>(label: &str, n: usize, mut f: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let mut worst = Duration::ZERO;
        let start = std::time::Instant::now();
        for _ in 0..n {
            let t = std::time::Instant::now();
            f().await;
            worst = worst.max(t.elapsed());
        }
        let total = start.elapsed();
        println!(
            "[{label:<28}] mean {:>7.1} ms   worst {:>7.1} ms   ({n} connections)",
            total.as_secs_f64() * 1e3 / n as f64,
            worst.as_secs_f64() * 1e3,
        );
    }

    const BENCH_TOTAL: usize = 128 * 1024 * 1024;
    const BENCH_CHUNK: usize = 64 * 1024;
    const PINGPONG_MSGS: usize = 400;

    fn report(name: &str, bytes: usize, elapsed: f64) {
        println!(
            "[{name:<26}] {:>7.1} MB/s  ({} MiB in {:.2}s)",
            bytes as f64 / 1e6 / elapsed,
            bytes / (1024 * 1024),
            elapsed,
        );
    }

    fn report_latency(name: &str, msgs: usize, elapsed: f64) {
        println!(
            "[{name:<26}] {:>7.0} us/msg  ({msgs} msgs in {:.2}s)",
            elapsed / msgs as f64 * 1e6,
            elapsed,
        );
    }

    /// Long-running single-connection transfer, for attaching a profiler.
    ///
    /// The ordinary `stream_rust_to_rust` finishes in well under a second, so a
    /// sampling profiler catches mostly process startup. This repeats the
    /// transfer for roughly ten seconds on one connection.
    ///
    /// `cargo test --release profile_stream -- --ignored --nocapture &`
    /// then `sample <pid> 5 -file /tmp/prof.txt`
    ///
    /// # What the profile says (macOS, 2026-07)
    ///
    /// Discounting parked threads (`__psynch_cvwait`, which is idle time), the
    /// non-idle profile is almost entirely system calls:
    ///
    /// ```text
    /// __sendto           2430
    /// __recvfrom         1074
    /// kevent             1000
    /// _platform_memmove   120
    /// all udt_proto + udt_async code combined  ~200
    /// ```
    ///
    /// Our own code — packet assembly, the receive ring, congestion control —
    /// is a few percent. The per-packet copies and allocations that look
    /// expensive when reading the source are not where the time goes, and
    /// shaving them further would not move the number.
    ///
    /// Single-connection throughput is therefore a **syscall-rate ceiling**:
    /// ~375 MB/s at a 1436-byte payload is ~260k packets/s, and every packet
    /// costs one `sendto` on one side and one `recvfrom` on the other. The
    /// two-connection benchmark reaches ~580 MB/s precisely because it spreads
    /// those syscalls over more cores.
    ///
    /// Note `sendto` outnumbers `recvfrom` roughly 2:1: the receive path already
    /// batches (`RECV_BATCH` drains everything queued per wakeup) while the send
    /// path cannot — UDP is one datagram per call. Closing that asymmetry needs
    /// `sendmmsg`/`recvmmsg`, which macOS does not have; on Linux it is the one
    /// change with real headroom left. Raising the MSS would also cut packets
    /// per byte, but changes what the benchmark measures and does not reflect a
    /// 1500-byte-MTU path.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn profile_stream_rust_to_rust() {
        const ROUNDS: usize = 12;
        let (server, mut client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        let chunk = vec![0x5Au8; BENCH_CHUNK];

        let start = std::time::Instant::now();
        let mut total = 0usize;
        for _ in 0..ROUNDS {
            let c = chunk.clone();
            let sender = tokio::spawn(async move {
                let mut sent = 0usize;
                while sent < BENCH_TOTAL {
                    if client.send(&c).await.is_err() {
                        break;
                    }
                    sent += BENCH_CHUNK;
                }
                client
            });
            let mut buf = vec![0u8; BENCH_CHUNK * 2];
            let mut got = 0usize;
            while got < BENCH_TOTAL {
                got += server.recv(&mut buf).await.unwrap();
            }
            total += got;
            client = sender.await.unwrap();
        }
        report("profile rust→rust", total, start.elapsed().as_secs_f64());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn connect_latency() {
        time_n("listen/connect", 20, || async {
            let _ = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        })
        .await;

        time_n("rendezvous", 20, || async {
            let _ = new_rendezvous_pair().await;
        })
        .await;
    }

    /// Long-running two-connection transfer, for attaching a profiler.
    ///
    /// Both connections are accepted through one endpoint, so their inbound
    /// traffic funnels through the single mux task — which is what this is for
    /// measuring.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn profile_stream_two_connections() {
        const ROUNDS: usize = 8;
        const PER_CONN: usize = BENCH_TOTAL / 2;

        let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let server_addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();

        let conn_tasks: Vec<_> = (0..2)
            .map(|_| {
                tokio::spawn(async move {
                    let cep = Endpoint::bind("127.0.0.1:0").await.unwrap();
                    (cep.connect(server_addr).await.unwrap(), cep)
                })
            })
            .collect();
        let mut servers = Vec::new();
        for _ in 0..2 {
            servers.push(listener.accept().await.unwrap());
        }
        let mut clients = Vec::new();
        for t in conn_tasks {
            clients.push(t.await.unwrap());
        }

        let start = std::time::Instant::now();
        let mut total = 0usize;
        let xfer: Vec<_> = servers
            .into_iter()
            .zip(clients)
            .map(|(srv, (cli, _cep))| {
                tokio::spawn(async move {
                    let wr = std::sync::Arc::new(cli);
                    let chunk = vec![0xAAu8; BENCH_CHUNK];
                    let mut got = 0usize;
                    for _ in 0..ROUNDS {
                        let c = chunk.clone();
                        let w = std::sync::Arc::clone(&wr);
                        let sender = tokio::spawn(async move {
                            let mut sent = 0usize;
                            while sent < PER_CONN {
                                if w.send(&c).await.is_err() {
                                    break;
                                }
                                sent += BENCH_CHUNK;
                            }
                        });
                        let mut buf = vec![0u8; BENCH_CHUNK * 2];
                        let mut round = 0usize;
                        while round < PER_CONN {
                            round += srv.recv(&mut buf).await.unwrap();
                        }
                        got += round;
                        sender.await.unwrap();
                    }
                    (got, wr)
                })
            })
            .collect();
        for t in xfer {
            let (n, _held) = t.await.unwrap();
            total += n;
        }
        report("profile rust 2-conn", total, start.elapsed().as_secs_f64());
    }

    /// Rendezvous connections created from one endpoint all share that
    /// endpoint's socket and its single routing task. This measures whether
    /// that shared path is a throughput ceiling, by running the same N
    /// concurrent transfers two ways: all from one endpoint, then each from its
    /// own endpoint.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn rendezvous_parallel_scaling() {
        for n in [1usize, 2, 4, 8] {
            let shared = rendezvous_throughput(n, true).await;
            let separate = rendezvous_throughput(n, false).await;
            println!(
                "[rendezvous n={n:<2}] shared endpoint {shared:>7.1} MB/s   \
                 separate endpoints {separate:>7.1} MB/s   \
                 ratio {:.2}",
                shared / separate,
            );
        }
    }

    /// Run `n` concurrent rendezvous transfers, either all from one endpoint or
    /// each from its own. Returns aggregate MB/s.
    async fn rendezvous_throughput(n: usize, share_endpoint: bool) -> f64 {
        const PER_CONN: usize = 32 * 1024 * 1024;

        let hub = Arc::new(Endpoint::bind("127.0.0.1:0").await.unwrap());
        let mut pairs = Vec::new();
        for _ in 0..n {
            let a = if share_endpoint {
                Arc::clone(&hub)
            } else {
                Arc::new(Endpoint::bind("127.0.0.1:0").await.unwrap())
            };
            let b = Arc::new(Endpoint::bind("127.0.0.1:0").await.unwrap());
            let (aa, ba) = (a.local_addr(), b.local_addr());
            let (sa, sb) = tokio::join!(async { a.connect_rendezvous(ba).await.unwrap() }, async {
                b.connect_rendezvous(aa).await.unwrap()
            },);
            pairs.push((sa, sb, a, b));
        }

        let start = std::time::Instant::now();
        let tasks: Vec<_> = pairs
            .into_iter()
            .map(|(sa, sb, ea, eb)| {
                tokio::spawn(async move {
                    let chunk = vec![0x5Au8; BENCH_CHUNK];
                    let sender = tokio::spawn(async move {
                        let mut sent = 0usize;
                        while sent < PER_CONN {
                            if sa.send(&chunk).await.is_err() {
                                break;
                            }
                            sent += BENCH_CHUNK;
                        }
                        sa
                    });
                    let mut buf = vec![0u8; BENCH_CHUNK * 2];
                    let mut got = 0usize;
                    while got < PER_CONN {
                        match sb.recv(&mut buf).await {
                            Ok(k) => got += k,
                            Err(_) => break,
                        }
                    }
                    let _held = sender.await.unwrap();
                    let _keep = (ea, eb);
                    (got, start.elapsed().as_secs_f64())
                })
            })
            .collect();

        let mut total = 0usize;
        let mut per_conn = Vec::new();
        for t in tasks {
            let (got, secs) = t.await.unwrap();
            total += got;
            per_conn.push(secs);
        }
        // One connection finishing far after the rest drags the aggregate down
        // by the whole factor, so report the spread when asked.
        if std::env::var_os("UDT_PERCONN").is_some() {
            per_conn.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let each: Vec<String> = per_conn.iter().map(|s| format!("{:.2}", s * 1e3)).collect();
            eprintln!("    per-conn ms: {}", each.join(" "));
        }
        total as f64 / 1e6 / start.elapsed().as_secs_f64()
    }

    // ── Streaming throughput ──────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn stream_rust_to_rust() {
        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        let chunk = vec![0x5Au8; BENCH_CHUNK];

        let start = std::time::Instant::now();
        let sender = tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < BENCH_TOTAL {
                client.send(&chunk).await.unwrap();
                sent += BENCH_CHUNK;
            }
            client
        });

        let mut buf = vec![0u8; BENCH_CHUNK * 2];
        let mut got = 0usize;
        while got < BENCH_TOTAL {
            got += server.recv(&mut buf).await.unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        let _held = sender.await.unwrap();
        report("stream rust→rust", got, elapsed);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn stream_rust_two_connections() {
        let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let server_addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();

        let conn_tasks: Vec<_> = (0..2)
            .map(|_| {
                tokio::spawn(async move {
                    let cep = Endpoint::bind("127.0.0.1:0").await.unwrap();
                    cep.connect(server_addr).await.unwrap()
                })
            })
            .collect();
        let mut server_socks = Vec::new();
        for _ in 0..2 {
            server_socks.push(listener.accept().await.unwrap());
        }
        let mut client_socks = Vec::new();
        for t in conn_tasks {
            client_socks.push(t.await.unwrap());
        }

        const PER_CONN: usize = BENCH_TOTAL / 2;
        let start = std::time::Instant::now();
        let xfer: Vec<_> = server_socks
            .into_iter()
            .zip(client_socks)
            .map(|(srv, cli)| {
                let chunk = vec![0xAAu8; BENCH_CHUNK];
                tokio::spawn(async move {
                    let sender = tokio::spawn(async move {
                        let mut sent = 0usize;
                        while sent < PER_CONN {
                            cli.send(&chunk).await.unwrap();
                            sent += BENCH_CHUNK;
                        }
                        cli
                    });
                    let mut buf = vec![0u8; BENCH_CHUNK * 2];
                    let mut got = 0usize;
                    while got < PER_CONN {
                        got += srv.recv(&mut buf).await.unwrap();
                    }
                    let _held = sender.await.unwrap();
                    got
                })
            })
            .collect();
        let totals: Vec<usize> =
            futures::future::join_all(xfer).await.into_iter().map(|r| r.unwrap()).collect();
        let elapsed = start.elapsed().as_secs_f64();
        report("stream rust 2-conn", totals.iter().sum(), elapsed);
    }

    // ── Ping-pong latency ─────────────────────────────────────────────────────
    //
    // One message in flight at a time.  The C++ receiver only makes data visible
    // to the application when it emits an ACK, and it only services its ACK
    // timer when a packet arrives or on a 100 ms idle sweep (queue.cpp).  A
    // sender that goes quiet after each message therefore waits on that sweep,
    // which is why the C++-receiver numbers here are far worse than the
    // streaming ones.  The cpp→cpp variant shows this is inherent to the
    // reference implementation, not something the Rust side introduces.

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn pingpong_rust_to_rust() {
        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        let chunk = vec![0x55u8; BENCH_CHUNK];
        let mut buf = vec![0u8; BENCH_CHUNK * 2];

        let start = std::time::Instant::now();
        for _ in 0..PINGPONG_MSGS {
            client.send(&chunk).await.unwrap();
            server.recv(&mut buf).await.unwrap();
        }
        report_latency("pingpong rust→rust", PINGPONG_MSGS, start.elapsed().as_secs_f64());
    }
}
