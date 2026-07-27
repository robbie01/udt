#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use udt_async::{Endpoint, Socket};

    const SMALL: &[u8] = b"hello, world!   "; // 16 bytes — single packet
    fn medium() -> Vec<u8> { vec![0x42u8; 4096] } // 3 packets at default MSS (payload=1436B)
    fn large() -> Vec<u8> { vec![0x7fu8; 65536] } // ~45 packets

    // ── Pure Rust helpers ────────────────────────────────────────────────────

    async fn new_listener_pair(
        listener_addr: SocketAddr,
    ) -> (Socket, Socket) {
        let ep = Endpoint::bind(listener_addr).unwrap();
        let server_addr = ep.local_addr().unwrap();
        let mut listener = ep.listen(4).unwrap();

        let (server_sock, client_sock) = tokio::join!(
            async { listener.accept().await.unwrap() },
            async {
                let cep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
                tokio::time::timeout(Duration::from_secs(5), cep.connect(server_addr))
                    .await
                    .expect("connect timed out")
                    .expect("connect failed")
            }
        );
        (server_sock, client_sock)
    }

    async fn echo_exchange(
        mut server: Socket,
        mut client: Socket,
        payload: &[u8],
        count: usize,
    ) {
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
        let ep_a = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let ep_b = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr_a = ep_a.local_addr().unwrap();
        let addr_b = ep_b.local_addr().unwrap();

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

    // ── Mixed (C++ <-> Rust) connection setup helpers ─────────────────────────

    /// Set up a Rust listener + C++ connector pair.
    /// Returns (rust_server_sock, cpp_client_conn).
    async fn new_s2_pair() -> (Socket, udt_compat::Connection) {
        use udt_compat::Endpoint as CppEndpoint;

        let ep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = ep.local_addr().unwrap();
        let mut listener = ep.listen(4).unwrap();

        let (server_sock, cpp_conn) = tokio::join!(
            async { listener.accept().await.unwrap() },
            async {
                let cpp_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
                tokio::time::timeout(Duration::from_secs(5), cpp_ep.connect(server_addr, false))
                    .await
                    .expect("cpp connect timed out")
                    .expect("cpp connect failed")
            }
        );
        (server_sock, cpp_conn)
    }

    /// Set up a C++ listener + Rust connector pair.
    /// Returns (cpp_server_conn, rust_client_sock).
    async fn new_s3_pair() -> (udt_compat::Connection, Socket) {
        use udt_compat::Endpoint as CppEndpoint;

        let cpp_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let server_addr = cpp_ep.local_addr().unwrap();
        let cpp_listener = cpp_ep.listen(4).unwrap();

        let (cpp_conn, client_sock) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(5), cpp_listener.accept())
                    .await
                    .expect("cpp accept timed out")
                    .expect("cpp accept failed")
            },
            async {
                let cep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
                tokio::time::timeout(Duration::from_secs(5), cep.connect(server_addr))
                    .await
                    .expect("connect timed out")
                    .expect("connect failed")
            }
        );
        (cpp_conn, client_sock)
    }

    /// Set up a C++ rendezvous + Rust rendezvous pair.
    /// Returns (cpp_conn, rust_sock).
    async fn new_s5_pair() -> (udt_compat::Connection, Socket) {
        use udt_compat::Endpoint as CppEndpoint;

        let cpp_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let rust_ep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let cpp_addr = cpp_ep.local_addr().unwrap();
        let rust_addr = rust_ep.local_addr().unwrap();

        let (cpp_conn, rust_sock) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(5), cpp_ep.connect(rust_addr, true))
                    .await
                    .expect("cpp rendezvous timed out")
                    .expect("cpp rendezvous failed")
            },
            async {
                tokio::time::timeout(Duration::from_secs(5), rust_ep.connect_rendezvous(cpp_addr))
                    .await
                    .expect("rust rendezvous timed out")
                    .expect("rust rendezvous failed")
            }
        );
        (cpp_conn, rust_sock)
    }

    /// Exchange `count` messages: C++ sends first, Rust echoes back.
    async fn cpp_first_echo_exchange(
        cpp_conn: udt_compat::Connection,
        mut rust_sock: Socket,
        payload: &[u8],
        count: usize,
    ) {
        let mut buf = vec![0u8; 131072];
        for _ in 0..count {
            // C++ → Rust
            tokio::time::timeout(Duration::from_secs(5), cpp_conn.send(payload))
                .await
                .expect("cpp send timed out")
                .expect("cpp send failed");
            let n = tokio::time::timeout(Duration::from_secs(5), rust_sock.recv(&mut buf))
                .await
                .expect("rust recv timed out")
                .expect("rust recv failed");
            assert_eq!(&buf[..n], payload, "rust received wrong data from cpp");

            // Rust → C++ echo
            tokio::time::timeout(Duration::from_secs(5), rust_sock.send(&buf[..n]))
                .await
                .expect("rust echo send timed out")
                .expect("rust echo send failed");
            let n = tokio::time::timeout(Duration::from_secs(5), cpp_conn.recv(&mut buf))
                .await
                .expect("cpp recv timed out")
                .expect("cpp recv failed");
            assert_eq!(&buf[..n], payload, "cpp received wrong echo from rust");
        }
    }

    /// Exchange `count` messages: Rust sends first, C++ echoes back.
    async fn rust_first_echo_exchange(
        mut rust_sock: Socket,
        cpp_conn: udt_compat::Connection,
        payload: &[u8],
        count: usize,
    ) {
        let mut buf = vec![0u8; 131072];
        for _ in 0..count {
            // Rust → C++
            tokio::time::timeout(Duration::from_secs(5), rust_sock.send(payload))
                .await
                .expect("rust send timed out")
                .expect("rust send failed");
            let n = tokio::time::timeout(Duration::from_secs(5), cpp_conn.recv(&mut buf))
                .await
                .expect("cpp recv timed out")
                .expect("cpp recv failed");
            assert_eq!(&buf[..n], payload, "cpp received wrong data from rust");

            // C++ → Rust echo
            tokio::time::timeout(Duration::from_secs(5), cpp_conn.send(&buf[..n]))
                .await
                .expect("cpp echo send timed out")
                .expect("cpp echo send failed");
            let n = tokio::time::timeout(Duration::from_secs(5), rust_sock.recv(&mut buf))
                .await
                .expect("rust recv timed out")
                .expect("rust recv failed");
            assert_eq!(&buf[..n], payload, "rust received wrong echo from cpp");
        }
    }

    // ── Scenario 2: new listener + old connector (udt-compat connects) ───────

    #[tokio::test(flavor = "multi_thread")]
    async fn s2_new_listener_old_connector_small() {
        let (rust_sock, cpp_conn) = new_s2_pair().await;
        cpp_first_echo_exchange(cpp_conn, rust_sock, SMALL, 5).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s2_new_listener_old_connector_medium() {
        let (rust_sock, cpp_conn) = new_s2_pair().await;
        cpp_first_echo_exchange(cpp_conn, rust_sock, &medium(), 3).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s2_new_listener_old_connector_large() {
        let (rust_sock, cpp_conn) = new_s2_pair().await;
        cpp_first_echo_exchange(cpp_conn, rust_sock, &large(), 2).await;
    }

    // ── Scenario 3: old listener + new connector ──────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn s3_old_listener_new_connector_small() {
        let (cpp_conn, rust_sock) = new_s3_pair().await;
        rust_first_echo_exchange(rust_sock, cpp_conn, SMALL, 5).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s3_old_listener_new_connector_medium() {
        let (cpp_conn, rust_sock) = new_s3_pair().await;
        rust_first_echo_exchange(rust_sock, cpp_conn, &medium(), 3).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s3_old_listener_new_connector_large() {
        let (cpp_conn, rust_sock) = new_s3_pair().await;
        rust_first_echo_exchange(rust_sock, cpp_conn, &large(), 2).await;
    }

    // ── Scenario 5: rendezvous old + new ──────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn s5_rendezvous_old_new_small() {
        let (cpp_conn, rust_sock) = new_s5_pair().await;
        rust_first_echo_exchange(rust_sock, cpp_conn, SMALL, 5).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s5_rendezvous_old_new_medium() {
        let (cpp_conn, rust_sock) = new_s5_pair().await;
        rust_first_echo_exchange(rust_sock, cpp_conn, &medium(), 3).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn s5_rendezvous_old_new_large() {
        let (cpp_conn, rust_sock) = new_s5_pair().await;
        rust_first_echo_exchange(rust_sock, cpp_conn, &large(), 2).await;
    }

    // ── Scenario 6: multiple simultaneous connections to the same listener ────
    //
    // Verifies that the endpoint mux correctly routes packets when N clients are
    // connected concurrently and that no payload is commingled across connections.

    #[tokio::test(flavor = "multi_thread")]
    async fn s6_multi_connection_same_listener() {
        const N: usize = 4;

        let ep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = ep.local_addr().unwrap();
        let mut listener = ep.listen(N + 1).unwrap();

        // Spawn N clients simultaneously.
        let client_tasks: Vec<_> = (0usize..N).map(|i| {
            let payload = vec![(i as u8).wrapping_add(0x41); 3000]; // 'A', 'B', 'C', 'D' repeated
            tokio::spawn(async move {
                let cep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
                let mut sock = tokio::time::timeout(
                    Duration::from_secs(5),
                    cep.connect(server_addr),
                )
                .await
                .expect("connect timed out")
                .expect("connect failed");

                // Send our distinctive payload.
                tokio::time::timeout(Duration::from_secs(5), sock.send(&payload))
                    .await.expect("send timed out").expect("send failed");

                // Receive the echo.
                let mut buf = vec![0u8; 131072];
                let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
                    .await.expect("recv timed out").expect("recv failed");

                assert_eq!(&buf[..n], &payload,
                    "client {} received wrong echo (commingling?)", i);
            })
        }).collect();

        // Accept N connections on the server side and echo each payload back.
        let mut server_tasks = Vec::new();
        for _ in 0..N {
            let mut server_sock = tokio::time::timeout(
                Duration::from_secs(5),
                listener.accept(),
            )
            .await
            .expect("accept timed out")
            .expect("accept failed");

            server_tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 131072];
                let n = tokio::time::timeout(Duration::from_secs(5), server_sock.recv(&mut buf))
                    .await.expect("server recv timed out").expect("server recv failed");
                tokio::time::timeout(Duration::from_secs(5), server_sock.send(&buf[..n]))
                    .await.expect("server send timed out").expect("server send failed");
            }));
        }

        for t in server_tasks { t.await.unwrap(); }
        for t in client_tasks { t.await.unwrap(); }
    }

    // ── Scenario 7: multiple simultaneous rendezvous from the same endpoint ───
    //
    // Verifies that concurrent connect_rendezvous() calls on the same Endpoint
    // all go through the single endpoint mux without racing on recv_from.

    #[tokio::test(flavor = "multi_thread")]
    async fn s7_multi_rendezvous_same_endpoint() {
        const N: usize = 3;

        // Create N pairs of endpoints.  Each pair on one "side" uses the same
        // shared Endpoint ep_a; the other side has N individual Endpoints.
        let ep_a = Arc::new(Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let eps_b: Vec<_> = (0..N)
            .map(|_| Arc::new(Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap()))
            .collect();

        let addr_a = ep_a.local_addr().unwrap();
        let addrs_b: Vec<SocketAddr> = eps_b.iter().map(|e| e.local_addr().unwrap()).collect();

        // Connect all N rendezvous pairs concurrently.
        let mut tasks_a: Vec<_> = addrs_b.iter().enumerate().map(|(i, &addr_b)| {
            let ep_a = Arc::clone(&ep_a);
            let _payload = vec![(i as u8).wrapping_add(0x61); 2000]; // 'a', 'b', 'c' repeated
            tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(5), ep_a.connect_rendezvous(addr_b))
                    .await.expect("rendezvous A timed out").expect("rendezvous A failed")
            })
        }).collect();

        let mut tasks_b: Vec<_> = eps_b.iter().enumerate().map(|(i, ep_b)| {
            let ep_b = Arc::clone(ep_b);
            let payload = vec![(i as u8).wrapping_add(0x61); 2000];
            tokio::spawn(async move {
                let sock = tokio::time::timeout(
                    Duration::from_secs(5),
                    ep_b.connect_rendezvous(addr_a),
                )
                .await.expect("rendezvous B timed out").expect("rendezvous B failed");
                (sock, payload)
            })
        }).collect();

        // Collect sockets from side A.
        let mut socks_a: Vec<Socket> = Vec::new();
        for t in tasks_a.drain(..) { socks_a.push(t.await.unwrap()); }
        let pairs: Vec<(Socket, Socket, Vec<u8>)> = {
            let mut v = Vec::new();
            for (sa, tb) in socks_a.into_iter().zip(tasks_b.drain(..)) {
                let (sb, payload) = tb.await.unwrap();
                v.push((sa, sb, payload));
            }
            v
        };

        // Exchange data on each pair concurrently and verify no commingling.
        let xfer_tasks: Vec<_> = pairs.into_iter().enumerate().map(|(i, (mut sa, mut sb, payload))| {
            tokio::spawn(async move {
                // A → B
                tokio::time::timeout(Duration::from_secs(5), sa.send(&payload))
                    .await.expect("A send timed out").expect("A send failed");
                let mut buf = vec![0u8; 131072];
                let n = tokio::time::timeout(Duration::from_secs(5), sb.recv(&mut buf))
                    .await.expect("B recv timed out").expect("B recv failed");
                assert_eq!(&buf[..n], &payload, "pair {} B received wrong data", i);

                // B → A echo
                tokio::time::timeout(Duration::from_secs(5), sb.send(&buf[..n]))
                    .await.expect("B echo timed out").expect("B echo failed");
                let n2 = tokio::time::timeout(Duration::from_secs(5), sa.recv(&mut buf))
                    .await.expect("A echo recv timed out").expect("A echo recv failed");
                assert_eq!(&buf[..n2], &payload, "pair {} A received wrong echo", i);
            })
        }).collect();
        for t in xfer_tasks { t.await.unwrap(); }
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

        let (mut server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;

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

        let (mut server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;

        let sender = tokio::spawn(async move {
            for i in 0..MSGS {
                let chunk = vec![pattern(i); CHUNK];
                client
                    .send_with(&chunk, None, false)
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
                .unwrap_or_else(|_| {
                    panic!("unordered stream stalled after {i} of {MSGS} messages")
                })
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
        let (mut server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;

        // A TTL of zero expires the moment the send path reconsiders the
        // message, so this deterministically exercises the drop path.
        client
            .send_with(&vec![0xEEu8; 8192], Some(Duration::from_millis(0)), false)
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

    // ── C++ interop integrity ─────────────────────────────────────────────────
    //
    // Bulk transfers across the Rust/C++ boundary with every byte verified.
    // These use a dedicated sender task rather than send-then-wait, both because
    // it keeps many messages in flight (exercising the send buffer, flow control
    // and retransmission) and because a sender that goes quiet after each
    // message stalls on the C++ receiver's 100 ms idle timer.

    const INTEROP_MSGS: usize = 1500;
    const INTEROP_CHUNK: usize = 4096;

    /// Rust → C++, every message verified by the C++ side.
    #[tokio::test(flavor = "multi_thread")]
    async fn interop_bulk_rust_to_cpp_verified() {
        let (cpp_conn, rust_sock) = new_s3_pair().await;

        let sender = tokio::spawn(async move {
            for i in 0..INTEROP_MSGS {
                let chunk = vec![pattern(i); INTEROP_CHUNK];
                rust_sock.send(&chunk).await.expect("rust send failed");
            }
            rust_sock
        });

        let mut buf = vec![0u8; INTEROP_CHUNK * 2];
        for i in 0..INTEROP_MSGS {
            let n = tokio::time::timeout(Duration::from_secs(20), cpp_conn.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("cpp recv timed out on message {i} of {INTEROP_MSGS}"))
                .expect("cpp recv failed");
            assert_eq!(n, INTEROP_CHUNK, "message {i} arrived at C++ with wrong length");
            assert!(
                buf[..n].iter().all(|&b| b == pattern(i)),
                "message {i} corrupted in transit to C++ (expected fill {:#04x}, got {:#04x})",
                pattern(i),
                buf[0],
            );
        }
        let _held = sender.await.unwrap();
    }

    /// C++ → Rust, every message verified by the Rust side.
    #[tokio::test(flavor = "multi_thread")]
    async fn interop_bulk_cpp_to_rust_verified() {
        let (mut rust_sock, cpp_conn) = new_s2_pair().await;

        let sender = tokio::spawn(async move {
            for i in 0..INTEROP_MSGS {
                let chunk = vec![pattern(i); INTEROP_CHUNK];
                cpp_conn.send(&chunk).await.expect("cpp send failed");
            }
            cpp_conn
        });

        let mut buf = vec![0u8; INTEROP_CHUNK * 2];
        for i in 0..INTEROP_MSGS {
            let n = tokio::time::timeout(Duration::from_secs(20), rust_sock.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("rust recv timed out on message {i} of {INTEROP_MSGS}"))
                .expect("rust recv failed");
            assert_eq!(n, INTEROP_CHUNK, "message {i} arrived at Rust with wrong length");
            assert!(
                buf[..n].iter().all(|&b| b == pattern(i)),
                "message {i} corrupted in transit from C++ (expected fill {:#04x}, got {:#04x})",
                pattern(i),
                buf[0],
            );
        }
        let _held = sender.await.unwrap();
    }

    /// Message sizes chosen to straddle the packet payload boundary (1436 bytes
    /// at the default MSS), so single-packet, exact-multiple and partial-tail
    /// messages are all covered.
    ///
    /// UDT is message-oriented: each `send` must surface as exactly one `recv`
    /// of the same length, never split or coalesced. Boundary handling is
    /// encoded in per-packet flags, so a disagreement with C++ here would be a
    /// wire-format bug.
    const BOUNDARY_SIZES: &[usize] = &[
        1,      // single packet, minimal
        1435,   // one byte under a full payload
        1436,   // exactly one full payload
        1437,   // full payload + 1 → two packets, tiny tail
        2872,   // exactly two full payloads
        4308,   // exactly three full payloads
        5000,   // three full payloads + partial tail
        65536,  // 45 full payloads + partial tail
    ];

    #[tokio::test(flavor = "multi_thread")]
    async fn interop_message_boundaries_rust_to_cpp() {
        let (cpp_conn, rust_sock) = new_s3_pair().await;

        let sender = tokio::spawn(async move {
            for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
                let msg: Vec<u8> = (0..size).map(|b| (b.wrapping_add(i)) as u8).collect();
                rust_sock.send(&msg).await.expect("rust send failed");
            }
            rust_sock
        });

        let mut buf = vec![0u8; 131072];
        for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
            let n = tokio::time::timeout(Duration::from_secs(20), cpp_conn.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("cpp recv timed out on {size}-byte message"))
                .expect("cpp recv failed");
            assert_eq!(n, size, "C++ saw a different message length (message {i})");
            let expected: Vec<u8> = (0..size).map(|b| (b.wrapping_add(i)) as u8).collect();
            assert_eq!(&buf[..n], &expected[..], "{size}-byte message corrupted");
        }
        let _held = sender.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn interop_message_boundaries_cpp_to_rust() {
        let (mut rust_sock, cpp_conn) = new_s2_pair().await;

        let sender = tokio::spawn(async move {
            for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
                let msg: Vec<u8> = (0..size).map(|b| (b.wrapping_add(i)) as u8).collect();
                cpp_conn.send(&msg).await.expect("cpp send failed");
            }
            cpp_conn
        });

        let mut buf = vec![0u8; 131072];
        for (i, &size) in BOUNDARY_SIZES.iter().enumerate() {
            let n = tokio::time::timeout(Duration::from_secs(20), rust_sock.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("rust recv timed out on {size}-byte message"))
                .expect("rust recv failed");
            assert_eq!(n, size, "Rust saw a different message length (message {i})");
            let expected: Vec<u8> = (0..size).map(|b| (b.wrapping_add(i)) as u8).collect();
            assert_eq!(&buf[..n], &expected[..], "{size}-byte message corrupted");
        }
        let _held = sender.await.unwrap();
    }

    /// Same streaming integrity check as the Rust-only test, but with C++ on
    /// both ends of the rendezvous handshake path.
    #[tokio::test(flavor = "multi_thread")]
    async fn interop_bulk_rendezvous_rust_to_cpp_verified() {
        let (cpp_conn, rust_sock) = new_s5_pair().await;

        let sender = tokio::spawn(async move {
            for i in 0..INTEROP_MSGS {
                let chunk = vec![pattern(i); INTEROP_CHUNK];
                rust_sock.send(&chunk).await.expect("rust send failed");
            }
            rust_sock
        });

        let mut buf = vec![0u8; INTEROP_CHUNK * 2];
        for i in 0..INTEROP_MSGS {
            let n = tokio::time::timeout(Duration::from_secs(20), cpp_conn.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("cpp recv timed out on message {i} of {INTEROP_MSGS}"))
                .expect("cpp recv failed");
            assert_eq!(n, INTEROP_CHUNK, "message {i} arrived at C++ with wrong length");
            assert!(
                buf[..n].iter().all(|&b| b == pattern(i)),
                "message {i} corrupted over rendezvous to C++",
            );
        }
        let _held = sender.await.unwrap();
    }

    /// Unordered sends from Rust into the C++ receiver, exercising its
    /// `scanMsg` early-delivery path.
    ///
    /// Ignored by default and reporting rather than asserting: this documents
    /// how far the reference gets before its out-of-order path gives out, which
    /// is the behaviour the Rust side deliberately does not reproduce. Run with
    /// `cargo test --release unordered_into_cpp -- --ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn unordered_into_cpp_reference() {
        const MSGS: usize = 3000;
        const CHUNK: usize = 4096;

        let (cpp_conn, rust_sock) = new_s3_pair().await;

        let sender = tokio::spawn(async move {
            for i in 0..MSGS {
                let chunk = vec![pattern(i); CHUNK];
                if rust_sock.send_with(&chunk, None, false).await.is_err() {
                    return (rust_sock, i);
                }
            }
            (rust_sock, MSGS)
        });

        let mut buf = vec![0u8; CHUNK * 2];
        let start = std::time::Instant::now();
        let mut got = 0usize;
        let mut misordered = 0usize;
        while got < MSGS {
            match tokio::time::timeout(Duration::from_secs(5), cpp_conn.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if n != CHUNK || buf[0] != pattern(got) {
                        misordered += 1;
                    }
                    got += 1;
                }
                Ok(Err(e)) => {
                    println!("[unordered→cpp] C++ recv failed after {got}/{MSGS}: {e}");
                    break;
                }
                Err(_) => {
                    println!("[unordered→cpp] C++ stalled after {got}/{MSGS} messages");
                    break;
                }
            }
        }
        println!(
            "[unordered→cpp] delivered {got}/{MSGS} in {:.2}s ({misordered} out of sequence)",
            start.elapsed().as_secs_f64(),
        );
        let (_held, sent) = sender.await.unwrap();
        println!("[unordered→cpp] Rust queued {sent}/{MSGS}");
    }

    /// The reverse: C++ as the *sender* of unordered, TTL-bearing messages at
    /// full rate — the configuration behind the reported livelock.
    ///
    /// **This does not reproduce the livelock on loopback, and is not expected
    /// to.** C++'s drop path only fires when a TTL-expired block is on the send
    /// loss list, which needs real packet loss; loopback with 12 MB socket
    /// buffers produces essentially none, and the reference completes cleanly
    /// here. Reproducing it needs a lossy path (netem, or a deliberately tiny
    /// receive buffer). The test is kept as the harness for that.
    ///
    /// When the path does fire, C++ `packData` emits a MsgDrop naming one
    /// sequence number too many and advances `m_iSndCurrSeqNo` past sequence
    /// numbers with no backing block, desynchronising the positional
    /// block-to-sequence mapping every later `readData(offset)` depends on.
    /// `udt-proto` avoids both: `expire_msg_at` reports an exact inclusive range
    /// and consumes the sequence numbers rather than skipping them.
    ///
    /// Note `udt_compat::Connection::try_send_with` forces `inorder = true`
    /// whenever no TTL is given, precisely to keep applications off this path;
    /// supplying a TTL is what unlocks it. Ignored and reporting, not asserting.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn unordered_from_cpp_reference() {
        const MSGS: usize = 3000;
        const CHUNK: usize = 4096;
        let ttl = Some(Duration::from_millis(20));

        let (mut rust_sock, cpp_conn) = new_s2_pair().await;

        let sender = tokio::spawn(async move {
            for i in 0..MSGS {
                let chunk = vec![pattern(i); CHUNK];
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    cpp_conn.send_with(&chunk, ttl, false),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        println!("[unordered←cpp] C++ send failed at {i}/{MSGS}: {e}");
                        return (cpp_conn, i);
                    }
                    Err(_) => {
                        println!("[unordered←cpp] C++ send stalled at {i}/{MSGS}");
                        return (cpp_conn, i);
                    }
                }
            }
            (cpp_conn, MSGS)
        });

        let mut buf = vec![0u8; CHUNK * 2];
        let start = std::time::Instant::now();
        let mut got = 0usize;
        while got < MSGS {
            match tokio::time::timeout(Duration::from_secs(5), rust_sock.recv(&mut buf)).await {
                Ok(Ok(_)) => got += 1,
                Ok(Err(e)) => {
                    println!("[unordered←cpp] Rust recv failed after {got}/{MSGS}: {e}");
                    break;
                }
                Err(_) => {
                    println!("[unordered←cpp] stalled after {got}/{MSGS} messages");
                    break;
                }
            }
        }
        println!(
            "[unordered←cpp] delivered {got}/{MSGS} in {:.2}s",
            start.elapsed().as_secs_f64(),
        );
        let (_held, sent) = sender.await.unwrap();
        println!("[unordered←cpp] C++ queued {sent}/{MSGS}");
    }

    // ── LEDBAT++ ──────────────────────────────────────────────────────────────

    /// A LEDBAT++ connection must carry data correctly, not just back off.
    #[tokio::test(flavor = "multi_thread")]
    async fn ledbat_transfers_correctly() {
        use udt_async::{CcKind, EndpointConfig};

        const MSGS: usize = 400;
        const CHUNK: usize = 4096;
        let cfg = EndpointConfig { congestion: CcKind::LedbatPlusPlus, ..Default::default() };

        let ep = Endpoint::bind_with("127.0.0.1:0".parse().unwrap(), cfg).unwrap();
        let server_addr = ep.local_addr().unwrap();
        let mut listener = ep.listen(4).unwrap();

        let (mut server, client) = tokio::join!(
            async { listener.accept().await.unwrap() },
            async {
                let cep = Endpoint::bind_with("127.0.0.1:0".parse().unwrap(), cfg).unwrap();
                tokio::time::timeout(Duration::from_secs(5), cep.connect(server_addr))
                    .await
                    .expect("ledbat connect timed out")
                    .expect("ledbat connect failed")
            }
        );

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

    /// The property that defines a scavenger: when a LEDBAT++ flow shares a
    /// path with a default (UDT) flow, it must give way.
    ///
    /// Both flows run concurrently for a fixed window and we compare how much
    /// each moved. Loopback is a poor congestion signal — there is no real
    /// bottleneck queue — so this asserts only the direction of the effect,
    /// generously, rather than a precise share.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn ledbat_yields_to_default_flow() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use udt_async::{CcKind, EndpointConfig};

        const CHUNK: usize = 64 * 1024;
        const RUN: Duration = Duration::from_secs(3);

        async fn spawn_flow(cc: CcKind, counter: Arc<AtomicUsize>, stop: Arc<AtomicUsize>) {
            let cfg = EndpointConfig { congestion: cc, ..Default::default() };
            let ep = Endpoint::bind_with("127.0.0.1:0".parse().unwrap(), cfg).unwrap();
            let addr = ep.local_addr().unwrap();
            let mut listener = ep.listen(4).unwrap();
            let (mut server, client) = tokio::join!(
                async { listener.accept().await.unwrap() },
                async {
                    let cep = Endpoint::bind_with("127.0.0.1:0".parse().unwrap(), cfg).unwrap();
                    cep.connect(addr).await.unwrap()
                }
            );

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
                match tokio::time::timeout(Duration::from_millis(500), server.recv(&mut buf)).await {
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
        assert!(
            led <= udt,
            "LEDBAT flow ({led} B) did not yield to the default flow ({udt} B)",
        );
    }

    // ── Reported-livelock repro attempts ──────────────────────────────────────

    /// Throughput matrix for the relaxed-delivery modes, with the **fork on
    /// both ends** driven through the RPoll async wrapper — the configuration
    /// the livelock was reported under — and the Rust implementation beside it.
    ///
    /// Reports rather than asserts, so a livelock shows up as a bounded,
    /// readable number instead of a hung suite.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn relaxed_delivery_throughput_matrix() {
        const MSGS: usize = 20_000;
        const CHUNK: usize = 8192;
        let ttl = Some(Duration::from_millis(20));

        // The compat shim forces inorder=true whenever no TTL is given, so a
        // TTL is required to reach the unordered path at all.
        for (label, in_order) in [("cpp↔cpp ordered+ttl", true), ("cpp↔cpp unordered+ttl", false)] {
            let (server, client) = new_cpp_cpp_pair().await;
            let sender = tokio::spawn(async move {
                for i in 0..MSGS {
                    let r = tokio::time::timeout(
                        Duration::from_secs(5),
                        client.send_with(&vec![pattern(i); CHUNK], ttl, in_order),
                    )
                    .await;
                    if !matches!(r, Ok(Ok(_))) {
                        return (client, i);
                    }
                }
                (client, MSGS)
            });

            let mut buf = vec![0u8; CHUNK * 2];
            let start = std::time::Instant::now();
            let mut got = 0usize;
            while got < MSGS {
                match tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf)).await {
                    Ok(Ok(_)) => got += 1,
                    _ => break,
                }
            }
            let secs = start.elapsed().as_secs_f64();
            println!(
                "[{label:<24}] {:>7.1} MB/s   {got}/{MSGS} delivered in {secs:.2}s",
                (got * CHUNK) as f64 / 1e6 / secs.max(1e-9),
            );
            let _ = sender.await.unwrap();
        }

        for (label, in_order) in [("rust↔rust ordered", true), ("rust↔rust unordered", false)] {
            let (mut server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
            let sender = tokio::spawn(async move {
                for i in 0..MSGS {
                    if client
                        .send_with(&vec![pattern(i); CHUNK], None, in_order)
                        .await
                        .is_err()
                    {
                        return (client, i);
                    }
                }
                (client, MSGS)
            });

            let mut buf = vec![0u8; CHUNK * 2];
            let start = std::time::Instant::now();
            let mut got = 0usize;
            while got < MSGS {
                match tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf)).await {
                    Ok(Ok(_)) => got += 1,
                    _ => break,
                }
            }
            let secs = start.elapsed().as_secs_f64();
            println!(
                "[{label:<24}] {:>7.1} MB/s   {got}/{MSGS} delivered in {secs:.2}s",
                (got * CHUNK) as f64 / 1e6 / secs.max(1e-9),
            );
            let _ = sender.await.unwrap();
        }
    }

    // ── Connection setup latency ──────────────────────────────────────────────
    //
    // Rendezvous in particular: the handshake is a symmetric exchange with a
    // 250 ms retransmit timer on the Rust side, so a single lost or mistimed
    // packet is directly visible as a step in these numbers.

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

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn connect_latency_all_paths() {
        // Hold one C++ socket open for the whole run. Without it, each
        // iteration drops the last UDT socket, the library's global refcount
        // hits zero, and `UDT::cleanup()` blocks in the GC loop
        // (api.cpp `checkBrokenSockets`) until closed sockets age out after a
        // hard-coded 1 000 000 µs. That is teardown, not connection setup, and
        // measuring it would attribute a full second to every C++ connect.
        let _keep_udt_alive =
            Arc::new(udt_compat::Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());

        time_n("rust listen/connect", 20, || async {
            let _ = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        })
        .await;

        time_n("rust↔rust rendezvous", 20, || async {
            let _ = new_rendezvous_pair().await;
        })
        .await;

        time_n("rust↔cpp rendezvous", 20, || async {
            let _ = new_s5_pair().await;
        })
        .await;

        time_n("cpp listen/connect", 20, || async {
            let _ = new_cpp_cpp_pair().await;
        })
        .await;

        time_n("cpp↔cpp rendezvous", 20, || async {
            let _ = new_cpp_cpp_rendezvous_pair().await;
        })
        .await;
    }

    /// C++ rendezvous on both ends, via the async bridge.
    async fn new_cpp_cpp_rendezvous_pair() -> (udt_compat::Connection, udt_compat::Connection) {
        use udt_compat::Endpoint as CppEndpoint;

        let ep_a = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let ep_b = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let addr_a = ep_a.local_addr().unwrap();
        let addr_b = ep_b.local_addr().unwrap();

        tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(10), ep_a.connect(addr_b, true))
                    .await
                    .expect("cpp rendezvous A timed out")
                    .expect("cpp rendezvous A failed")
            },
            async {
                tokio::time::timeout(Duration::from_secs(10), ep_b.connect(addr_a, true))
                    .await
                    .expect("cpp rendezvous B timed out")
                    .expect("cpp rendezvous B failed")
            }
        )
    }

    // ── Benchmarks ────────────────────────────────────────────────────────────
    //
    // Run with: cargo test --release -- --ignored --nocapture --test-threads=1
    //
    // Two distinct patterns, because they measure different things:
    //
    //  * `stream_*` keeps the pipe full — a dedicated sender pushes continuously
    //    while a receiver drains.  This is the throughput number.
    //
    //  * `pingpong_*` sends one message and waits for it to arrive before
    //    sending the next.  With only one message in flight this is really a
    //    latency measurement, and it is dominated by how promptly the *receiver*
    //    acknowledges a burst that is followed by silence.
    //
    // Every configuration has a C++↔C++ variant so the Rust numbers can be read
    // against the reference implementation on the same machine, in the same
    // conditions, rather than against an absolute expectation.

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

    /// C++ listener + C++ connector — the reference implementation talking to
    /// itself, for a same-machine baseline.
    async fn new_cpp_cpp_pair() -> (udt_compat::Connection, udt_compat::Connection) {
        use udt_compat::Endpoint as CppEndpoint;

        let srv_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let srv_addr = srv_ep.local_addr().unwrap();
        let listener = srv_ep.listen(4).unwrap();

        tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .expect("cpp accept timed out")
                    .expect("cpp accept failed")
            },
            async {
                let cep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
                tokio::time::timeout(Duration::from_secs(5), cep.connect(srv_addr, false))
                    .await
                    .expect("cpp connect timed out")
                    .expect("cpp connect failed")
            }
        )
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
        let (mut server, mut client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
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

    // ── Streaming throughput ──────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn stream_rust_to_rust() {
        let (mut server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
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
    async fn stream_cpp_to_cpp() {
        let (server, client) = new_cpp_cpp_pair().await;
        let chunk = vec![0x5Au8; BENCH_CHUNK];

        let start = std::time::Instant::now();
        let sender = tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < BENCH_TOTAL {
                sent += client.send(&chunk).await.unwrap();
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
        report("stream cpp→cpp", got, elapsed);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn stream_rust_to_cpp() {
        let (cpp_conn, rust_sock) = new_s3_pair().await;
        let chunk = vec![0x5Au8; BENCH_CHUNK];

        let start = std::time::Instant::now();
        let sender = tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < BENCH_TOTAL {
                rust_sock.send(&chunk).await.unwrap();
                sent += BENCH_CHUNK;
            }
            rust_sock
        });

        let mut buf = vec![0u8; BENCH_CHUNK * 2];
        let mut got = 0usize;
        while got < BENCH_TOTAL {
            got += cpp_conn.recv(&mut buf).await.unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        let _held = sender.await.unwrap();
        report("stream rust→cpp", got, elapsed);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn stream_cpp_to_rust() {
        let (mut rust_sock, cpp_conn) = new_s2_pair().await;
        let chunk = vec![0x5Au8; BENCH_CHUNK];

        let start = std::time::Instant::now();
        let sender = tokio::spawn(async move {
            let mut sent = 0usize;
            while sent < BENCH_TOTAL {
                sent += cpp_conn.send(&chunk).await.unwrap();
            }
            cpp_conn
        });

        let mut buf = vec![0u8; BENCH_CHUNK * 2];
        let mut got = 0usize;
        while got < BENCH_TOTAL {
            got += rust_sock.recv(&mut buf).await.unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        let _held = sender.await.unwrap();
        report("stream cpp→rust", got, elapsed);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn stream_rust_two_connections() {
        let ep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = ep.local_addr().unwrap();
        let mut listener = ep.listen(4).unwrap();

        let conn_tasks: Vec<_> = (0..2)
            .map(|_| {
                tokio::spawn(async move {
                    let cep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
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
            .map(|(mut srv, cli)| {
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
        let totals: Vec<usize> = futures::future::join_all(xfer)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
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
        let (mut server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        let chunk = vec![0x55u8; BENCH_CHUNK];
        let mut buf = vec![0u8; BENCH_CHUNK * 2];

        let start = std::time::Instant::now();
        for _ in 0..PINGPONG_MSGS {
            client.send(&chunk).await.unwrap();
            server.recv(&mut buf).await.unwrap();
        }
        report_latency("pingpong rust→rust", PINGPONG_MSGS, start.elapsed().as_secs_f64());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn pingpong_cpp_to_cpp() {
        let (server, client) = new_cpp_cpp_pair().await;
        let chunk = vec![0x55u8; BENCH_CHUNK];
        let mut buf = vec![0u8; BENCH_CHUNK * 2];

        let start = std::time::Instant::now();
        for _ in 0..PINGPONG_MSGS {
            client.send(&chunk).await.unwrap();
            server.recv(&mut buf).await.unwrap();
        }
        report_latency("pingpong cpp→cpp", PINGPONG_MSGS, start.elapsed().as_secs_f64());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn pingpong_rust_to_cpp() {
        let (cpp_conn, rust_sock) = new_s3_pair().await;
        let chunk = vec![0x55u8; BENCH_CHUNK];
        let mut buf = vec![0u8; BENCH_CHUNK * 2];

        let start = std::time::Instant::now();
        for _ in 0..PINGPONG_MSGS {
            rust_sock.send(&chunk).await.unwrap();
            cpp_conn.recv(&mut buf).await.unwrap();
        }
        report_latency("pingpong rust→cpp", PINGPONG_MSGS, start.elapsed().as_secs_f64());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn pingpong_cpp_to_rust() {
        let (mut rust_sock, cpp_conn) = new_s2_pair().await;
        let chunk = vec![0x55u8; BENCH_CHUNK];
        let mut buf = vec![0u8; BENCH_CHUNK * 2];

        let start = std::time::Instant::now();
        for _ in 0..PINGPONG_MSGS {
            cpp_conn.send(&chunk).await.unwrap();
            rust_sock.recv(&mut buf).await.unwrap();
        }
        report_latency("pingpong cpp→rust", PINGPONG_MSGS, start.elapsed().as_secs_f64());
    }
}
