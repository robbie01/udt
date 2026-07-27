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
