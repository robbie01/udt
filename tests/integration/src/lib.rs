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

    // ── Throughput benchmarks (run with: cargo test throughput -- --ignored --nocapture) ──

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn throughput_rust_single_connection() {
        const TOTAL: usize = 128 * 1024 * 1024; // 128 MiB
        const CHUNK: usize = 64 * 1024;          // 64 KiB per message

        let (mut server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        let mut buf = vec![0u8; CHUNK * 2];
        let chunk = vec![0x55u8; CHUNK];

        let start = std::time::Instant::now();
        let mut sent = 0usize;
        while sent < TOTAL {
            client.send(&chunk).await.unwrap();
            let n = server.recv(&mut buf).await.unwrap();
            sent += n;
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "[throughput_rust_single] {:.1} MB/s  ({} MiB in {:.2}s)",
            sent as f64 / 1e6 / elapsed,
            sent / (1024 * 1024),
            elapsed
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn throughput_rust_two_connections_concurrent() {
        const TOTAL: usize = 64 * 1024 * 1024; // 64 MiB per connection
        const CHUNK: usize = 64 * 1024;

        let ep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = ep.local_addr().unwrap();
        let mut listener = ep.listen(4).unwrap();

        let conn_tasks: Vec<_> = (0..2).map(|_| {
            tokio::spawn(async move {
                let cep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
                cep.connect(server_addr).await.unwrap()
            })
        }).collect();
        let mut server_socks = Vec::new();
        for _ in 0..2 { server_socks.push(listener.accept().await.unwrap()); }
        let client_socks: Vec<Socket> = {
            let mut v = Vec::new();
            for t in conn_tasks { v.push(t.await.unwrap()); }
            v
        };

        let start = std::time::Instant::now();
        let xfer: Vec<_> = server_socks.into_iter().zip(client_socks)
            .map(|(mut srv, cli)| {
                let chunk = vec![0xAAu8; CHUNK];
                tokio::spawn(async move {
                    let mut buf = vec![0u8; CHUNK * 2];
                    let mut sent = 0usize;
                    while sent < TOTAL {
                        cli.send(&chunk).await.unwrap();
                        let n = srv.recv(&mut buf).await.unwrap();
                        sent += n;
                    }
                    sent
                })
            })
            .collect();
        let totals: Vec<usize> = futures::future::join_all(xfer)
            .await.into_iter().map(|r| r.unwrap()).collect();
        let elapsed = start.elapsed().as_secs_f64();
        let total_bytes: usize = totals.iter().sum();
        println!(
            "[throughput_rust_2conn] {:.1} MB/s combined  ({} MiB in {:.2}s)",
            total_bytes as f64 / 1e6 / elapsed,
            total_bytes / (1024 * 1024),
            elapsed
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn throughput_cpp_connector_rust_listener() {
        #[allow(unused_imports)]
        use udt_compat::Endpoint as CppEndpoint;
        const TOTAL: usize = 128 * 1024 * 1024;
        const CHUNK: usize = 64 * 1024;

        let (mut rust_sock, cpp_conn) = new_s2_pair().await;
        let mut buf = vec![0u8; CHUNK * 2];
        let chunk = vec![0xBBu8; CHUNK];

        let start = std::time::Instant::now();
        let mut sent = 0usize;
        while sent < TOTAL {
            cpp_conn.send(&chunk).await.unwrap();
            let n = rust_sock.recv(&mut buf).await.unwrap();
            sent += n;
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "[throughput_cpp→rust] {:.1} MB/s  ({} MiB in {:.2}s)",
            sent as f64 / 1e6 / elapsed,
            sent / (1024 * 1024),
            elapsed
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn throughput_rust_connector_cpp_listener() {
        #[allow(unused_imports)]
        use udt_compat::Endpoint as CppEndpoint;
        const TOTAL: usize = 128 * 1024 * 1024;
        const CHUNK: usize = 64 * 1024;

        let (cpp_conn, rust_sock) = new_s3_pair().await;
        let mut buf = vec![0u8; CHUNK * 2];
        let chunk = vec![0xCCu8; CHUNK];

        let start = std::time::Instant::now();
        let mut sent = 0usize;
        while sent < TOTAL {
            rust_sock.send(&chunk).await.unwrap();
            let n = cpp_conn.recv(&mut buf).await.unwrap();
            sent += n;
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "[throughput_rust→cpp] {:.1} MB/s  ({} MiB in {:.2}s)",
            sent as f64 / 1e6 / elapsed,
            sent / (1024 * 1024),
            elapsed
        );
    }
}
