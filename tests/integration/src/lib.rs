#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use udt_async::{Endpoint, Socket};

    const SMALL: &[u8] = b"hello, world!   "; // 16 bytes — single packet
    fn medium() -> Vec<u8> { vec![0x42u8; 4096] } // 3 packets at 1472B MSS
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
}
