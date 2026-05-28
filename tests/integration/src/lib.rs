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

    // ── Scenario 2: new listener + old connector (udt-compat connects) ───────

    #[tokio::test(flavor = "multi_thread")]
    async fn s2_new_listener_old_connector_small() {
        use udt_compat::Endpoint as CppEndpoint;

        let ep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = ep.local_addr().unwrap();
        let mut listener = ep.listen(4).unwrap();

        let (mut server_sock, cpp_conn) = tokio::join!(
            async { listener.accept().await.unwrap() },
            async {
                let cpp_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
                tokio::time::timeout(Duration::from_secs(5), cpp_ep.connect(server_addr, false))
                    .await
                    .expect("cpp connect timed out")
                    .expect("cpp connect failed")
            }
        );

        let mut buf = vec![0u8; 65536];
        for _ in 0..5 {
            cpp_conn.send(SMALL).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), server_sock.recv(&mut buf))
                .await
                .expect("server recv timed out")
                .unwrap();
            assert_eq!(&buf[..n], SMALL);

            server_sock.send(&buf[..n]).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), cpp_conn.recv(&mut buf))
                .await
                .expect("cpp recv timed out")
                .unwrap();
            assert_eq!(&buf[..n], SMALL);
        }
    }

    // ── Scenario 3: old listener + new connector ──────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn s3_old_listener_new_connector_small() {
        use udt_compat::Endpoint as CppEndpoint;

        let cpp_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let server_addr = cpp_ep.local_addr().unwrap();
        let cpp_listener = cpp_ep.listen(4).unwrap();

        let (cpp_conn, mut client_sock) = tokio::join!(
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

        let mut buf = vec![0u8; 65536];
        for _ in 0..5 {
            client_sock.send(SMALL).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), cpp_conn.recv(&mut buf))
                .await
                .expect("cpp recv timed out")
                .unwrap();
            assert_eq!(&buf[..n], SMALL);

            cpp_conn.send(&buf[..n]).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), client_sock.recv(&mut buf))
                .await
                .expect("client recv timed out")
                .unwrap();
            assert_eq!(&buf[..n], SMALL);
        }
    }

    // ── Scenario 5: rendezvous old + new ──────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn s5_rendezvous_old_new_small() {
        use udt_compat::Endpoint as CppEndpoint;

        let cpp_ep = Arc::new(CppEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let rust_ep = Endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let cpp_addr = cpp_ep.local_addr().unwrap();
        let rust_addr = rust_ep.local_addr().unwrap();

        let (cpp_conn, mut rust_sock) = tokio::join!(
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

        let mut buf = vec![0u8; 65536];
        for _ in 0..5 {
            rust_sock.send(SMALL).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), cpp_conn.recv(&mut buf))
                .await
                .expect("cpp recv timed out")
                .unwrap();
            assert_eq!(&buf[..n], SMALL);

            cpp_conn.send(&buf[..n]).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), rust_sock.recv(&mut buf))
                .await
                .expect("rust recv timed out")
                .unwrap();
            assert_eq!(&buf[..n], SMALL);
        }
    }
}
