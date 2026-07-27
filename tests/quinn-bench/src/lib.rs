//! Throughput reference point: [quinn] on loopback.
//!
//! [quinn]: https://crates.io/crates/quinn
//!
//! Quinn is a mature Rust QUIC implementation over UDP, so it bounds what this
//! machine's UDP stack achieves under a comparable design — one connection, one
//! event loop, one datagram per `sendto`. Our own single-connection ceiling was
//! measured as ~95% `sendto`/`recvfrom` time, and this is the cross-check on
//! that conclusion.
//!
//! **Not a like-for-like comparison.** Quinn encrypts every packet (AES-GCM or
//! ChaCha20-Poly1305) and UDT does not, so quinn pays crypto per byte that we
//! never pay. Read it as a floor for "a well-optimised Rust UDP transport on
//! this box", not as a target we should match exactly.
//!
//! Run with:
//! `cargo test -p quinn-bench --release -- --ignored --nocapture --test-threads=1`

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};

    const TOTAL: usize = 128 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;

    fn report(name: &str, bytes: usize, elapsed: f64) {
        println!(
            "[{name:<26}] {:>7.1} MB/s  ({} MiB in {:.2}s)",
            bytes as f64 / 1e6 / elapsed,
            bytes / (1024 * 1024),
            elapsed,
        );
    }

    /// Self-signed cert trusted directly by the client — this measures the data
    /// path, not PKI.
    fn configs() -> (ServerConfig, ClientConfig) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        // Windows large enough that flow control is never the limiter; we are
        // measuring the transport, not a default window.
        let mut transport = TransportConfig::default();
        transport
            .stream_receive_window((8u32 * 1024 * 1024).into())
            .receive_window((16u32 * 1024 * 1024).into())
            .send_window(16 * 1024 * 1024);
        let transport = Arc::new(transport);

        let mut server = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())
            .expect("server config");
        server.transport_config(Arc::clone(&transport));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client.transport_config(transport);

        (server, client)
    }

    /// One connection, one unidirectional stream, sender and receiver running
    /// concurrently — the same shape as our own `stream_rust_to_rust`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn quinn_stream_loopback() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server_cfg, client_cfg) = configs();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Endpoint::server(server_cfg, addr).unwrap();
        let server_addr = server.local_addr().unwrap();

        let acceptor = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let mut recv = conn.accept_uni().await.unwrap();
            let mut got = 0usize;
            let mut buf = vec![0u8; CHUNK * 2];
            while got < TOTAL {
                match recv.read(&mut buf).await.unwrap() {
                    Some(n) => got += n,
                    None => break,
                }
            }
            (got, server)
        });

        let mut client = Endpoint::client(addr).unwrap();
        client.set_default_client_config(client_cfg);
        let conn = client.connect(server_addr, "localhost").unwrap().await.unwrap();

        let start = std::time::Instant::now();
        let mut send = conn.open_uni().await.unwrap();
        let sender = tokio::spawn(async move {
            let chunk = vec![0x5Au8; CHUNK];
            let mut sent = 0usize;
            while sent < TOTAL {
                send.write_all(&chunk).await.unwrap();
                sent += CHUNK;
            }
            send.finish().unwrap();
            send
        });

        let (got, _server) = acceptor.await.unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        let _held = sender.await.unwrap();
        report("quinn 1 stream", got, elapsed);
        assert_eq!(got, TOTAL, "quinn delivered {got} of {TOTAL} bytes");
    }

    /// Two connections in parallel, matching `stream_rust_two_connections`.
    /// Isolates how much of the single-connection number is per-connection
    /// serialisation rather than a protocol limit.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn quinn_stream_loopback_2conn() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        const PER_CONN: usize = TOTAL / 2;

        let start = std::time::Instant::now();
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                let (server_cfg, client_cfg) = configs();
                tokio::spawn(async move {
                    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
                    let server = Endpoint::server(server_cfg, addr).unwrap();
                    let server_addr = server.local_addr().unwrap();

                    let acceptor = tokio::spawn(async move {
                        let conn = server.accept().await.unwrap().await.unwrap();
                        let mut recv = conn.accept_uni().await.unwrap();
                        let mut got = 0usize;
                        let mut buf = vec![0u8; CHUNK * 2];
                        while got < PER_CONN {
                            match recv.read(&mut buf).await.unwrap() {
                                Some(n) => got += n,
                                None => break,
                            }
                        }
                        (got, server)
                    });

                    let mut client = Endpoint::client(addr).unwrap();
                    client.set_default_client_config(client_cfg);
                    let conn =
                        client.connect(server_addr, "localhost").unwrap().await.unwrap();
                    let mut send = conn.open_uni().await.unwrap();
                    let sender = tokio::spawn(async move {
                        let chunk = vec![0x5Au8; CHUNK];
                        let mut sent = 0usize;
                        while sent < PER_CONN {
                            send.write_all(&chunk).await.unwrap();
                            sent += CHUNK;
                        }
                        send.finish().unwrap();
                        send
                    });
                    let (got, _server) = acceptor.await.unwrap();
                    let _held = sender.await.unwrap();
                    got
                })
            })
            .collect();

        let mut total = 0usize;
        for t in tasks {
            total += t.await.unwrap();
        }
        report("quinn 2 streams", total, start.elapsed().as_secs_f64());
    }
}
