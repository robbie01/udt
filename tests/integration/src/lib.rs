#![forbid(unsafe_code)]

mod relay;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use udt_async::{Connection, Endpoint, EndpointConfig, SendOptions};

    const SMALL: &[u8] = b"hello, world!   "; // 16 bytes — single packet
    fn medium() -> Vec<u8> {
        vec![0x42u8; 4096]
    } // 3 packets at default MSS (payload=1436B)
    fn large() -> Vec<u8> {
        vec![0x7fu8; 65536]
    } // ~45 packets

    // ── Pure Rust helpers ────────────────────────────────────────────────────

    async fn new_listener_pair(listener_addr: SocketAddr) -> (Connection, Connection) {
        let ep = Endpoint::bind(listener_addr).await.unwrap();
        let server_addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();

        let (server_sock, client_sock) =
            tokio::join!(async { listener.accept().await.unwrap() }, async {
                let cep = Endpoint::bind("127.0.0.1:0").await.unwrap();
                tokio::time::timeout(Duration::from_secs(5), async {
                    cep.connect(server_addr).await?.await
                })
                .await
                .expect("connect timed out")
                .expect("connect failed")
            });
        (server_sock, client_sock)
    }

    async fn echo_exchange(server: Connection, client: Connection, payload: &[u8], count: usize) {
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

    /// An outbound connection sends from the endpoint's own address, not a
    /// fresh ephemeral port.
    ///
    /// Taking a new port for each dial opens a second pinhole in the local
    /// firewall and makes the source a peer observes disagree with the address
    /// it was handed — which for a peer-to-peer system is most of the point of
    /// having an endpoint at all. Checked from the far side as well as locally,
    /// because only the peer's view proves what actually went on the wire.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_outbound_connection_sends_from_the_endpoint_port() {
        let server_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_ep.local_addr();
        let listener = server_ep.listen(4).unwrap();

        let client_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_ep.local_addr();

        let (server, client) = tokio::join!(async { listener.accept().await.unwrap() }, async {
            client_ep.connect(server_addr).await.unwrap().await.unwrap()
        });

        assert_eq!(client.local_addr(), client_addr, "the dial took a different local address");
        assert_eq!(server.peer_addr(), client_addr, "the peer saw a different source address");

        // A second connection over the same endpoint shares it rather than
        // taking yet another port.
        let (server2, client2) = tokio::join!(async { listener.accept().await.unwrap() }, async {
            client_ep.connect(server_addr).await.unwrap().await.unwrap()
        });
        assert_eq!(client2.local_addr(), client_addr);
        assert_eq!(server2.peer_addr(), client_addr);

        // And they are still distinct connections, told apart by socket id.
        client.send(b"first").await.unwrap();
        client2.send(b"second").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
            .await
            .expect("first connection timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"first", "two connections on one port were commingled");
        let n = tokio::time::timeout(Duration::from_secs(5), server2.recv(&mut buf))
            .await
            .expect("second connection timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"second", "two connections on one port were commingled");
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

    async fn new_rendezvous_pair() -> (Connection, Connection) {
        let ep_a = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let ep_b = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let addr_a = ep_a.local_addr();
        let addr_b = ep_b.local_addr();

        let (sock_a, sock_b) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    ep_a.connect_rendezvous(addr_b).await.expect("rendezvous A not started").await
                })
                .await
                .expect("rendezvous A timed out")
                .expect("rendezvous A failed")
            },
            async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    ep_b.connect_rendezvous(addr_a).await.expect("rendezvous B not started").await
                })
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
                    let sock = tokio::time::timeout(Duration::from_secs(5), async {
                        cep.connect(server_addr).await?.await
                    })
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

    /// The negotiated limit must be visible on both ends and agree.
    ///
    /// It is what a sender sizes its framing to, so a value that only one end
    /// knows, or that the two disagree on, would be worse than none.
    #[tokio::test(flavor = "multi_thread")]
    async fn both_ends_agree_on_the_unsegmented_limit() {
        let server_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = server_ep.local_addr();
        let listener = server_ep.listen(4).unwrap();
        let client_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();

        let (server, client) = tokio::join!(async { listener.accept().await.unwrap() }, async {
            client_ep.connect(addr).await.unwrap().await.unwrap()
        });

        let c = client.max_unsegmented_len().expect("client had no limit");
        let s = server.max_unsegmented_len().expect("server had no limit");
        assert_eq!(c, s, "the two ends disagree on the unsegmented limit");
        assert_eq!(c, udt_async::MAX_PAYLOAD_SIZE, "loopback should negotiate the default MTU");

        // And a message of exactly that size makes the round trip intact.
        let payload = vec![0xA5u8; c];
        client.send(&payload).await.unwrap();
        let mut buf = vec![0u8; c * 2];
        let n = tokio::time::timeout(Duration::from_secs(10), server.recv(&mut buf))
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(&buf[..n], &payload[..]);
    }

    /// Messages queued on a `Connecting` must arrive as the connection's first
    /// messages, in order, with no special handling on the server.
    #[tokio::test(flavor = "multi_thread")]
    async fn early_data_arrives_as_the_first_messages() {
        let msgs: [&[u8]; 3] = [b"noise msg1", b"and a payload", b"and a request"];

        let server_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = server_ep.local_addr();
        let listener = server_ep.listen(4).unwrap();

        let client_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let (server, client) = tokio::join!(async { listener.accept().await.unwrap() }, async {
            let connecting = client_ep.connect(addr).await.unwrap();
            for m in msgs {
                connecting.try_send(m).expect("early message refused");
            }
            connecting.await.unwrap()
        });

        // Ordinary recvs, exactly as a server that knows nothing about this
        // would write them.
        let mut buf = vec![0u8; 4096];
        for want in msgs {
            let n = tokio::time::timeout(Duration::from_secs(10), server.recv(&mut buf))
                .await
                .expect("early data never arrived")
                .unwrap();
            assert_eq!(&buf[..n], want);
        }

        // And nothing is delivered twice: a follow-up must be next, not a
        // repeat of what already arrived.
        client.send(b"after").await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(10), server.recv(&mut buf))
            .await
            .expect("follow-up never arrived")
            .unwrap();
        assert_eq!(&buf[..n], b"after", "an early message was delivered twice");
    }

    /// Rendezvous carries early data too, in both directions at once.
    ///
    /// It is the case with no listener to hold anything: each peer's connection
    /// exists before either sends a packet, so the data arrives at a connection
    /// still negotiating. Both sides queue, so both have to handle that.
    #[tokio::test(flavor = "multi_thread")]
    async fn rendezvous_carries_early_data_both_ways() {
        let msgs: [&[u8]; 2] = [b"noise e", b"noise es payload"];

        let ep_a = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let ep_b = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let (addr_a, addr_b) = (ep_a.local_addr(), ep_b.local_addr());

        let (conn_a, conn_b) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                async {
                    let c = ep_a.connect_rendezvous(addr_b).await.expect("A not started");
                    for m in msgs {
                        c.try_send(m).expect("early message refused");
                    }
                    c.await.expect("rendezvous A failed")
                },
                async {
                    let c = ep_b.connect_rendezvous(addr_a).await.expect("B not started");
                    for m in msgs {
                        c.try_send(m).expect("early message refused");
                    }
                    c.await.expect("rendezvous B failed")
                },
            )
        })
        .await
        .expect("rendezvous timed out");

        for conn in [&conn_a, &conn_b] {
            let mut buf = vec![0u8; 4096];
            for want in msgs {
                let n = tokio::time::timeout(Duration::from_secs(10), conn.recv(&mut buf))
                    .await
                    .expect("early data never arrived")
                    .unwrap();
                assert_eq!(&buf[..n], want);
            }
        }

        // Nothing delivered twice: the follow-up must be next, not a repeat.
        conn_a.send(b"after").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(10), conn_b.recv(&mut buf))
            .await
            .expect("follow-up never arrived")
            .unwrap();
        assert_eq!(&buf[..n], b"after", "an early message was delivered twice");
    }

    /// Past what the handshake can carry, messages are held rather than lost —
    /// they go out as soon as the connection completes, still in order.
    #[tokio::test(flavor = "multi_thread")]
    async fn early_data_past_the_cap_still_arrives_in_order() {
        const N: usize = udt_async::MAX_EARLY_MESSAGES + 8;

        let server_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = server_ep.local_addr();
        let listener = server_ep.listen(4).unwrap();
        let client_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();

        let (server, _client) = tokio::join!(async { listener.accept().await.unwrap() }, async {
            let connecting = client_ep.connect(addr).await.unwrap();
            for i in 0..N {
                connecting.try_send(format!("{i}").as_bytes()).expect("refused");
            }
            connecting.await.unwrap()
        });

        let mut buf = vec![0u8; 4096];
        for i in 0..N {
            let n = tokio::time::timeout(Duration::from_secs(10), server.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("message {i} never arrived"))
                .unwrap();
            assert_eq!(&buf[..n], format!("{i}").as_bytes(), "message {i} out of order");
        }
    }

    /// An empty early message is refused, as it is on an open connection.
    #[tokio::test(flavor = "multi_thread")]
    async fn empty_early_data_is_refused() {
        let server_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = server_ep.local_addr();
        let _listener = server_ep.listen(4).unwrap();
        let client_ep = Endpoint::bind("127.0.0.1:0").await.unwrap();

        let connecting = client_ep.connect(addr).await.unwrap();
        let kind = match connecting.try_send(b"") {
            Ok(()) => panic!("an empty early message was accepted"),
            Err(e) => e.kind(),
        };
        assert_eq!(kind, std::io::ErrorKind::InvalidInput);
    }

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
                    tokio::time::timeout(Duration::from_secs(5), async {
                        ep_a.connect_rendezvous(addr_b)
                            .await
                            .expect("rendezvous A not started")
                            .await
                    })
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
                    let sock = tokio::time::timeout(Duration::from_secs(5), async {
                        ep_b.connect_rendezvous(addr_a)
                            .await
                            .expect("rendezvous B not started")
                            .await
                    })
                    .await
                    .expect("rendezvous B timed out")
                    .expect("rendezvous B failed");
                    (sock, payload)
                })
            })
            .collect();

        // Collect sockets from side A.
        let mut socks_a: Vec<Connection> = Vec::new();
        for t in tasks_a.drain(..) {
            socks_a.push(t.await.unwrap());
        }
        let pairs: Vec<(Connection, Connection, Vec<u8>)> = {
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

    /// A live connection can be inspected.
    ///
    /// `ConnectionStats` existed in the protocol crate and was unreachable from
    /// here, so an operator had no view of round-trip time, window or backlog on
    /// a connection that was misbehaving.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_live_connection_can_be_inspected() {
        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;

        let payload = vec![0x33u8; 64 * 1024];
        client.send(&payload).await.expect("send failed");
        let mut buf = vec![0u8; payload.len() * 2];
        let n = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
            .await
            .expect("recv timed out")
            .expect("recv failed");
        assert_eq!(n, payload.len());

        let s = client.stats().expect("a connected socket should report state");
        assert!(s.connected, "reported as not connected while it plainly is");
        assert!(s.rtt_us > 0, "no round-trip estimate");
        assert!(s.cwnd > 0.0, "no congestion window");

        // And it stops reporting rather than going stale once the peer is gone.
        drop(server);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while client.stats().is_some_and(|s| s.connected) && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !client.stats().is_some_and(|s| s.connected),
            "still reporting a live connection after the peer went away"
        );
    }

    /// Closing tells the peer *why*, not just that.
    ///
    /// Every cause used to arrive as one `BrokenPipe`, so an application could
    /// not tell a peer closing cleanly from a path that will not carry its
    /// packets — opposite decisions: one says stop, the other says retry with a
    /// smaller MTU.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_closed_connection_says_why() {
        use udt_async::DisconnectReason;

        let (server, client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        assert_eq!(client.disconnect_reason(), None, "a live connection has no reason yet");

        // The peer going away cleanly is a shutdown, and it reads as one.
        drop(client);
        let mut buf = vec![0u8; 1024];
        let err = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
            .await
            .expect("recv should not hang after the peer closed")
            .expect_err("recv should fail once the peer has gone");

        assert_eq!(
            server.disconnect_reason(),
            Some(DisconnectReason::Shutdown),
            "a clean peer close should be reported as one, got {:?}",
            server.disconnect_reason()
        );
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionAborted,
            "the error kind should distinguish a peer close from anything else"
        );
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
            tokio::time::timeout(Duration::from_secs(5), async {
                cep.connect(server_addr).await?.await
            })
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
    async fn ledbat_shares_a_link_without_running_away() {
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
                    cep.connect(addr).await.unwrap().await.unwrap()
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

        // Against the default, which is now CUBIC. Measured against UdtCc this
        // said nothing: that controller does not converge to a share, so
        // "ledbat took less than it" was a fact about UdtCc.
        let a = tokio::spawn(spawn_flow(CcKind::Cubic, Arc::clone(&udt_bytes), Arc::clone(&stop)));
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
            "[ledbat-yield] cubic={:.1} MB  ledbat={:.1} MB  (ledbat took {:.0}% of the pair)",
            udt as f64 / 1e6,
            led as f64 / 1e6,
            100.0 * led as f64 / (udt + led).max(1) as f64,
        );
        assert!(led > 0, "LEDBAT flow moved nothing at all");

        // Deliberately not `led <= udt`. LEDBAT yields by sensing the queuing
        // delay a full bottleneck buffer creates, and loopback has no bottleneck
        // and so nothing to sense — the two flows are near enough even, and
        // which one edges ahead is scheduling noise. Locally that reads 44-45%;
        // a loaded CI runner produced 51% and failed an assertion that had no
        // business being strict.
        //
        // What loopback *can* show is that the controller runs, moves data, and
        // does not run away with the link. The property this test is named for
        // is proven in `congestion::sim::ledbat_yields_to_udt_cc_on_a_bottleneck`,
        // which models an actual bottleneck and holds LEDBAT under 25%.
        let share = 100.0 * led as f64 / (udt + led).max(1) as f64;
        assert!(
            share < 65.0,
            "LEDBAT took {share:.0}% of a link with no bottleneck ({led} B against {udt} B); \
             it is supposed to be a scavenger, not merely even"
        );
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

    /// One transfer, one number.
    ///
    /// A smoke figure only: enough to notice that throughput has fallen off a
    /// cliff, useless for telling two builds apart. Use [`Samples`] for that —
    /// these single-shot numbers have been seen to differ by a factor of two
    /// between consecutive runs of the same binary.
    fn report(name: &str, bytes: usize, elapsed: f64) {
        println!(
            "[{name:<26}] {:>7.1} MB/s  ({} MiB in {:.2}s, single run)",
            bytes as f64 / 1e6 / elapsed,
            bytes / (1024 * 1024),
            elapsed,
        );
    }

    /// Throughput measured repeatedly, reported as a distribution.
    ///
    /// A single number is not a measurement here. The same binary on the same
    /// idle machine has been seen to differ by 5x between sessions and by 2x
    /// between consecutive runs, which over this project's history produced
    /// several confident and wrong conclusions — a machine artefact read as a
    /// code regression, and twice the reverse. Anything comparing two builds
    /// needs the spread, not the mean, and needs to discard the first round.
    #[derive(Default)]
    struct Samples {
        rates: Vec<f64>,
    }

    impl Samples {
        /// Record one round. `bytes` over `secs` becomes a rate in MB/s.
        fn push(&mut self, bytes: usize, secs: f64) {
            if secs > 0.0 {
                self.rates.push(bytes as f64 / 1e6 / secs);
            }
        }

        /// Print the median, and the range around it.
        ///
        /// The first round is dropped: it pays for connection setup, slow start,
        /// and whatever the allocator and page cache have not warmed yet.
        fn report(&self, name: &str) {
            let mut r = self.rates.clone();
            if r.len() > 2 {
                r.remove(0);
            }
            if r.is_empty() {
                println!("[{name:<26}] no samples");
                return;
            }
            r.sort_by(f64::total_cmp);
            let median = r[r.len() / 2];
            let (lo, hi) = (r[0], r[r.len() - 1]);
            // Spread relative to the median is the number that says whether a
            // difference between two builds means anything.
            let spread = if median > 0.0 { (hi - lo) / median * 100.0 } else { 0.0 };
            println!(
                "[{name:<26}] {median:>7.1} MB/s  median of {:>2}  \
                 (min {lo:>7.1} max {hi:>7.1}, spread {spread:>5.1}%)",
                r.len(),
            );
        }
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
    /// shaving them further does not move the number. That has been tested
    /// twice since: pooling the receive buffers to avoid a copy measured 25%
    /// *slower*, and moving the socket writes to a task of their own measured
    /// 5–20% slower on both platforms.
    ///
    /// So single-connection throughput is a **syscall-rate ceiling**, and the
    /// only thing that has ever moved it is making each syscall carry more.
    /// Segmentation offload and `recvmmsg` (through `quinn-udp`) did exactly
    /// that on Linux, which is why it now reaches gigabytes a second where
    /// macOS, which has neither, sits near 500 MB/s at the same packet size.
    ///
    /// What is left is not in this file's reach:
    ///
    /// * On platforms without offload, connections sharing an endpoint's port
    ///   are limited by one reader doing one syscall per packet. It cannot be
    ///   split — several readers on one socket reorder a flow, which UDT reads
    ///   as loss, and that wedged the connection outright when tried. It needs
    ///   the kernel to fan out with flow affinity, or a socket per connection.
    ///   Windows is less exposed than macOS here: it has no `recvmmsg` either,
    ///   but it does coalesce received datagrams, so one call can still return
    ///   a run of them.
    /// * Raising the MTU cuts packets per byte, but then the benchmark stops
    ///   describing a 1500-byte path.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn profile_stream_rust_to_rust() {
        const ROUNDS: usize = 12;
        let (server, mut client) = new_listener_pair("127.0.0.1:0".parse().unwrap()).await;
        let chunk = vec![0x5Au8; BENCH_CHUNK];

        // Timed per round rather than in aggregate, so the output carries a
        // spread. See `Samples`.
        let mut samples = Samples::default();
        for _ in 0..ROUNDS {
            let round = std::time::Instant::now();
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
            client = sender.await.unwrap();
            samples.push(got, round.elapsed().as_secs_f64());
        }
        samples.report("profile rust→rust");
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
    ///
    /// **This one is noisy.** Rounds are held to a common barrier, so a round
    /// costs whatever the slower connection costs, and the two do not share the
    /// endpoint's reader evenly from round to round. Measured on macOS it ran a
    /// 61% spread around the median where the single-connection case ran 2.4%.
    /// Treat a difference below that as nothing at all, and prefer
    /// `rendezvous_parallel_scaling` for questions about how connections share
    /// an endpoint.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn profile_stream_two_connections() {
        const CONNS: usize = 2;
        const ROUNDS: usize = 8;
        const PER_CONN: usize = BENCH_TOTAL / CONNS;

        let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let server_addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();

        let conn_tasks: Vec<_> = (0..CONNS)
            .map(|_| {
                tokio::spawn(async move {
                    let cep = Endpoint::bind("127.0.0.1:0").await.unwrap();
                    (cep.connect(server_addr).await.unwrap().await.unwrap(), cep)
                })
            })
            .collect();
        let mut servers = Vec::new();
        for _ in 0..CONNS {
            servers.push(listener.accept().await.unwrap());
        }
        let mut clients = Vec::new();
        for t in conn_tasks {
            clients.push(t.await.unwrap());
        }

        // The connections are held to the same round boundaries so each round
        // can be timed as a whole, which is what makes the aggregate rate
        // meaningful per round rather than only across the whole run. Each
        // worker is a party, and so is this task, which does the timing.
        let gate = Arc::new(tokio::sync::Barrier::new(CONNS + 1));

        let xfer: Vec<_> = servers
            .into_iter()
            .zip(clients)
            .map(|(srv, (cli, _cep))| {
                let gate = Arc::clone(&gate);
                tokio::spawn(async move {
                    let wr = Arc::new(cli);
                    let chunk = vec![0xAAu8; BENCH_CHUNK];
                    let mut got = 0usize;
                    for _ in 0..ROUNDS {
                        gate.wait().await;
                        let c = chunk.clone();
                        let w = Arc::clone(&wr);
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
                        let mut moved = 0usize;
                        while moved < PER_CONN {
                            moved += srv.recv(&mut buf).await.unwrap();
                        }
                        got += moved;
                        sender.await.unwrap();
                        gate.wait().await;
                    }
                    (got, wr)
                })
            })
            .collect();

        let mut samples = Samples::default();
        for _ in 0..ROUNDS {
            gate.wait().await;
            let round = std::time::Instant::now();
            gate.wait().await;
            // Every connection moves PER_CONN in the round.
            samples.push(PER_CONN * CONNS, round.elapsed().as_secs_f64());
        }
        for t in xfer {
            let (_n, _held) = t.await.unwrap();
        }
        samples.report("profile rust 2-conn");
    }

    /// Rendezvous connections created from one endpoint all share that
    /// endpoint's socket and its single routing task. This measures whether
    /// that shared path is a throughput ceiling, by running the same N
    /// concurrent transfers two ways: all from one endpoint, then each from its
    /// own endpoint.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn rendezvous_parallel_scaling() {
        // Runs of each configuration. This is the least stable measurement
        // here — a single connection finishing late drags the whole aggregate
        // down, since it waits for all of them — so it is taken repeatedly and
        // reduced to a median.
        const RUNS: usize = 3;

        for n in [1usize, 2, 4, 8] {
            let mut shared = Vec::new();
            let mut separate = Vec::new();
            for _ in 0..RUNS {
                shared.push(rendezvous_throughput(n, true).await);
                separate.push(rendezvous_throughput(n, false).await);
            }
            let (s, sp) = (median(&mut shared), median(&mut separate));
            // `median` sorted them, so the ends are now the min and max.
            println!(
                "[rendezvous n={n:<2}] shared endpoint {s:>7.1} MB/s   \
                 separate endpoints {sp:>7.1} MB/s   \
                 ratio {:.2}   (median of {RUNS}, shared {:>7.1}-{:>7.1})",
                s / sp,
                shared[0],
                shared[shared.len() - 1],
            );
        }
    }

    /// Median of `v`, which is sorted in place — callers rely on that to read
    /// the min and max off the ends afterwards.
    fn median(v: &mut [f64]) -> f64 {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
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
            let (sa, sb) = tokio::join!(
                async { a.connect_rendezvous(ba).await.unwrap().await.unwrap() },
                async { b.connect_rendezvous(aa).await.unwrap().await.unwrap() },
            );
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
                    cep.connect(server_addr).await.unwrap().await.unwrap()
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

/// Regression cover for the driver's wind-down loop.
#[cfg(test)]
mod wind_down {
    use std::time::Duration;
    use udt_async::Endpoint;

    /// A fixed slice of cooperative work, measured on the thread the drivers
    /// share with this task.
    async fn work_slice() -> Duration {
        let start = std::time::Instant::now();
        for _ in 0..2_000 {
            let mut acc = 0u64;
            for i in 0..2_000u64 {
                acc = acc.wrapping_add(i * i);
            }
            std::hint::black_box(acc);
            tokio::task::yield_now().await;
        }
        start.elapsed()
    }

    /// The fastest of several slices.
    ///
    /// A single timing on a shared machine is at the mercy of whatever else is
    /// running: one perturbed sample moves the ratio either way, which failed
    /// this test once on a loaded CI runner with no spin to show for it. The
    /// minimum is the least-disturbed sample, and it keeps the test's power --
    /// a spinning driver steals from *every* slice, so the minimum stays high
    /// exactly when it should.
    async fn fastest_work_slice() -> Duration {
        let mut best = Duration::MAX;
        for _ in 0..5 {
            best = best.min(work_slice().await);
        }
        best
    }

    /// Dropping the last handle while data is still queued must leave the
    /// driver waiting, not spinning.
    ///
    /// The driver's `select!` has an arm on the application's send channel. A
    /// closed channel makes `recv()` resolve *immediately and for ever*, so once
    /// the last handle is dropped that arm is permanently ready: the loop turns
    /// as fast as the thread allows, doing no useful work, for the whole time
    /// the send buffer takes to drain. Measured directly, with a counter in the
    /// `None` arm, at ~363,000 iterations a second, sustained indefinitely
    /// while the transfer was stalled.
    ///
    /// Measured here by what a co-scheduled task loses to it, which needs no
    /// instrumentation: `#[tokio::test]` runs everything on one thread, so a
    /// driver that never parks halves it at best. The threshold is far below
    /// what was observed (5.3x to 6.6x across runs, with the stalled figure
    /// steady to within 1%), because the point is to catch a spin rather than
    /// to measure the machine. A driver that parks costs the probe nothing, so
    /// the honest expectation is ~1.0; what is measured is 2.19-2.25x in
    /// release and 6.75-7.00x in debug, each steady to within a few percent
    /// across runs. Release is lower only because the driver's work per
    /// iteration is cheaper, not because it spins less.
    ///
    /// The stall is set up so nothing is ever `blocked`: fewer bytes than the
    /// send buffer holds, but more messages than the peer's receive backlog, so
    /// the peer's driver stops reading and flow control pins the sender. With a
    /// message `blocked` instead, the arm is disabled by its own guard and the
    /// spin does not appear.
    #[tokio::test]
    async fn dropping_the_last_handle_does_not_spin_the_driver() {
        let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();
        let (server, client) = tokio::join!(async { listener.accept().await.unwrap() }, async {
            let cep = Endpoint::bind("127.0.0.1:0").await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async { cep.connect(addr).await?.await })
                .await
                .expect("connect timed out")
                .expect("connect failed")
        });

        // The peer never reads, so its receive backlog fills and the transfer
        // stalls with the send buffer still holding data.
        for _ in 0..400 {
            client.send(&[7u8; 1000]).await.unwrap();
        }

        let control = fastest_work_slice().await;
        drop(client);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stalled = fastest_work_slice().await;
        drop(server);

        let ratio = stalled.as_secs_f64() / control.as_secs_f64();
        assert!(
            ratio < 1.8,
            "the driver kept the thread busy after its last handle went away: \
             a work slice took {stalled:?} against {control:?} idle, {ratio:.1}x",
        );
    }
}

/// Regression cover for where an established connection accepts datagrams from.
#[cfg(test)]
mod source_address {
    use std::time::Duration;
    use udt_async::Endpoint;

    /// A datagram naming a connection's socket id must still have to come from
    /// that connection's peer.
    ///
    /// `Router::route` keys on the socket id alone and hands the datagram
    /// straight to that connection's driver, and `run_shared` — the path every
    /// accepted connection takes — never compares the source address against
    /// its peer. (`run_owned`, which each outgoing connection uses, does:
    /// `if rx.metas[i].addr != d.peer { continue }`.) So for an accepted
    /// connection the 32-bit socket id is the whole of the check.
    ///
    /// That matters because UDT authenticates nothing and several control
    /// packets are fatal. Forging one is normally gated on *also* spoofing the
    /// peer's source address, which off-path attackers on a network doing
    /// ingress filtering cannot do. Here an unrelated host needs only the id.
    #[tokio::test]
    async fn a_shutdown_from_a_stranger_does_not_close_the_connection() {
        let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let addr = ep.local_addr();
        let listener = ep.listen(4).unwrap();
        let (server, client) = tokio::join!(async { listener.accept().await.unwrap() }, async {
            let cep = Endpoint::bind("127.0.0.1:0").await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async { cep.connect(addr).await?.await })
                .await
                .expect("connect timed out")
                .expect("connect failed")
        });
        client.send(b"hello").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Stand in for a guessed identifier: take the real one and send a
        // shutdown from a host that has nothing to do with this connection.
        let victim_id = server.stats().expect("stats").socket_id;
        let mut shutdown = [0u8; 20];
        // word0: control bit | type 5 (shutdown); word3: destination socket id.
        shutdown[0..4].copy_from_slice(&(0x8000_0000u32 | (5u32 << 16)).to_be_bytes());
        shutdown[12..16].copy_from_slice(&victim_id.to_be_bytes());
        let stranger = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger.send_to(&shutdown, addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        client.send(b"still here").await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
            .await
            .expect("the connection was killed by a third party")
            .expect("the connection was killed by a third party");
        assert_eq!(&buf[..n], b"still here");
    }
}
