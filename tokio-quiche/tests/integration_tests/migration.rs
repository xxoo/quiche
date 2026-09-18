// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use h3i::quiche;
use h3i::quiche::test_utils::Pipe;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio::time::timeout_at;
use tokio::time::Instant;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::ClientH3Controller;
use tokio_quiche::http3::driver::ClientH3Driver;
use tokio_quiche::http3::driver::ClientH3Event;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::InboundFrame;
use tokio_quiche::http3::driver::NewClientRequest;
use tokio_quiche::quic::connect_migratable;
use tokio_quiche::quic::connect_migratable_with_config;
use tokio_quiche::quic::QuicCommand;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::quiche::h3::NameValue as _;
use tokio_quiche::ConnectionIdGenerator as _;
use tokio_quiche::ConnectionParams;

use crate::fixtures::*;

#[test]
fn connection_stats_use_active_path() {
    let mut config = Pipe::default_config("cubic").unwrap();
    config.set_active_connection_id_limit(2);

    let mut pipe = Pipe::<BufFactory>::with_config_and_scid_lengths_and_buf(
        &mut config,
        0,
        0,
    )
    .unwrap();
    pipe.handshake().unwrap();

    let migrated_addr: SocketAddr = "127.0.0.1:5678".parse().unwrap();
    pipe.client.migrate_source(migrated_addr).unwrap();

    assert!(!pipe.client.path_stats().next().unwrap().active);

    let (stats_tx, stats_rx) = std::sync::mpsc::channel();
    QuicCommand::ConnectionStats(Box::new(move |stats| {
        stats_tx.send(stats).unwrap();
    }))
    .execute(&mut pipe.client);

    let path_stats = stats_rx.recv().unwrap().path_stats.unwrap();

    assert!(path_stats.active);
    assert_eq!(path_stats.local_addr, migrated_addr);
}

#[tokio::test]
async fn test_passive_migration() {
    let _ = run_migration_test(false, 12345).await;
}

#[tokio::test]
async fn test_active_migration() {
    let _ = run_migration_test(true, 23456).await;
}

#[tokio::test]
async fn test_tokio_quiche_client_hard_migration() {
    let mut quic_settings = QuicSettings::default();
    quic_settings.active_connection_id_limit = 2;
    quic_settings.disable_active_migration = false;
    quic_settings.disable_dcid_reuse = false;

    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server_addr).await.unwrap();

    let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());
    let mut params = ConnectionParams::default();
    params.settings.discover_path_mtu = true;
    let conn = timeout(
        Duration::from_secs(5),
        connect_migratable_with_config(socket, Some("test.com"), &params, driver),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    assert!(conn.is_migratable());
    let initial_local_addr = conn.local_addr();

    send_tokio_quiche_request(&mut controller, 1).await;

    let migrated_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    migrated_socket.connect(server_addr).await.unwrap();
    let expected_migrated_addr = migrated_socket.local_addr().unwrap();

    let outcome =
        timeout(Duration::from_secs(5), conn.migrate_socket(migrated_socket))
            .await
            .expect("migration timed out")
            .expect("migration failed");

    assert_eq!(outcome.previous_local_addr, initial_local_addr);
    assert_eq!(outcome.local_addr, expected_migrated_addr);
    assert_eq!(outcome.peer_addr, server_addr);
    assert_eq!(outcome.datagram_payload_max, Some(1156));
    assert_eq!(conn.local_addr(), expected_migrated_addr);

    send_tokio_quiche_request(&mut controller, 2).await;
}

#[tokio::test]
async fn test_tokio_quiche_client_hard_migration_rejects_disabled_peer() {
    let mut quic_settings = QuicSettings::default();
    quic_settings.active_connection_id_limit = 2;
    quic_settings.disable_active_migration = true;
    quic_settings.disable_dcid_reuse = false;

    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server_addr).await.unwrap();

    let (conn, mut controller) = timeout(
        Duration::from_secs(5),
        connect_migratable(socket, Some("test.com")),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    send_tokio_quiche_request(&mut controller, 1).await;

    let initial_local_addr = conn.local_addr();
    let migrated_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    migrated_socket.connect(server_addr).await.unwrap();

    timeout(Duration::from_secs(5), conn.migrate_socket(migrated_socket))
        .await
        .expect("migration timed out")
        .expect_err("migration should fail when peer disabled it");

    assert_eq!(conn.local_addr(), initial_local_addr);
}

#[tokio::test]
async fn test_tokio_quiche_client_hard_migration_rejects_without_spare_cid() {
    let mut quic_settings = QuicSettings::default();
    quic_settings.active_connection_id_limit = 2;
    quic_settings.disable_active_migration = false;
    quic_settings.disable_dcid_reuse = false;

    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server_addr).await.unwrap();

    let (conn, mut controller) = timeout(
        Duration::from_secs(5),
        connect_migratable(socket, Some("test.com")),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    send_tokio_quiche_request(&mut controller, 1).await;

    let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    first_socket.connect(server_addr).await.unwrap();
    let first_migrated_addr = first_socket.local_addr().unwrap();

    timeout(Duration::from_secs(5), conn.migrate_socket(first_socket))
        .await
        .expect("first migration timed out")
        .expect("first migration failed");

    let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    second_socket.connect(server_addr).await.unwrap();

    timeout(Duration::from_secs(5), conn.migrate_socket(second_socket))
        .await
        .expect("second migration timed out")
        .expect_err("second migration should fail without a spare DCID");

    assert_eq!(conn.local_addr(), first_migrated_addr);
}

/// Tests that the client can migrate either actively or passively.
///
/// Active migration means the client intentionally chooses a new local address
/// to switch to. In this case, it must select a new DCID that was previously
/// issued to it by the server. The server then also switches to a new DCID
/// that was generated by the client.
///
/// Passive migration occurs when the client's address changes while keeping
/// the same source and destination CIDs. The client is not necessarily aware
/// of the change (e.g. due to NAT rebinding). Under these circumstances, the
/// endpoints are allowed to keep talking to each other with the existing
/// DCIDs.
///
/// The test simply binds a UDP socket on one address which is then used to
/// complete the handshake and send an initial HTTP/3 request. Next, it
/// switches (actively or passively) to a new socket bound to a different port
/// and sends an additional HTTP/3 request. If both requests complete that
/// means that the client was successfully migrated to the new address.
///
/// This requires using "plain" quiche as a client to properly control when and
/// where packets are sent to, which is not possible using h3i.
pub(crate) async fn run_migration_test(
    active: bool, base_port: u16,
) -> (Vec<quiche::PathEvent>, SocketAddr, SocketAddr) {
    let mut quic_settings = QuicSettings::default();
    quic_settings.active_connection_id_limit = 2;
    quic_settings.disable_active_migration = !active;
    quic_settings.disable_dcid_reuse = false;

    let hook = TestConnectionHook::new();
    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);

    let mut client_config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    client_config.set_application_protos(&[b"h3"]).unwrap();
    client_config.set_initial_max_data(1500);
    client_config.set_initial_max_stream_data_bidi_local(1500);
    client_config.set_initial_max_stream_data_bidi_remote(1500);
    client_config.set_initial_max_stream_data_uni(1500);
    client_config.set_initial_max_streams_bidi(10);
    client_config.set_initial_max_streams_uni(3);
    client_config.set_active_connection_id_limit(2);
    // QUICv1 server can't initiate migration but disable it explicitly anyway.
    client_config.set_disable_active_migration(true);
    client_config.verify_peer(false);

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();

    let client_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), base_port);
    let socket = tokio::net::UdpSocket::bind(client_addr).await.unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    if active {
        // Supply a second SCID to the server to facilitate active migration
        let extra_scid = SimpleConnectionIdGenerator.new_connection_id();
        conn.new_scid(&extra_scid, 0xAABBCCDDEEFF0123454678, false)
            .unwrap();
    }

    // One deadline bounds the whole handshake, including retransmissions.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !conn.is_established() {
        emit_flight(&socket, &mut conn, deadline).await;
        process_flight(&socket, client_addr, &mut conn, deadline).await;
    }

    // Create a new HTTP/3 connection once the QUIC connection is established.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    // The echo body exceeds the client's initial 1500-byte flow-control
    // window. Completing it must receive multiple flights and flush new credit.
    let request_path = format!("/{}", "x".repeat(2048));
    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", request_path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];

    // Client sends first request on the initial path.
    let stream_id = h3_conn.send_request(&mut conn, &req, true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    emit_flight(&socket, &mut conn, deadline).await;
    let (got_headers, finished, body, flights) = process_h3_events(
        &socket,
        client_addr,
        &mut h3_conn,
        &mut conn,
        stream_id,
        deadline,
    )
    .await;
    assert_eq!((got_headers, finished), (true, true));
    assert_eq!(body, format!("{stream_id},GET {request_path}|").as_bytes());
    assert!(flights > 1, "response must span multiple network flights");

    // Client migrates to new address.
    let migrated_addr = SocketAddr::new(client_addr.ip(), base_port + 1);
    let migrated_socket =
        tokio::net::UdpSocket::bind(migrated_addr).await.unwrap();

    let client_addr = if active {
        // We actively switch the connection to `migrated_addr` and report that
        // address for all packets we receive from now on.
        conn.migrate_source(migrated_addr)
            .expect("active migration should succeed");
        migrated_addr
    } else {
        // Keep the original client address to emulate an unrecognized path
        // change, such as NAT rebinding.
        client_addr
    };

    // Client sends second request on the new address.
    let stream_id = h3_conn.send_request(&mut conn, &req, true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    emit_flight(&migrated_socket, &mut conn, deadline).await;

    let stats = conn.stats();
    assert_eq!(stats.path_challenge_rx_count, 0);

    process_flight(&migrated_socket, client_addr, &mut conn, deadline).await;

    let stats = conn.stats();
    assert_eq!(stats.path_challenge_rx_count, 1);

    // Client responds to PATH_CHALLENGE.
    emit_flight(&migrated_socket, &mut conn, deadline).await;

    // Receive the complete second response even when it spans several flights.
    let (got_headers, finished, body, _) = process_h3_events(
        &migrated_socket,
        client_addr,
        &mut h3_conn,
        &mut conn,
        stream_id,
        deadline,
    )
    .await;
    assert_eq!((got_headers, finished), (true, true));
    assert_eq!(body, format!("{stream_id},GET {request_path}|").as_bytes());

    (hook.path_events(), server_addr, migrated_addr)
}

async fn emit_flight(
    socket: &tokio::net::UdpSocket, conn: &mut quiche::Connection,
    deadline: Instant,
) {
    assert!(
        Instant::now() < deadline,
        "migration flight deadline expired"
    );
    let flight = match quiche::test_utils::emit_flight(conn) {
        Ok(v) => v,

        Err(quiche::Error::Done) => return,

        Err(e) => panic!("failed to emit flight: {e:?}"),
    };

    for p in flight {
        // We avoid using the `from` field here on purpose, as in case of
        // passive migration the client might be unaware that their address
        // changed.
        timeout_at(deadline, socket.send_to(&p.0, p.1.to))
            .await
            .expect("migration flight send timed out")
            .unwrap();
    }
}

async fn process_flight(
    socket: &tokio::net::UdpSocket, client_addr: std::net::SocketAddr,
    conn: &mut quiche::Connection, deadline: Instant,
) {
    let mut buf = [0; 65535];

    loop {
        assert!(
            Instant::now() < deadline,
            "migration flight receive timed out"
        );
        assert!(
            !conn.is_closed(),
            "QUIC connection closed before the response"
        );
        let transport_deadline = conn
            .timeout_instant()
            .map(Instant::from_std)
            .unwrap_or(deadline)
            .min(deadline);
        match timeout_at(transport_deadline, socket.readable()).await {
            Ok(result) => result.unwrap(),
            Err(_) => {
                assert!(
                    Instant::now() < deadline,
                    "migration flight receive timed out"
                );
                conn.on_timeout();
                emit_flight(socket, conn, deadline).await;
                continue;
            },
        }

        let mut received = false;
        loop {
            let (len, from) = match socket.try_recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("failed to receive packets: {e:?}"),
            };

            // Preserve the original local address during passive migration to
            // emulate a client that cannot observe its NAT rebinding.
            let recv_info = quiche::RecvInfo {
                to: client_addr,
                from,
            };

            conn.recv(&mut buf[..len], recv_info).unwrap();
            received = true;
        }
        if received {
            return;
        }
    }
}

async fn process_h3_events(
    socket: &tokio::net::UdpSocket, client_addr: SocketAddr,
    h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection,
    expected_stream_id: u64, deadline: Instant,
) -> (bool, bool, Vec<u8>, usize) {
    let mut buf = [0; 65535];
    let mut got_headers = false;
    let mut body = Vec::new();
    let mut flights = 0;

    loop {
        assert!(Instant::now() < deadline, "HTTP/3 response timed out");
        match h3_conn.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { .. })) => {
                assert_eq!(stream_id, expected_stream_id);
                got_headers = true;
            },

            Ok((stream_id, quiche::h3::Event::Data)) => {
                assert_eq!(stream_id, expected_stream_id);
                loop {
                    match h3_conn.recv_body(conn, stream_id, &mut buf) {
                        Ok(len) => body.extend_from_slice(&buf[..len]),
                        Err(quiche::h3::Error::Done) => break,
                        Err(error) =>
                            panic!("failed to receive HTTP/3 body: {error:?}"),
                    }
                }
            },

            Ok((stream_id, quiche::h3::Event::Finished)) => {
                assert_eq!(stream_id, expected_stream_id);
                return (got_headers, true, body, flights);
            },

            Err(quiche::h3::Error::Done) => {
                // Incomplete responses need more network input. Flush ACKs and
                // the receive credit released while draining the current body.
                emit_flight(socket, conn, deadline).await;
                process_flight(socket, client_addr, conn, deadline).await;
                flights += 1;
            },

            Err(error) => panic!("failed to poll HTTP/3 response: {error:?}"),
            Ok((_, event)) =>
                panic!("unexpected HTTP/3 response event: {event:?}"),
        }
    }
}

async fn send_tokio_quiche_request(
    controller: &mut ClientH3Controller, request_id: u64,
) {
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id,
            headers: h3i_fixtures::default_headers(),
            body_writer: None,
        })
        .unwrap();

    let mut stream_id = None;

    loop {
        let event = timeout(
            Duration::from_secs(5),
            controller.event_receiver_mut().recv(),
        )
        .await
        .expect("request event timed out")
        .expect("client event stream closed");

        match event {
            ClientH3Event::NewOutboundRequest {
                stream_id: id,
                request_id: id_request_id,
            } if id_request_id == request_id => stream_id = Some(id),

            ClientH3Event::Core(H3Event::IncomingHeaders(incoming_headers))
                if stream_id == Some(incoming_headers.stream_id) =>
            {
                assert!(incoming_headers.headers.iter().any(|header| {
                    header.name() == b":status" && header.value() == b"200"
                }));

                let read_fin = incoming_headers.read_fin;
                let mut recv = incoming_headers.recv;
                if !read_fin {
                    loop {
                        let frame = timeout(Duration::from_secs(5), recv.recv())
                            .await
                            .expect("response body timed out")
                            .expect("response body stream closed");

                        match frame {
                            InboundFrame::Body(_, true) => break,
                            InboundFrame::Body(_, false) => {},
                            InboundFrame::Datagram(_) => unreachable!(),
                        }
                    }
                }

                return;
            },

            ClientH3Event::Core(H3Event::ConnectionError(err)) =>
                panic!("connection error while waiting for response: {err:?}"),

            ClientH3Event::Core(H3Event::ConnectionShutdown(err)) =>
                panic!("connection shutdown while waiting for response: {err:?}"),

            _ => {},
        }
    }
}
