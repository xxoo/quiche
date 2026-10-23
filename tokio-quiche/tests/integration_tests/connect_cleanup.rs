// Copyright (C) 2026, Cloudflare, Inc.
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

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::sleep;
use tokio::time::timeout;
use tokio_quiche::http3::driver::ClientH3Driver;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::connect_migratable_with_config;
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::socket::Socket;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicConnection;
use tokio_quiche::QuicResult;

async fn connect_to_silent_peer(
    socket: UdpSocket, migratable: bool,
) -> QuicResult<QuicConnection> {
    let mut params = ConnectionParams::default();
    params.settings.verify_peer = false;
    params.settings.max_idle_timeout = Some(Duration::from_millis(100));
    let (driver, _controller) = ClientH3Driver::new(Http3Settings::default());

    if migratable {
        connect_migratable_with_config(socket, Some("localhost"), &params, driver)
            .await
    } else {
        connect_with_config(
            Socket::try_from(socket).unwrap(),
            Some("localhost"),
            &params,
            driver,
        )
        .await
    }
}

async fn assert_socket_released(addr: SocketAddr) {
    // With time paused, this cannot wait for a subsequent QUIC timeout to
    // accidentally wake the router. The peer also sends no packets.
    timeout(Duration::from_millis(100), async {
        loop {
            match std::net::UdpSocket::bind(addr) {
                Ok(_) => return,
                Err(error) if error.kind() == ErrorKind::AddrInUse =>
                    sleep(Duration::from_millis(1)).await,
                Err(error) => panic!("cannot rebind released socket: {error}"),
            }
        }
    })
    .await
    .expect("the idle packet router retained its UDP socket");
}

#[rstest::rstest]
#[tokio::test]
async fn connect_timeout_releases_socket(
    #[values(false, true)] migratable: bool,
) {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(peer.local_addr().unwrap()).await.unwrap();
    let local_addr = socket.local_addr().unwrap();

    let error = timeout(
        Duration::from_secs(8),
        connect_to_silent_peer(socket, migratable),
    )
    .await
    .expect("the transport's own timeout must complete")
    .err()
    .expect("a silent peer cannot complete a handshake");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        ErrorKind::TimedOut
    );

    tokio::time::pause();
    assert_socket_released(local_addr).await;
}

#[rstest::rstest]
#[tokio::test]
async fn cancelled_connect_releases_socket(
    #[values(false, true)] migratable: bool,
) {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(peer.local_addr().unwrap()).await.unwrap();
    let local_addr = socket.local_addr().unwrap();
    let connect = tokio::spawn(connect_to_silent_peer(socket, migratable));

    // Wait until the detached router has sent the Initial and is awaiting a
    // reply before cancelling its caller.
    timeout(Duration::from_secs(5), peer.recv(&mut [0; 1500]))
        .await
        .unwrap()
        .unwrap();
    tokio::time::pause();
    connect.abort();
    assert!(connect
        .await
        .err()
        .expect("connect was cancelled")
        .is_cancelled());
    assert_socket_released(local_addr).await;
}

#[tokio::test]
async fn dropped_idle_listener_releases_socket() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_addr = socket.local_addr().unwrap();
    let incoming = tokio_quiche::listen(
        [socket],
        ConnectionParams::default(),
        DefaultMetrics,
    )
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::pause();
    drop(incoming);
    assert_socket_released(local_addr).await;
}
