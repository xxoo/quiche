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

//! `async`-ified QUIC connections powered by [quiche].
//!
//! Hooking up a [quiche::Connection] to [tokio]'s executor and IO primitives
//! requires an [`ApplicationOverQuic`] to control the connection. The
//! application exposes a small number of callbacks which are executed whenever
//! there is work to do with the connection.
//!
//! The primary entrypoints to set up a connection are [`listen`][listen] for
//! servers and [`connect`] for clients.
//! [`listen_with_capabilities`](crate::listen_with_capabilities)
//! and [`connect_with_config`] exist for scenarios that require more in-depth
//! configuration. Lastly, the [`raw`] submodule allows users to take full
//! control over connection creation and its ingress path.
//!
//! # QUIC Connection Internals
//!
//! ![QUIC Worker Setup](https://github.com/cloudflare/quiche/blob/master/tokio-quiche/docs/worker.png?raw=true)
//!
//! *Note: Internal details are subject to change between minor versions.*
//!
//! tokio-quiche conceptually separates a network socket into a `recv` half and
//! a `send` half. The `recv` half can only sensibly be used by one async task
//! at a time, while many tasks can `send` packets on the socket concurrently.
//! Thus, we spawn a dedicated `InboundPacketRouter` task for each socket which
//! becomes the sole owner of the socket's `recv` half. It decodes the QUIC
//! header in each packet, looks up the destination connection ID (DCID), and
//! forwards the packet to the connection's `IoWorker` task.
//!
//! If the packet initiates a new connection, it is passed to an
//! `InitialPacketHandler` with logic for either the client- or server-side
//! connection setup. The purple `ConnectionAcceptor` depicted above is the
//! server-side implementation. It optionally validates the client's IP
//! address with a `RETRY` packet before packaging the nascent connection into
//! an [`InitialQuicConnection`][iqc] and sending it to the
//! [`QuicConnectionStream`] returned by [`listen`][listen].
//!
//! At this point the caller of [`listen`][listen] has control of the
//! [`InitialQuicConnection`][iqc] (`IQC`). Now an `IoWorker` task needs to be
//! spawned to continue driving the connection. This is possible with
//! `IQC::handshake` or `IQC::start` (see the [`InitialQuicConnection`][iqc]
//! docs). Client-side connections use the same infrastructure (except for the
//! `InitialPacketHandler`), but [`connect`] immediately consumes the
//! [`QuicConnectionStream`] and calls `IQC::start`.
//!
//! `IoWorker` is responsible for feeding inbound packets into the underlying
//! [`quiche::Connection`], executing the [`ApplicationOverQuic`] callbacks, and
//! flushing outbound packets to the network via the socket's shared `send`
//! half. It loops through these operations in the order shown above, yielding
//! only when sending packets and on `wait_for_data` calls. New inbound packets
//! or a timeout can also restart the loop while `wait_for_data` is pending.
//! This continues until the connection is closed or the [`ApplicationOverQuic`]
//! returns an error.
//!
//! [listen]: crate::listen
//! [iqc]: crate::InitialQuicConnection

use std::sync::Arc;
use std::time::Duration;

use datagram_socket::DatagramSocketRecv;
use datagram_socket::DatagramSocketSend;
use foundations::telemetry::log;
use octets::Octets;
use qlog::writer::make_qlog_writer_from_path;
use qlog::writer::qlog_file_name;

use crate::http3::settings::Http3Settings;
use crate::metrics::DefaultMetrics;
use crate::metrics::Metrics;
use crate::settings::Config;
use crate::settings::ZeroRttStream;
use crate::socket::QuicListener;
use crate::socket::Socket;
use crate::ClientH3Controller;
use crate::ClientH3Driver;
use crate::ConnectionParams;
use crate::QuicConnectionStream;
use crate::QuicResult;
use crate::QuicResultExt;

mod addr_validation_token;
pub(crate) mod connection;
mod hooks;
mod io;
pub mod raw;
mod router;

use self::connection::ApplicationOverQuic;
use self::connection::ConnectionIdGenerator as _;
use self::connection::QuicConnection;
use self::router::acceptor::ConnectionAcceptor;
use self::router::acceptor::ConnectionAcceptorConfig;
use self::router::connector::ClientConnector;
use self::router::InboundPacketRouter;

pub use self::connection::ConnectionShutdownBehaviour;
pub use self::connection::HandshakeError;
pub use self::connection::HandshakeInfo;
pub use self::connection::Incoming;
pub use self::connection::QuicCommand;
pub use self::connection::QuicConnectionStats;
pub use self::connection::SimpleConnectionIdGenerator;
pub use self::hooks::ConnectionHook;

/// Alias of [quiche::Connection] used internally by the crate.
pub type QuicheConnection = quiche::Connection<crate::buf_factory::BufFactory>;

/// Connects to an HTTP/3 server using `socket` and the default client
/// configuration.
///
/// This function always uses the [`ApplicationOverQuic`] provided in
/// [`http3::driver`](crate::http3::driver) and returns a corresponding
/// [ClientH3Controller]. To specify a different implementation or customize the
/// configuration, use [`connect_with_config`].
///
/// # Note
/// tokio-quiche currently only supports one client connection per socket.
/// Sharing a socket among multiple connections will lead to lost packets as
/// both connections try to read from the shared socket.
pub async fn connect<Tx, Rx, S>(
    socket: S, host: Option<&str>,
) -> QuicResult<(QuicConnection, ClientH3Controller)>
where
    Tx: DatagramSocketSend + Send + 'static,
    Rx: DatagramSocketRecv + Unpin + 'static,
    S: TryInto<Socket<Tx, Rx>>,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    // Don't apply_max_capabilities(): some NICs don't support GSO
    let socket: Socket<Tx, Rx> = socket.try_into()?;

    let (h3_driver, h3_controller) =
        ClientH3Driver::new(Http3Settings::default());
    let mut params = ConnectionParams::default();
    params.settings.max_idle_timeout = Some(Duration::from_secs(30));

    Ok((
        connect_with_config(socket, host, &params, h3_driver).await?,
        h3_controller,
    ))
}

/// Connects to a QUIC server using `socket` and the provided
/// [`ApplicationOverQuic`].
///
/// When the future resolves, the connection has completed its handshake and
/// `app` is running in the worker task. In case the handshake failed, we close
/// the connection automatically and the future will resolve with an error.
///
/// # Note
/// tokio-quiche currently only supports one client connection per socket.
/// Sharing a socket among multiple connections will lead to lost packets as
/// both connections try to read from the shared socket.
pub async fn connect_with_config<Tx, Rx, App>(
    socket: Socket<Tx, Rx>, host: Option<&str>, params: &ConnectionParams<'_>,
    app: App,
) -> QuicResult<QuicConnection>
where
    Tx: DatagramSocketSend + Send + 'static,
    Rx: DatagramSocketRecv + Unpin + 'static,
    App: ApplicationOverQuic,
{
    if !params.zero_rtt_dgrams.is_empty() || !params.zero_rtt_streams.is_empty() {
        if params.session.is_none() {
            return Err("0-RTT data requires a resumption session".into());
        }

        if !params.settings.enable_early_data {
            return Err("0-RTT data requires early data to be enabled".into());
        }
    }

    let mut client_config = Config::new(params, socket.capabilities)?;
    let scid = SimpleConnectionIdGenerator.new_connection_id();

    #[cfg(feature = "custom-client-dcid")]
    let mut quiche_conn = if let Some(dcid) = &params.dcid {
        quiche::connect_with_dcid_and_buffer_factory(
            host,
            &scid,
            dcid,
            socket.local_addr,
            socket.peer_addr,
            client_config.as_mut(),
        )?
    } else {
        quiche::connect_with_buffer_factory(
            host,
            &scid,
            socket.local_addr,
            socket.peer_addr,
            client_config.as_mut(),
        )?
    };

    #[cfg(not(feature = "custom-client-dcid"))]
    let mut quiche_conn = quiche::connect_with_buffer_factory(
        host,
        &scid,
        socket.local_addr,
        socket.peer_addr,
        client_config.as_mut(),
    )?;

    #[cfg(feature = "custom-client-dcid")]
    log::info!("created unestablished quiche::Connection"; "scid" => ?scid, "provided_dcid" => ?params.dcid);
    #[cfg(not(feature = "custom-client-dcid"))]
    log::info!("created unestablished quiche::Connection"; "scid" => ?scid);

    if let Some(session) = &params.session {
        quiche_conn.set_session(session).map_err(|error| {
            log::error!("application provided an invalid session"; "error"=>?error);
            quiche::Error::CryptoFail
        })?;
    }

    if !params.zero_rtt_streams.is_empty() {
        let session = params
            .session
            .as_deref()
            .ok_or("0-RTT STREAMs require a resumption session")?;
        let limits = zero_rtt_stream_limits_from_session(session)?;
        validate_zero_rtt_streams(&params.zero_rtt_streams, limits)?;
    }

    // Set the qlog writer here instead of in the `ClientConnector` to avoid
    // missing logs from early in the connection
    if let Some(qlog_dir) = &client_config.qlog_dir {
        log::info!("setting up qlogs"; "qlog_dir"=>qlog_dir);
        let id = format!("{:?}", &scid);
        let path = std::path::Path::new(qlog_dir)
            .join(qlog_file_name(&id, client_config.qlog_compression));
        if let Ok(writer) =
            make_qlog_writer_from_path(&path, client_config.qlog_compression)
        {
            quiche_conn.set_qlog(
                writer,
                "tokio-quiche qlog".to_string(),
                format!("tokio-quiche qlog id={id}"),
            );
        }
    }

    // Set the keylog file here for the same reason
    if let Some(keylog_file) = &client_config.keylog_file {
        log::info!("setting up keylog file");
        if let Ok(keylog_clone) = keylog_file.try_clone() {
            quiche_conn.set_keylog(Box::new(keylog_clone));
        }
    }

    let socket_tx = Arc::new(socket.send);
    let socket_rx = socket.recv;

    let (router, mut quic_connection_stream) = InboundPacketRouter::new(
        client_config,
        Arc::clone(&socket_tx),
        socket_rx,
        socket.local_addr,
        ClientConnector::new(
            socket_tx,
            quiche_conn,
            params.zero_rtt_dgrams.clone(),
            params.zero_rtt_streams.clone(),
        ),
        DefaultMetrics,
    );

    // drive the packet router:
    tokio::spawn(async move {
        match router.await {
            Ok(()) => log::debug!("incoming packet router finished"),
            Err(error) => {
                log::error!("incoming packet router failed"; "error"=>error)
            },
        }
    });

    Ok(quic_connection_stream
        .recv()
        .await
        .ok_or("unable to establish connection")??
        .start(app))
}

#[derive(Clone, Copy, Debug, Default)]
struct ZeroRttStreamLimits {
    initial_max_data: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_streams_bidi: u64,
}

fn zero_rtt_stream_limits_from_session(
    session: &[u8],
) -> QuicResult<ZeroRttStreamLimits> {
    const INITIAL_MAX_DATA: u64 = 0x0004;
    const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x0006;
    const INITIAL_MAX_STREAMS_BIDI: u64 = 0x0008;

    let mut session = Octets::with_slice(session);
    let session_len = usize::try_from(session.get_u64()?)
        .map_err(|_| "0-RTT session data is too large")?;
    let _ = session.get_bytes(session_len)?;

    let raw_params_len = usize::try_from(session.get_u64()?)
        .map_err(|_| "0-RTT session transport parameters are too large")?;
    let mut raw_params = session.get_bytes(raw_params_len)?;
    let mut limits = ZeroRttStreamLimits::default();

    while raw_params.cap() > 0 {
        let id = raw_params.get_varint()?;
        let len = usize::try_from(raw_params.get_varint()?)
            .map_err(|_| "0-RTT session transport parameter is too large")?;
        let mut value = raw_params.get_bytes(len)?;

        match id {
            INITIAL_MAX_DATA => {
                limits.initial_max_data = value.get_varint()?;
            },

            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                limits.initial_max_stream_data_bidi_remote =
                    value.get_varint()?;
            },

            INITIAL_MAX_STREAMS_BIDI => {
                limits.initial_max_streams_bidi = value.get_varint()?;
            },

            _ => (),
        }
    }

    Ok(limits)
}

fn validate_zero_rtt_streams(
    streams: &[ZeroRttStream], limits: ZeroRttStreamLimits,
) -> QuicResult<()> {
    let stream_count = u64::try_from(streams.len())
        .map_err(|_| "too many 0-RTT STREAMs configured")?;

    if stream_count > limits.initial_max_streams_bidi {
        return Err(format!(
            "0-RTT STREAM count {stream_count} exceeds peer bidirectional stream limit {}",
            limits.initial_max_streams_bidi
        )
        .into());
    }

    let mut total_stream_data = 0_u64;

    for (idx, stream) in streams.iter().enumerate() {
        let stream_id = ConnectionParams::zero_rtt_stream_id(idx)
            .ok_or("too many 0-RTT STREAMs configured")?;
        let len = u64::try_from(stream.data.len()).map_err(|_| {
            format!("0-RTT STREAM {stream_id} payload is too large")
        })?;

        if len > limits.initial_max_stream_data_bidi_remote {
            return Err(format!(
                "0-RTT STREAM {stream_id} payload length {len} exceeds peer stream data limit {}",
                limits.initial_max_stream_data_bidi_remote
            )
            .into());
        }

        total_stream_data = total_stream_data.checked_add(len).ok_or(
            "0-RTT STREAM payload lengths exceed the connection data limit",
        )?;

        if total_stream_data > limits.initial_max_data {
            return Err(format!(
                "0-RTT STREAM payload length total {total_stream_data} exceeds peer connection data limit {}",
                limits.initial_max_data
            )
            .into());
        }
    }

    Ok(())
}

pub(crate) fn start_listener<M>(
    socket: QuicListener, params: &ConnectionParams, metrics: M,
) -> std::io::Result<QuicConnectionStream<M>>
where
    M: Metrics,
{
    #[cfg(unix)]
    assert!(
        datagram_socket::is_nonblocking(&socket).unwrap_or_default(),
        "O_NONBLOCK should be set for the listening socket"
    );

    let config = Config::new(params, socket.capabilities).into_io()?;

    let local_addr = socket.socket.local_addr()?;
    let socket_tx = Arc::new(socket.socket);
    let socket_rx = Arc::clone(&socket_tx);

    let acceptor = ConnectionAcceptor::new(
        ConnectionAcceptorConfig {
            disable_client_ip_validation: config.disable_client_ip_validation,
            qlog_dir: config.qlog_dir.clone(),
            qlog_compression: config.qlog_compression,
            keylog_file: config
                .keylog_file
                .as_ref()
                .and_then(|f| f.try_clone().ok()),
            #[cfg(target_os = "linux")]
            with_pktinfo: if local_addr.is_ipv4() {
                config.has_ippktinfo
            } else {
                config.has_ipv6pktinfo
            },
        },
        Arc::clone(&socket_tx),
        Default::default(),
        socket.cid_generator,
        metrics.clone(),
    );

    let (socket_driver, accept_stream) = InboundPacketRouter::new(
        config,
        socket_tx,
        socket_rx,
        local_addr,
        acceptor,
        metrics.clone(),
    );

    crate::metrics::tokio_task::spawn("quic_udp_listener", metrics, async move {
        match socket_driver.await {
            Ok(()) => log::trace!("incoming packet router finished"),
            Err(error) => {
                log::error!("incoming packet router failed"; "error"=>error)
            },
        }
    });
    Ok(QuicConnectionStream::new(accept_stream))
}
