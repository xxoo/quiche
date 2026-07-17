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

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;
#[cfg(feature = "perf-quic-listener-metrics")]
use std::time::SystemTime;

use super::connection_stage::Close;
use super::connection_stage::ConnectionStage;
use super::connection_stage::ConnectionStageContext;
use super::connection_stage::Handshake;
use super::connection_stage::RunningApplication;
use super::gso::*;
use super::utilization_estimator::BandwidthReporter;

use crate::metrics::labels;
use crate::metrics::Metrics;
use crate::quic::connection::ApplicationOverQuic;
use crate::quic::connection::ClientMigrationOutcome;
use crate::quic::connection::ClientMigrationRequest;
use crate::quic::connection::ConnectionEndpointState;
use crate::quic::connection::HandshakeError;
use crate::quic::connection::Incoming;
use crate::quic::connection::QuicConnectionStats;
use crate::quic::connection::RouteCleanupGuard;
use crate::quic::connection::SharedConnectionIdGenerator;
use crate::quic::hooks::peer_ip_matches;
use crate::quic::router::ConnectionMapCommand;
use crate::quic::QuicheConnection;
use crate::socket::MigratableUdpSocket;
use crate::BoxError;
use crate::QuicResult;

use boring::ssl::SslRef;
use datagram_socket::DatagramSocketSend;
use datagram_socket::DatagramSocketSendExt;
use datagram_socket::MaybeConnectedSocket;
use datagram_socket::QuicAuditStats;
use foundations::telemetry::log;
use quiche::ConnectionId;
use quiche::Error as QuicheError;
use quiche::SendInfo;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time;

// Number of incoming packets to be buffered in the incoming channel.
pub(crate) const INCOMING_QUEUE_SIZE: usize = 2048;

// Check if there are any incoming packets while sending data every this number
// of sent packets
pub(crate) const CHECK_INCOMING_QUEUE_RATIO: usize = INCOMING_QUEUE_SIZE / 16;

const RELEASE_TIMER_THRESHOLD: Duration = Duration::from_micros(250);

/// Stop queuing GSO packets, if packet size is below this threshold.
const GSO_THRESHOLD: usize = 1_000;

pub struct WriterConfig {
    pub pending_cid: Option<ConnectionId<'static>>,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub with_gso: bool,
    pub pacing_offload: bool,
    pub with_pktinfo: bool,
    pub fixed_peer_ip: Option<std::net::IpAddr>,
}

#[derive(Default)]
pub(crate) struct WriteState {
    conn_established: bool,
    bytes_written: usize,
    segment_size: usize,
    num_pkts: usize,
    tx_time: Option<Instant>,
    has_pending_data: bool,
    // If pacer schedules packets too far into the future, we want to pause
    // sending, until the future arrives
    next_release_time: Option<Instant>,
    // The selected source and destination addresses for the current write
    // cycle.
    selected_path: Option<(SocketAddr, SocketAddr)>,
    // Iterator over the network paths that haven't been flushed yet.
    pending_paths: quiche::SocketAddrIter,
}

pub(crate) struct IoWorkerParams<Tx, M> {
    pub(crate) socket: MaybeConnectedSocket<Tx>,
    pub(crate) shutdown_tx: mpsc::Sender<()>,
    pub(crate) cfg: WriterConfig,
    pub(crate) audit_log_stats: Arc<QuicAuditStats>,
    pub(crate) write_state: WriteState,
    pub(crate) conn_map_cmd_tx: mpsc::UnboundedSender<ConnectionMapCommand>,
    pub(crate) route_cleanup: Option<RouteCleanupGuard>,
    pub(crate) cid_generator: Option<SharedConnectionIdGenerator>,
    pub(crate) client_migration_rx:
        Option<mpsc::UnboundedReceiver<ClientMigrationRequest>>,
    pub(crate) client_migration_socket: Option<MigratableUdpSocket>,
    pub(crate) endpoint_state: ConnectionEndpointState,
    #[cfg(feature = "perf-quic-listener-metrics")]
    pub(crate) init_rx_time: Option<SystemTime>,
    pub(crate) metrics: M,
}

pub(crate) struct IoWorker<Tx, M, S> {
    socket: MaybeConnectedSocket<Tx>,
    /// A field that signals to the listener task that the connection has gone
    /// away (nothing is sent here, listener task just detects the sender
    /// has dropped)
    shutdown_tx: mpsc::Sender<()>,
    cfg: WriterConfig,
    audit_log_stats: Arc<QuicAuditStats>,
    write_state: WriteState,
    conn_map_cmd_tx: mpsc::UnboundedSender<ConnectionMapCommand>,
    route_cleanup: Option<RouteCleanupGuard>,
    cid_generator: Option<SharedConnectionIdGenerator>,
    client_migration_rx: Option<mpsc::UnboundedReceiver<ClientMigrationRequest>>,
    client_migration_socket: Option<MigratableUdpSocket>,
    endpoint_state: ConnectionEndpointState,
    #[cfg(feature = "perf-quic-listener-metrics")]
    init_rx_time: Option<SystemTime>,
    metrics: M,
    conn_stage: S,
    bw_estimator: BandwidthReporter,
}

async fn recv_client_migration(
    rx: &mut Option<mpsc::UnboundedReceiver<ClientMigrationRequest>>,
) -> Option<ClientMigrationRequest> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn recv_incoming(
    fixed_peer_ip: Option<std::net::IpAddr>, qconn: &mut QuicheConnection,
    mut pkt: Incoming,
) -> QuicResult<bool> {
    if !peer_ip_matches(fixed_peer_ip, pkt.peer_addr.ip()) {
        return Ok(false);
    }

    let recv_info = quiche::RecvInfo {
        from: pkt.peer_addr,
        to: pkt.local_addr,
    };

    if let Some(gro) = pkt.gro {
        for dgram in pkt.buf.chunks_mut(gro as usize) {
            qconn.recv(dgram, recv_info)?;
        }
    } else {
        qconn.recv(&mut pkt.buf, recv_info)?;
    }

    Ok(true)
}

impl<Tx, M, S> IoWorker<Tx, M, S>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
    S: ConnectionStage,
{
    pub(crate) fn new(params: IoWorkerParams<Tx, M>, conn_stage: S) -> Self {
        let bw_estimator =
            BandwidthReporter::new(params.metrics.utilized_bandwidth());

        log::trace!("Creating IoWorker with stage: {conn_stage:?}");

        Self {
            socket: params.socket,
            shutdown_tx: params.shutdown_tx,
            cfg: params.cfg,
            audit_log_stats: params.audit_log_stats,
            write_state: params.write_state,
            conn_map_cmd_tx: params.conn_map_cmd_tx,
            route_cleanup: params.route_cleanup,
            cid_generator: params.cid_generator,
            client_migration_rx: params.client_migration_rx,
            client_migration_socket: params.client_migration_socket,
            endpoint_state: params.endpoint_state,
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time: params.init_rx_time,
            metrics: params.metrics,
            conn_stage,
            bw_estimator,
        }
    }

    async fn fill_available_scids(&mut self, qconn: &mut QuicheConnection) {
        self.fill_available_scids_with(qconn, random_u128).await;
    }

    async fn fill_available_scids_with(
        &mut self, qconn: &mut QuicheConnection,
        mut next_reset_token: impl FnMut() -> u128,
    ) {
        if qconn.scids_left() == 0 {
            return;
        }
        let Some(cid_generator) = self.cid_generator.clone() else {
            return;
        };
        let Some(owner) = self
            .route_cleanup
            .as_ref()
            .map(|cleanup| cleanup.owner().clone())
        else {
            return;
        };

        let current_cid = qconn.source_id().into_owned();
        for _ in 0..qconn.scids_left() {
            // We don't emit stateless resets, so any unguessable value is fine
            let reset_token = next_reset_token();
            let new_cid = cid_generator.new_connection_id();
            let (result_tx, result_rx) = oneshot::channel();
            let newly_tracked =
                self.route_cleanup.as_mut().is_some_and(|route_cleanup| {
                    route_cleanup.track(new_cid.clone())
                });
            if !newly_tracked {
                // The generator repeated one of this owner's live CIDs.
                continue;
            }
            // Tracking before the asynchronous command makes cancellation
            // enqueue an owner-scoped unmap after the map command.
            if self
                .conn_map_cmd_tx
                .send(ConnectionMapCommand::MapCid {
                    owner: owner.clone(),
                    existing_cid: current_cid.clone(),
                    new_cid: new_cid.clone(),
                    result: result_tx,
                })
                .is_err()
            {
                if let Some(route_cleanup) = &mut self.route_cleanup {
                    route_cleanup.forget(&new_cid);
                }
                // The connection map is gone, so no new CID can be routed.
                return;
            }

            match result_rx.await {
                Ok(true) => {},
                Ok(false) => {
                    if let Some(route_cleanup) = &mut self.route_cleanup {
                        route_cleanup.forget(&new_cid);
                    }
                    continue;
                },
                Err(_) => {
                    // Router shutdown drops the entire map. No mapping remains
                    // to clean, and the CID was never added to quiche.
                    if let Some(route_cleanup) = &mut self.route_cleanup {
                        route_cleanup.forget(&new_cid);
                    }
                    return;
                },
            }

            if qconn.new_scid(&new_cid, reset_token, false).is_err() {
                // The route was confirmed first. Roll it back when quiche no
                // longer has capacity or rejects the generated CID.
                self.unmap_cid(new_cid);
                return;
            }
        }
    }

    fn unmap_cid(&mut self, cid: ConnectionId<'static>) {
        let owner = self
            .route_cleanup
            .as_ref()
            .map(|cleanup| cleanup.owner().clone());
        if let Some(route_cleanup) = &mut self.route_cleanup {
            route_cleanup.forget(&cid);
        }
        // If the connection map is gone, the ID is already "unmapped"
        let _ = self
            .conn_map_cmd_tx
            .send(ConnectionMapCommand::UnmapCid { cid, owner });
    }

    async fn refresh_connection_ids(&mut self, qconn: &mut QuicheConnection) {
        // Top up the connection's active CIDs
        self.fill_available_scids(qconn).await;

        // Remove retired CIDs from the ingress router
        while let Some(retired_cid) = qconn.retired_scid_next() {
            self.unmap_cid(retired_cid);
        }
    }

    fn handle_client_migration(
        &mut self, qconn: &mut QuicheConnection, request: ClientMigrationRequest,
    ) {
        let outcome = self.try_client_migration(
            qconn,
            request.socket,
            request.local_addr,
            request.peer_addr,
        );

        let _ = request.response.send(outcome);
    }

    fn try_client_migration(
        &mut self, qconn: &mut QuicheConnection, socket: tokio::net::UdpSocket,
        local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> QuicResult<ClientMigrationOutcome> {
        let Some(client_migration_socket) = &self.client_migration_socket else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "connection is not migratable",
            )
            .into());
        };

        if peer_addr != self.cfg.peer_addr {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "migrated UDP socket peer address {peer_addr} does not \
                     match connection peer address {}",
                    self.cfg.peer_addr
                ),
            )
            .into());
        }

        if !qconn.is_established() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "connection migration requires an established QUIC connection",
            )
            .into());
        }

        if qconn.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "connection is already closed",
            )
            .into());
        }

        if qconn
            .peer_transport_params()
            .is_some_and(|params| params.disable_active_migration)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "peer disabled active migration",
            )
            .into());
        }

        qconn
            .probe_path(local_addr, peer_addr)
            .map_err(|error| Box::new(error) as BoxError)?;
        qconn
            .migrate_source(local_addr)
            .map_err(|error| Box::new(error) as BoxError)?;

        let previous_local_addr =
            client_migration_socket.replace(socket, local_addr, peer_addr)?;
        self.cfg.local_addr = local_addr;
        self.endpoint_state.set_local_addr(local_addr);
        self.write_state.selected_path = None;
        self.write_state.pending_paths = quiche::SocketAddrIter::default();
        self.write_state.has_pending_data = true;

        Ok(ClientMigrationOutcome {
            previous_local_addr,
            local_addr,
            peer_addr,
        })
    }

    async fn work_loop<A: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection,
        ctx: &mut ConnectionStageContext<A>,
    ) -> QuicResult<()> {
        const DEFAULT_SLEEP: Duration = Duration::from_secs(60);
        let mut current_deadline: Option<Instant> = None;
        let mut client_migration_rx = self.client_migration_rx.take();
        let sleep = time::sleep(DEFAULT_SLEEP);
        tokio::pin!(sleep);

        loop {
            let now = Instant::now();

            self.write_state.has_pending_data = true;

            while self.write_state.has_pending_data {
                let mut packets_sent = 0;

                // Try to clear all received packets every so often, because
                // incoming packets contain acks, and because the
                // receive queue has a very limited size, once it is full incoming
                // packets get stalled indefinitely
                let mut did_recv = false;
                while let Some(pkt) = ctx
                    .in_pkt
                    .take()
                    .or_else(|| ctx.incoming_pkt_receiver.try_recv().ok())
                {
                    did_recv |= self.process_incoming(qconn, pkt)?;
                }

                self.conn_stage.on_read(did_recv, qconn, ctx)?;
                self.refresh_connection_ids(qconn).await;

                let can_release = match self.write_state.next_release_time {
                    None => true,
                    Some(next_release) =>
                        next_release
                            .checked_duration_since(now)
                            .unwrap_or_default() <
                            RELEASE_TIMER_THRESHOLD,
                };

                self.write_state.has_pending_data &= can_release;

                while self.write_state.has_pending_data &&
                    packets_sent < CHECK_INCOMING_QUEUE_RATIO
                {
                    self.gather_data_from_quiche_conn(qconn, ctx.buffer())?;

                    // Break if the connection is closed
                    if qconn.is_closed() {
                        self.client_migration_rx = client_migration_rx;
                        return Ok(());
                    }

                    let mut flush_operation_token =
                        TrackMidHandshakeFlush::new(self.metrics.clone());

                    self.flush_buffer_to_socket(ctx.buffer()).await;

                    flush_operation_token.mark_complete();

                    packets_sent += self.write_state.num_pkts;

                    if let ControlFlow::Break(reason) =
                        self.conn_stage.on_flush(qconn, ctx)
                    {
                        self.client_migration_rx = client_migration_rx;
                        return reason;
                    }
                }
            }

            self.bw_estimator.update(qconn, now);

            self.audit_log_stats
                .set_max_bandwidth(self.bw_estimator.max_bandwidth);
            self.audit_log_stats.set_max_loss_pct(
                (self.bw_estimator.max_loss_pct * 100_f32).round() as u8,
            );

            let new_deadline = min_of_some(
                qconn.timeout_instant(),
                self.write_state.next_release_time,
            );
            let new_deadline =
                min_of_some(new_deadline, self.conn_stage.wait_deadline());

            if new_deadline != current_deadline {
                current_deadline = new_deadline;

                sleep
                    .as_mut()
                    .reset(new_deadline.unwrap_or(now + DEFAULT_SLEEP).into());
            }

            let incoming_recv = &mut ctx.incoming_pkt_receiver;
            let application = &mut ctx.application;

            select! {
                biased;
                () = &mut sleep => {
                    // It's very important that we keep the timeout arm at the top of this loop so
                    // that we poll it every time we need to. Since this is a biased `select!`, if
                    // we put this behind another arm, we could theoretically starve the sleep arm
                    // and hang connections.
                    //
                    // See https://docs.rs/tokio/latest/tokio/macro.select.html#fairness for more
                    qconn.on_timeout();

                    self.write_state.next_release_time = None;
                    current_deadline = None;
                    sleep.as_mut().reset((now + DEFAULT_SLEEP).into());
                }
                Some(pkt) = incoming_recv.recv() => ctx.in_pkt = Some(pkt),
                Some(request) = recv_client_migration(&mut client_migration_rx),
                    if client_migration_rx.is_some() =>
                {
                    self.handle_client_migration(qconn, request);
                    self.write_state.next_release_time = None;
                    current_deadline = None;
                    sleep.as_mut().reset((now + DEFAULT_SLEEP).into());
                }
                directive = self.wait_for_data_or_handshake(qconn, application) => {
                    match directive? {
                        WaitForDataOrHandshakeDirective::Flush => {
                            self.flush_buffer_to_socket(application.buffer()).await;
                        }
                        WaitForDataOrHandshakeDirective::Noop => {}
                    }
                },
            };

            if let ControlFlow::Break(reason) = self.conn_stage.post_wait(qconn) {
                self.client_migration_rx = client_migration_rx;
                return reason;
            }
        }
    }

    #[cfg(feature = "perf-quic-listener-metrics")]
    fn measure_complete_handshake_time(&mut self) {
        if let Some(init_rx_time) = self.init_rx_time.take() {
            if let Ok(delta) = init_rx_time.elapsed() {
                self.metrics
                    .handshake_time_seconds(
                        labels::QuicHandshakeStage::HandshakeResponse,
                    )
                    .observe(delta.as_nanos() as u64);
            }
        }
    }

    fn gather_data_from_quiche_conn(
        &mut self, qconn: &mut QuicheConnection, send_buf: &mut [u8],
    ) -> QuicResult<usize> {
        let mut segment_size = None;
        let mut send_info = None;

        self.write_state.num_pkts = 0;
        self.write_state.bytes_written = 0;

        self.write_state.selected_path = None;

        let now = Instant::now();

        let send_buf = {
            let trunc = UDP_MAX_GSO_PACKET_SIZE.min(send_buf.len());
            &mut send_buf[..trunc]
        };

        #[cfg(feature = "gcongestion")]
        let gcongestion_enabled = true;

        #[cfg(not(feature = "gcongestion"))]
        let gcongestion_enabled = qconn.gcongestion_enabled().unwrap_or(false);

        let initial_release_decision = if gcongestion_enabled {
            let initial_release_decision = qconn
                .get_next_release_time()
                .filter(|_| self.pacing_enabled(qconn));

            if let Some(future_release_time) =
                initial_release_decision.as_ref().and_then(|v| v.time(now))
            {
                let max_into_fut = qconn.max_release_into_future();

                if future_release_time.duration_since(now) >= max_into_fut {
                    self.write_state.next_release_time =
                        Some(now + max_into_fut.mul_f32(0.8));
                    self.write_state.has_pending_data = false;
                    return Ok(0);
                }
            }

            initial_release_decision
        } else {
            None
        };

        let buffer_write_outcome = loop {
            let outcome = self.write_packet_to_buffer(
                qconn,
                send_buf,
                &mut send_info,
                segment_size,
            );

            let packet_size = match outcome {
                Ok(0) => break Ok(0),

                Ok(bytes_written) => bytes_written,

                Err(e) => break Err(e),
            };

            // Flush to network after generating a single packet when GSO
            // is disabled.
            if !self.cfg.with_gso {
                break outcome;
            }

            #[cfg(not(feature = "gcongestion"))]
            let max_send_size = if !gcongestion_enabled {
                // Only call qconn.send_quantum when !gcongestion_enabled.
                tune_max_send_size(
                    segment_size,
                    qconn.send_quantum(),
                    send_buf.len(),
                )
            } else {
                usize::MAX
            };

            #[cfg(feature = "gcongestion")]
            let max_send_size = usize::MAX;

            // If segment_size is known, update the maximum of
            // GSO sender buffer size to the multiple of
            // segment_size.
            let buffer_is_full = self.write_state.num_pkts ==
                UDP_MAX_SEGMENT_COUNT ||
                self.write_state.bytes_written >= max_send_size;

            if buffer_is_full {
                break outcome;
            }

            // Flush to network when the newly generated packet size is
            // different from previously written packet, as GSO needs packets
            // to have the same size, except for the last one in the buffer.
            // The last packet may be smaller than the previous size.
            match segment_size {
                Some(size)
                    if packet_size != size || packet_size < GSO_THRESHOLD =>
                    break outcome,
                None => segment_size = Some(packet_size),
                _ => (),
            }

            if gcongestion_enabled {
                // If the release time of next packet is different, or it can't be
                // part of a burst, start the next batch
                if let Some(initial_release_decision) = initial_release_decision {
                    match qconn.get_next_release_time() {
                        Some(release)
                            if release.can_burst() ||
                                release.time_eq(
                                    &initial_release_decision,
                                    now,
                                ) => {},
                        _ => break outcome,
                    }
                }
            }
        };

        let tx_time = if gcongestion_enabled {
            initial_release_decision
                .filter(|_| self.pacing_enabled(qconn))
                // Return the time from the release decision if release_decision.time > now, else None.
                .and_then(|v| v.time(now))
        } else {
            send_info
                .filter(|_| self.pacing_enabled(qconn))
                .map(|v| v.at)
        };

        self.write_state.conn_established = qconn.is_established();
        self.write_state.tx_time = tx_time;
        self.write_state.segment_size =
            segment_size.unwrap_or(self.write_state.bytes_written);

        if !gcongestion_enabled {
            if let Some(time) = tx_time {
                const DEFAULT_MAX_INTO_FUTURE: Duration =
                    Duration::from_millis(1);
                if time
                    .checked_duration_since(now)
                    .map(|d| d > DEFAULT_MAX_INTO_FUTURE)
                    .unwrap_or(false)
                {
                    self.write_state.next_release_time =
                        Some(now + DEFAULT_MAX_INTO_FUTURE.mul_f32(0.8));
                    self.write_state.has_pending_data = false;
                    return Ok(0);
                }
            }
        }

        buffer_write_outcome
    }

    /// Selects a network path, if none already selected.
    ///
    /// This will return the first path available in the write state's
    /// `pending_paths` iterator. If that is empty a new iterator will be
    /// created by querying quiche itself.
    ///
    /// Note that the connection's statically configured local address will be
    /// used to query quiche for available paths, so this can't handle multiple
    /// local addresses currently.
    fn select_path(
        &mut self, qconn: &QuicheConnection,
    ) -> Option<(SocketAddr, SocketAddr)> {
        if self.write_state.selected_path.is_some() {
            return self.write_state.selected_path;
        }

        let from = self.cfg.local_addr;

        // Initialize paths iterator.
        if self.write_state.pending_paths.len() == 0 {
            self.write_state.pending_paths = qconn.paths_iter(from);
        }

        let to = self.write_state.pending_paths.next()?;

        Some((from, to))
    }

    #[cfg(not(feature = "gcongestion"))]
    fn pacing_enabled(&self, qconn: &QuicheConnection) -> bool {
        self.cfg.pacing_offload && qconn.pacing_enabled()
    }

    #[cfg(feature = "gcongestion")]
    fn pacing_enabled(&self, _qconn: &QuicheConnection) -> bool {
        self.cfg.pacing_offload
    }

    fn write_packet_to_buffer(
        &mut self, qconn: &mut QuicheConnection, send_buf: &mut [u8],
        send_info: &mut Option<SendInfo>, segment_size: Option<usize>,
    ) -> QuicResult<usize> {
        let mut send_buf = &mut send_buf[self.write_state.bytes_written..];
        if send_buf.len() > segment_size.unwrap_or(usize::MAX) {
            // Never let the buffer be longer than segment size, for GSO to
            // function properly.
            send_buf = &mut send_buf[..segment_size.unwrap_or(usize::MAX)];
        }

        // On the first call to `select_path()` a path will be chosen based on
        // the local address the connection initially landed on. Once a path is
        // selected following calls to `select_path()` will return it, until it
        // is reset at the start of the next write cycle.
        //
        // The path is then passed to `send_on_path()` which will only generate
        // packets meant for that path, this way a single GSO buffer will only
        // contain packets that belong to the same network path, which is
        // required because the from/to addresses for each `sendmsg()` call
        // apply to the whole GSO buffer.
        let (from, to) = self.select_path(qconn).unzip();

        match qconn.send_on_path(send_buf, from, to) {
            Ok((packet_size, info)) => {
                let _ = send_info.get_or_insert(info);

                self.write_state.bytes_written += packet_size;
                self.write_state.num_pkts += 1;

                let from = send_info.as_ref().map(|info| info.from);
                let to = send_info.as_ref().map(|info| info.to);

                self.write_state.selected_path = from.zip(to);

                self.write_state.has_pending_data = true;

                Ok(packet_size)
            },

            Err(QuicheError::Done) => {
                // Flush the current buffer to network. If no other path needs
                // to be flushed to the network also yield the work loop task.
                //
                // Otherwise the write loop will start again and the next path
                // will be selected.
                let has_pending_paths = self.write_state.pending_paths.len() > 0;

                // Keep writing if there are paths left to try.
                self.write_state.has_pending_data = has_pending_paths;

                Ok(0)
            },

            Err(e) => {
                let error_code = if let Some(local_error) = qconn.local_error() {
                    local_error.error_code
                } else {
                    let internal_error_code =
                        quiche::WireErrorCode::InternalError as u64;
                    let _ = qconn.close(false, internal_error_code, &[]);

                    internal_error_code
                };

                self.audit_log_stats
                    .set_sent_conn_close_transport_error_code(error_code as i64);

                Err(Box::new(e))
            },
        }
    }

    async fn flush_buffer_to_socket(&mut self, send_buf: &[u8]) {
        if self.write_state.bytes_written > 0 {
            let current_send_buf = &send_buf[..self.write_state.bytes_written];

            let (from, to) = self.write_state.selected_path.unzip();

            let to = to.unwrap_or(self.cfg.peer_addr);
            let from = from.filter(|_| self.cfg.with_pktinfo);

            let send_res = if let (Some(udp_socket), true) =
                (self.socket.as_udp_socket(), self.cfg.with_gso)
            {
                // Only UDP supports GSO.
                send_to(
                    udp_socket,
                    to,
                    from,
                    current_send_buf,
                    self.write_state.segment_size,
                    self.write_state.tx_time,
                    self.metrics
                        .write_errors(labels::QuicWriteError::WouldBlock),
                    self.metrics.send_to_wouldblock_duration_s(),
                )
                .await
            } else {
                self.socket.send_to(current_send_buf, to).await
            };

            #[cfg(feature = "perf-quic-listener-metrics")]
            self.measure_complete_handshake_time();

            match send_res {
                Ok(n) =>
                    if n < self.write_state.bytes_written {
                        self.metrics
                            .write_errors(labels::QuicWriteError::Partial)
                            .inc();
                    },

                Err(_) => {
                    self.metrics.write_errors(labels::QuicWriteError::Err).inc();
                },
            }
        }
    }

    /// Process the incoming packet
    fn process_incoming(
        &mut self, qconn: &mut QuicheConnection, pkt: Incoming,
    ) -> QuicResult<bool> {
        recv_incoming(self.cfg.fixed_peer_ip, qconn, pkt)
    }

    // When a connection is established, process application data, if not the task
    // is probably polled following a wakeup from boring, so we check if quiche
    // has any handshake packets to send.
    //
    // TODO(erittenhouse): would be nice to decouple wait_for_data from the
    // application, but wait_for_quiche relies on IOW methods, so we can't write a
    // default implementation for ConnectionStage
    async fn wait_for_data_or_handshake<A: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection, quic_application: &mut A,
    ) -> QuicResult<WaitForDataOrHandshakeDirective> {
        if quic_application.should_act() {
            // Poll the application to make progress.
            //
            // Once the connection has been established (i.e. the handshake is
            // complete), we only poll the application.
            //
            // The exception is 0-RTT in TLS 1.3, where the full handshake is
            // still in progress but we have 0-RTT keys to process early data.
            // This means TLS callbacks might only be polled on the next timeout
            // or when a packet is received from the peer.
            quic_application.wait_for_data(qconn).await?;
            Ok(WaitForDataOrHandshakeDirective::Noop)
        } else {
            // Poll quiche to make progress on handshake callbacks.
            self.wait_for_quiche(qconn, quic_application.buffer())
                .await?;
            Ok(WaitForDataOrHandshakeDirective::Flush)
        }
    }

    /// Check if Quiche has any packets to send
    ///
    /// If yes: fills buffer and updates self.write_state.bytes_written
    /// If no: Poll::Pending
    ///
    /// # Example
    ///
    /// This function can be used, for example, to drive an asynchronous TLS
    /// handshake. Each call to `gather_data_from_quiche_conn` attempts to
    /// progress the handshake via a call to `quiche::Connection.send()` -
    /// once one of the `gather_data_from_quiche_conn()` calls writes to the
    /// send buffer, we signal to the caller which has to take care of flushing
    async fn wait_for_quiche(
        &mut self, qconn: &mut QuicheConnection, buffer: &mut [u8],
    ) -> QuicResult<()> {
        std::future::poll_fn(|_| {
            match self.gather_data_from_quiche_conn(qconn, buffer) {
                Ok(bytes_written) => {
                    // We need to avoid consecutive calls to gather(), which write
                    // data to the buffer, without a flush().
                    // If we don't avoid those consecutive calls, we end
                    // up overwriting data in the buffer or unnecessarily waiting
                    // for more calls to drive_handshake()
                    // before calling the handshake complete.
                    if bytes_written == 0 && self.write_state.bytes_written == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(()))
                    }
                },
                _ => Poll::Ready(Err(quiche::Error::TlsFail)),
            }
        })
        .await?;
        Ok(())
    }
}

/// Whether caller of [`wait_for_data_or_handshake`] is required to
/// call [`flush_buffer_to_socket`]
#[must_use]
enum WaitForDataOrHandshakeDirective {
    Noop,
    Flush,
}

pub struct Running<Tx, M, A> {
    pub(crate) params: IoWorkerParams<Tx, M>,
    pub(crate) context: ConnectionStageContext<A>,
    /// See [`QuicConnectionParams::quiche_conn`].
    pub(crate) qconn: Box<QuicheConnection>,
}

impl<Tx, M, A> Running<Tx, M, A> {
    pub fn ssl(&mut self) -> &mut SslRef {
        // Deref to pick `Connection::as_mut` over `Box::as_mut`.
        (*self.qconn).as_mut()
    }
}

pub(crate) struct Closing<Tx, M, A> {
    pub(crate) params: IoWorkerParams<Tx, M>,
    pub(crate) context: ConnectionStageContext<A>,
    pub(crate) work_loop_result: QuicResult<()>,
    /// See [`QuicConnectionParams::quiche_conn`].
    pub(crate) qconn: Box<QuicheConnection>,
}

pub enum RunningOrClosing<Tx, M, A> {
    Running(Running<Tx, M, A>),
    Closing(Closing<Tx, M, A>),
}

impl<Tx, M> IoWorker<Tx, M, Handshake>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn run<A>(
        mut self, mut qconn: Box<QuicheConnection>,
        mut ctx: ConnectionStageContext<A>,
    ) -> RunningOrClosing<Tx, M, A>
    where
        A: ApplicationOverQuic,
    {
        // This makes an assumption that the waker being set in ex_data is stable
        // across the active task's lifetime. Moving a future that encompasses an
        // async callback from this task across a channel, for example, will
        // cause issues as this waker will then be stale and attempt to
        // wake the wrong task.
        std::future::poll_fn(|cx| {
            // Deref to pick `Connection::as_mut` over `Box::as_mut`.
            let ssl = (*qconn).as_mut();
            ssl.set_task_waker(Some(cx.waker().clone()));

            Poll::Ready(())
        })
        .await;

        #[cfg(target_os = "linux")]
        if let Some(incoming) = ctx.in_pkt.as_mut() {
            self.audit_log_stats
                .set_initial_so_mark_data(incoming.so_mark_data.take());
        }

        let mut work_loop_result = self.work_loop(&mut qconn, &mut ctx).await;
        if work_loop_result.is_ok() && qconn.is_closed() {
            work_loop_result = Err(HandshakeError::ConnectionClosed.into());
        }

        if let Err(err) = &work_loop_result {
            self.metrics.failed_handshakes(err.into()).inc();

            return RunningOrClosing::Closing(Closing {
                params: self.into(),
                context: ctx,
                work_loop_result,
                qconn,
            });
        };

        match self.on_conn_established(&mut qconn, &mut ctx.application) {
            Ok(()) => RunningOrClosing::Running(Running {
                params: self.into(),
                context: ctx,
                qconn,
            }),
            Err(e) => {
                foundations::telemetry::log::warn!(
                    "Handshake stage on_connection_established failed"; "error"=>%e
                );

                RunningOrClosing::Closing(Closing {
                    params: self.into(),
                    context: ctx,
                    work_loop_result,
                    qconn,
                })
            },
        }
    }

    fn on_conn_established<App: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection, driver: &mut App,
    ) -> QuicResult<()> {
        // Only calculate the QUIC handshake duration and call the driver's
        // on_conn_established hook if this is the first time
        // is_established == true.
        if self.audit_log_stats.transport_handshake_duration_us() == -1 {
            self.conn_stage.handshake_info.set_elapsed();
            let handshake_info = &self.conn_stage.handshake_info;

            self.audit_log_stats
                .set_transport_handshake_duration(handshake_info.elapsed());

            driver.on_conn_established(qconn, handshake_info)?;
        }

        if let Some(cid) = self.cfg.pending_cid.take() {
            self.unmap_cid(cid);
        }

        Ok(())
    }
}

impl<Tx, M, S> From<IoWorker<Tx, M, S>> for IoWorkerParams<Tx, M> {
    fn from(value: IoWorker<Tx, M, S>) -> Self {
        Self {
            socket: value.socket,
            shutdown_tx: value.shutdown_tx,
            cfg: value.cfg,
            audit_log_stats: value.audit_log_stats,
            write_state: value.write_state,
            conn_map_cmd_tx: value.conn_map_cmd_tx,
            route_cleanup: value.route_cleanup,
            cid_generator: value.cid_generator,
            client_migration_rx: value.client_migration_rx,
            client_migration_socket: value.client_migration_socket,
            endpoint_state: value.endpoint_state,
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time: value.init_rx_time,
            metrics: value.metrics,
        }
    }
}

impl<Tx, M> IoWorker<Tx, M, RunningApplication>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn run<A: ApplicationOverQuic>(
        mut self, mut qconn: Box<QuicheConnection>,
        mut ctx: ConnectionStageContext<A>,
    ) -> Closing<Tx, M, A> {
        // Perform a single call to process_reads()/process_writes(),
        // unconditionally, to ensure that any application data (e.g.
        // STREAM frames or datagrams) processed by the Handshake
        // stage are properly passed to the application.
        if let Err(e) = self.conn_stage.on_read(true, &mut qconn, &mut ctx) {
            return Closing {
                params: self.into(),
                context: ctx,
                work_loop_result: Err(e),
                qconn,
            };
        };

        let work_loop_result = self.work_loop(&mut qconn, &mut ctx).await;

        Closing {
            params: self.into(),
            context: ctx,
            work_loop_result,
            qconn,
        }
    }
}

impl<Tx, M> IoWorker<Tx, M, Close>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn close<A: ApplicationOverQuic>(
        mut self, qconn: &mut QuicheConnection,
        ctx: &mut ConnectionStageContext<A>,
    ) {
        if self.conn_stage.work_loop_result.is_ok() &&
            self.bw_estimator.max_bandwidth > 0
        {
            let metrics = &self.metrics;

            metrics
                .max_bandwidth_mbps()
                .observe(self.bw_estimator.max_bandwidth as f64 * 1e-6);

            metrics
                .max_loss_pct()
                .observe(self.bw_estimator.max_loss_pct as f64 * 100.);
        }

        if ctx.application.should_act() {
            ctx.application.on_conn_close(
                qconn,
                &self.metrics,
                &self.conn_stage.work_loop_result,
            );
        }

        // TODO: this assumes that the tidy_up operation can be completed in one
        // send (ignoring flow/congestion control constraints). We should
        // guarantee that it gets sent by doublechecking the
        // gathered/flushed byte totals and retry if they don't match.
        let _ = self.gather_data_from_quiche_conn(qconn, ctx.buffer());
        self.flush_buffer_to_socket(ctx.buffer()).await;

        *ctx.stats.lock().unwrap() = QuicConnectionStats::from_conn(qconn);

        if let Some(err) = qconn.peer_error() {
            if err.is_app {
                self.audit_log_stats
                    .set_recvd_conn_close_application_error_code(
                        err.error_code as _,
                    );
            } else {
                self.audit_log_stats
                    .set_recvd_conn_close_transport_error_code(
                        err.error_code as _,
                    );
            }
        }

        if let Some(err) = qconn.local_error() {
            if err.is_app {
                self.audit_log_stats
                    .set_sent_conn_close_application_error_code(
                        err.error_code as _,
                    );
            } else {
                self.audit_log_stats
                    .set_sent_conn_close_transport_error_code(
                        err.error_code as _,
                    );
            }
        }

        self.close_connection(qconn);

        if let Err(work_loop_error) = self.conn_stage.work_loop_result {
            self.audit_log_stats
                .set_connection_close_reason(work_loop_error);
        }
    }

    fn close_connection(&mut self, qconn: &mut QuicheConnection) {
        if let Some(cid) = self.cfg.pending_cid.take() {
            self.unmap_cid(cid);
        }
        while let Some(retired_cid) = qconn.retired_scid_next() {
            self.unmap_cid(retired_cid);
        }
        for cid in qconn.source_ids().cloned() {
            self.unmap_cid(cid.into_owned());
        }

        self.metrics.connections_in_memory().dec();
    }
}

/// Returns the minimum of `v1` and `v2`, ignoring `None`s.
fn min_of_some<T: Ord>(v1: Option<T>, v2: Option<T>) -> Option<T> {
    match (v1, v2) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(v), _) | (_, Some(v)) => Some(v),
        (None, None) => None,
    }
}

/// A Token which increment the skipped_mid_handshake_flush_count metric on
/// `Drop` unless it is marked complete.
struct TrackMidHandshakeFlush<M: Metrics> {
    complete: bool,
    metrics: M,
}

impl<M: Metrics> TrackMidHandshakeFlush<M> {
    fn new(metrics: M) -> Self {
        Self {
            complete: false,
            metrics,
        }
    }

    fn mark_complete(&mut self) {
        self.complete = true;
    }
}

impl<M: Metrics> Drop for TrackMidHandshakeFlush<M> {
    fn drop(&mut self) {
        if !self.complete {
            self.metrics.skipped_mid_handshake_flush_count().inc();
        }
    }
}

fn random_u128() -> u128 {
    let mut buf = [0; 16];
    boring::rand::rand_bytes(&mut buf).expect("boring's RAND_bytes never fails");
    u128::from_ne_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::DefaultMetrics;
    use crate::ConnectionIdGenerator;
    use quiche::test_utils::emit_flight;
    use quiche::test_utils::process_flight;
    use quiche::test_utils::Pipe;
    use std::collections::VecDeque;
    use std::future::Future as _;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    struct NoopDatagramSender;

    impl DatagramSocketSend for NoopDatagramSender {
        fn poll_send(
            &self, _cx: &mut std::task::Context, buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_send_to(
            &self, _cx: &mut std::task::Context, buf: &[u8], _addr: SocketAddr,
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
    }

    #[derive(Debug)]
    struct TestStage;

    impl ConnectionStage for TestStage {}

    struct SequenceCidGenerator {
        ids: Mutex<VecDeque<ConnectionId<'static>>>,
        fallback: ConnectionId<'static>,
    }

    impl ConnectionIdGenerator<'static> for SequenceCidGenerator {
        fn new_connection_id(&self) -> ConnectionId<'static> {
            self.ids
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.fallback.clone())
        }

        fn verify_connection_id(
            &self, _cid: &ConnectionId<'_>,
        ) -> QuicResult<()> {
            Ok(())
        }
    }

    fn cid_test_worker(
        current_cid: ConnectionId<'static>, generated: ConnectionId<'static>,
    ) -> (
        IoWorker<NoopDatagramSender, DefaultMetrics, TestStage>,
        mpsc::UnboundedReceiver<ConnectionMapCommand>,
    ) {
        let (conn_map_cmd_tx, conn_map_cmd_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
        let owner = crate::quic::connection::RouteOwner::new();
        let route_cleanup = RouteCleanupGuard::new(
            conn_map_cmd_tx.clone(),
            owner,
            current_cid.clone(),
            None,
        );
        let local_addr = "127.0.0.1:443".parse().unwrap();
        let peer_addr = "127.0.0.1:1234".parse().unwrap();
        let params = IoWorkerParams {
            socket: MaybeConnectedSocket::new(NoopDatagramSender),
            shutdown_tx,
            cfg: WriterConfig {
                pending_cid: None,
                peer_addr,
                local_addr,
                with_gso: false,
                pacing_offload: false,
                with_pktinfo: false,
                fixed_peer_ip: None,
            },
            audit_log_stats: Arc::new(QuicAuditStats::new(current_cid.to_vec())),
            write_state: WriteState::default(),
            conn_map_cmd_tx,
            route_cleanup: Some(route_cleanup),
            cid_generator: Some(Arc::new(SequenceCidGenerator {
                ids: Mutex::new(VecDeque::from([generated])),
                fallback: current_cid,
            })),
            client_migration_rx: None,
            client_migration_socket: None,
            endpoint_state: ConnectionEndpointState::new(local_addr, peer_addr),
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time: None,
            metrics: DefaultMetrics,
        };
        (IoWorker::new(params, TestStage), conn_map_cmd_rx)
    }

    fn take_map_result(
        commands: &mut mpsc::UnboundedReceiver<ConnectionMapCommand>,
        expected_cid: &ConnectionId<'_>,
    ) -> oneshot::Sender<bool> {
        match commands.try_recv().unwrap() {
            ConnectionMapCommand::MapCid {
                new_cid, result, ..
            } => {
                assert_eq!(new_cid, *expected_cid);
                result
            },
            ConnectionMapCommand::UnmapCid { .. } => {
                panic!("expected a route-map confirmation request")
            },
        }
    }

    fn test_config(server: bool) -> quiche::Config {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        if server {
            config
                .load_cert_chain_from_pem_file(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../quiche/examples/cert.crt"
                ))
                .unwrap();
            config
                .load_priv_key_from_pem_file(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../quiche/examples/cert.key"
                ))
                .unwrap();
        }
        config.set_application_protos(&[b"source-gate"]).unwrap();
        config.set_initial_max_data(64);
        config.set_initial_max_stream_data_bidi_local(64);
        config.set_initial_max_stream_data_bidi_remote(64);
        config.set_initial_max_streams_bidi(1);
        config.set_active_connection_id_limit(4);
        config.verify_peer(false);
        config
    }

    fn incoming(
        peer_addr: SocketAddr, local_addr: SocketAddr, buf: Vec<u8>,
        gro: Option<i32>,
    ) -> Incoming {
        Incoming {
            peer_addr,
            local_addr,
            rx_time: None,
            buf,
            gro,
            #[cfg(target_os = "linux")]
            so_mark_data: None,
        }
    }

    fn test_pipe() -> Pipe<crate::buf_factory::BufFactory> {
        let mut client_config = test_config(false);
        let mut server_config = test_config(true);
        Pipe::with_client_and_server_config_and_buf(
            &mut client_config,
            &mut server_config,
        )
        .unwrap()
    }

    fn source_ids(connection: &QuicheConnection) -> Vec<Vec<u8>> {
        connection.source_ids().map(|cid| cid.to_vec()).collect()
    }

    #[tokio::test]
    async fn dynamic_scid_is_not_added_before_route_confirmation() {
        let mut pipe = test_pipe();
        pipe.handshake().unwrap();
        pipe.advance().unwrap();
        assert!(pipe.server.scids_left() > 0);

        let current_cid = pipe.server.source_id().into_owned();
        let generated = ConnectionId::from_vec(vec![0xa5; 20]);
        let before = source_ids(&pipe.server);
        let (mut worker, mut commands) =
            cid_test_worker(current_cid, generated.clone());
        let mut fill = Box::pin(worker.fill_available_scids(&mut pipe.server));
        let mut context =
            std::task::Context::from_waker(std::task::Waker::noop());

        assert!(fill.as_mut().poll(&mut context).is_pending());
        let result = take_map_result(&mut commands, &generated);
        drop(fill);
        drop(result);

        assert_eq!(source_ids(&pipe.server), before);
        assert!(worker.route_cleanup.as_ref().unwrap().tracks(&generated));
        drop(worker);
        assert!(
            std::iter::from_fn(|| commands.try_recv().ok()).any(|command| {
                matches!(
                    command,
                    ConnectionMapCommand::UnmapCid { cid, .. } if cid == generated
                )
            })
        );
    }

    #[tokio::test]
    async fn dynamic_scid_collision_leaves_quiche_and_cleanup_unchanged() {
        let mut pipe = test_pipe();
        pipe.handshake().unwrap();
        pipe.advance().unwrap();
        assert!(pipe.server.scids_left() > 0);

        let current_cid = pipe.server.source_id().into_owned();
        let generated = ConnectionId::from_vec(vec![0x5a; 20]);
        let before = source_ids(&pipe.server);
        let (mut worker, mut commands) =
            cid_test_worker(current_cid.clone(), generated.clone());
        let mut fill = Box::pin(worker.fill_available_scids(&mut pipe.server));
        let mut context =
            std::task::Context::from_waker(std::task::Waker::noop());

        assert!(fill.as_mut().poll(&mut context).is_pending());
        take_map_result(&mut commands, &generated)
            .send(false)
            .unwrap();
        assert!(fill.as_mut().poll(&mut context).is_ready());
        drop(fill);

        assert_eq!(source_ids(&pipe.server), before);
        let cleanup = worker.route_cleanup.as_ref().unwrap();
        assert!(cleanup.tracks(&current_cid));
        assert!(!cleanup.tracks(&generated));
    }

    #[tokio::test]
    async fn dynamic_scid_is_added_only_after_route_confirmation() {
        let mut pipe = test_pipe();
        pipe.handshake().unwrap();
        pipe.advance().unwrap();
        assert!(pipe.server.scids_left() > 0);

        let current_cid = pipe.server.source_id().into_owned();
        let generated = ConnectionId::from_vec(vec![0x3c; 20]);
        let before = source_ids(&pipe.server);
        let (mut worker, mut commands) =
            cid_test_worker(current_cid, generated.clone());
        let mut fill = Box::pin(worker.fill_available_scids(&mut pipe.server));
        let mut context =
            std::task::Context::from_waker(std::task::Waker::noop());

        assert!(fill.as_mut().poll(&mut context).is_pending());
        take_map_result(&mut commands, &generated)
            .send(true)
            .unwrap();
        assert!(fill.as_mut().poll(&mut context).is_ready());
        drop(fill);

        let after = source_ids(&pipe.server);
        assert_eq!(after.len(), before.len() + 1);
        assert!(after.contains(&generated.to_vec()));
        assert!(worker.route_cleanup.as_ref().unwrap().tracks(&generated));
    }

    #[tokio::test]
    async fn repeated_live_scid_is_skipped_without_forgetting_cleanup() {
        let mut pipe = test_pipe();
        pipe.handshake().unwrap();
        pipe.advance().unwrap();
        assert!(pipe.server.scids_left() > 0);

        let current_cid = pipe.server.source_id().into_owned();
        let before = source_ids(&pipe.server);
        let (mut worker, mut commands) =
            cid_test_worker(current_cid.clone(), current_cid.clone());
        worker.fill_available_scids(&mut pipe.server).await;

        assert_eq!(source_ids(&pipe.server), before);
        assert!(commands.try_recv().is_err());
        assert!(worker.route_cleanup.as_ref().unwrap().tracks(&current_cid));
    }

    #[tokio::test]
    async fn quiche_scid_rejection_rolls_back_confirmed_route() {
        let mut pipe = test_pipe();
        pipe.handshake().unwrap();
        pipe.advance().unwrap();
        assert!(pipe.server.scids_left() > 0);

        let current_cid = pipe.server.source_id().into_owned();
        let invalid = ConnectionId::from_vec(vec![0x7e; 20]);
        pipe.server.new_scid(&invalid, 7, false).unwrap();
        assert!(pipe.server.scids_left() > 0);
        let before = source_ids(&pipe.server);
        let (mut worker, mut commands) =
            cid_test_worker(current_cid.clone(), invalid.clone());
        let mut fill =
            Box::pin(worker.fill_available_scids_with(&mut pipe.server, || 8));
        let mut context =
            std::task::Context::from_waker(std::task::Waker::noop());

        assert!(fill.as_mut().poll(&mut context).is_pending());
        take_map_result(&mut commands, &invalid).send(true).unwrap();
        assert!(fill.as_mut().poll(&mut context).is_ready());
        drop(fill);

        assert_eq!(source_ids(&pipe.server), before);
        assert!(matches!(
            commands.try_recv(),
            Ok(ConnectionMapCommand::UnmapCid { cid, .. }) if cid == invalid
        ));
        let cleanup = worker.route_cleanup.as_ref().unwrap();
        assert!(cleanup.tracks(&current_cid));
        assert!(!cleanup.tracks(&invalid));
    }

    #[tokio::test]
    async fn closed_router_never_adds_or_tracks_dynamic_scid() {
        let mut pipe = test_pipe();
        pipe.handshake().unwrap();
        pipe.advance().unwrap();
        assert!(pipe.server.scids_left() > 0);

        let current_cid = pipe.server.source_id().into_owned();
        let generated = ConnectionId::from_vec(vec![0x66; 20]);
        let before = source_ids(&pipe.server);
        let (mut worker, commands) =
            cid_test_worker(current_cid.clone(), generated.clone());
        drop(commands);
        worker.fill_available_scids(&mut pipe.server).await;

        assert_eq!(source_ids(&pipe.server), before);
        let cleanup = worker.route_cleanup.as_ref().unwrap();
        assert!(cleanup.tracks(&current_cid));
        assert!(!cleanup.tracks(&generated));
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ConnectionState {
        recv: usize,
        recv_bytes: u64,
        paths_count: usize,
        paths: Vec<(SocketAddr, SocketAddr, bool, usize)>,
        stream_readable: bool,
        local_error: bool,
        peer_error: bool,
    }

    fn state(conn: &QuicheConnection) -> ConnectionState {
        let stats = conn.stats();
        let paths = conn
            .path_stats()
            .map(|path| (path.local_addr, path.peer_addr, path.active, path.recv))
            .collect();
        ConnectionState {
            recv: stats.recv,
            recv_bytes: stats.recv_bytes,
            paths_count: stats.paths_count,
            paths,
            stream_readable: conn.stream_readable(0),
            local_error: conn.local_error().is_some(),
            peer_error: conn.peer_error().is_some(),
        }
    }

    #[test]
    fn fixed_peer_ip_drops_before_quiche_and_allows_original_source() {
        let mut pipe = test_pipe();
        pipe.handshake().unwrap();
        pipe.advance().unwrap();

        let initial_peer = Pipe::client_addr();
        pipe.client.stream_send(0, b"hello", false).unwrap();
        let mut flight = emit_flight(&mut pipe.client).unwrap();
        assert_eq!(flight.len(), 1);
        let (packet, send_info) = flight.pop().unwrap();
        let before = state(&pipe.server);

        let wrong_peer = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            initial_peer.port(),
        );
        assert!(!recv_incoming(
            Some(initial_peer.ip()),
            &mut pipe.server,
            incoming(wrong_peer, send_info.to, packet.clone(), None),
        )
        .unwrap());
        assert_eq!(state(&pipe.server), before);

        assert!(recv_incoming(
            Some(initial_peer.ip()),
            &mut pipe.server,
            incoming(send_info.from, send_info.to, packet, None),
        )
        .unwrap());
        let mut received = [0; 5];
        assert_eq!(pipe.server.stream_recv(0, &mut received), Ok((5, false)));
        assert_eq!(&received, b"hello");

        pipe.client.stream_send(0, b"!", false).unwrap();
        let flight = emit_flight(&mut pipe.client).unwrap();
        for (packet, send_info) in flight {
            let same_ip_new_port =
                SocketAddr::new(send_info.from.ip(), send_info.from.port() + 1);
            assert!(recv_incoming(
                Some(initial_peer.ip()),
                &mut pipe.server,
                incoming(same_ip_new_port, send_info.to, packet, None),
            )
            .unwrap());
        }
        let mut received = [0; 1];
        assert_eq!(pipe.server.stream_recv(0, &mut received), Ok((1, false)));
        assert_eq!(&received, b"!");

        let before_gro = state(&pipe.server);
        assert!(!recv_incoming(
            Some(initial_peer.ip()),
            &mut pipe.server,
            incoming(wrong_peer, Pipe::server_addr(), vec![0], Some(1)),
        )
        .unwrap());
        assert_eq!(state(&pipe.server), before_gro);
    }

    #[test]
    fn fixed_peer_ip_drops_initial_flight_without_changing_connection() {
        let mut pipe = test_pipe();

        let initial_peer = Pipe::client_addr();
        let wrong_peer = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            initial_peer.port(),
        );
        let flight = emit_flight(&mut pipe.client).unwrap();
        let before = state(&pipe.server);

        for (packet, send_info) in &flight {
            assert!(!recv_incoming(
                Some(initial_peer.ip()),
                &mut pipe.server,
                incoming(wrong_peer, send_info.to, packet.clone(), None),
            )
            .unwrap());
        }
        assert_eq!(state(&pipe.server), before);

        for (packet, send_info) in flight {
            assert!(recv_incoming(
                Some(initial_peer.ip()),
                &mut pipe.server,
                incoming(send_info.from, send_info.to, packet, None),
            )
            .unwrap());
        }

        for _ in 0..8 {
            if pipe.client.is_established() && pipe.server.is_established() {
                break;
            }
            let flight = emit_flight(&mut pipe.server).unwrap();
            process_flight(&mut pipe.client, flight).unwrap();
            let flight = emit_flight(&mut pipe.client).unwrap();
            process_flight(&mut pipe.server, flight).unwrap();
        }
        assert!(pipe.client.is_established());
        assert!(pipe.server.is_established());
    }

    #[test]
    fn unfixed_peer_accepts_stream_packet_from_new_ip() {
        let mut pipe = test_pipe();
        pipe.handshake().unwrap();
        pipe.advance().unwrap();

        pipe.client.stream_send(0, b"tunnel", false).unwrap();
        let mut flight = emit_flight(&mut pipe.client).unwrap();
        assert_eq!(flight.len(), 1);
        let (packet, send_info) = flight.pop().unwrap();
        let new_peer = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            send_info.from.port(),
        );

        assert!(recv_incoming(
            None,
            &mut pipe.server,
            incoming(new_peer, send_info.to, packet, None),
        )
        .unwrap());
        let mut received = [0; 6];
        assert_eq!(pipe.server.stream_recv(0, &mut received), Ok((6, false)));
        assert_eq!(&received, b"tunnel");
    }
}
