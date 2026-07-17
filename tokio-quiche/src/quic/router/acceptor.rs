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

use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use datagram_socket::DatagramSocketSend;
use datagram_socket::DatagramSocketSendExt;
use datagram_socket::MAX_DATAGRAM_SIZE;
use qlog::writer::make_qlog_writer_from_path;
use qlog::writer::qlog_file_name;
use quiche::ConnectionId;
use quiche::Header;
use quiche::RetryConnectionIds;
use quiche::Type as PacketType;
use task_killswitch::spawn_with_killswitch;

use crate::metrics::labels;
use crate::metrics::Metrics;
use crate::quic::addr_validation_token::AddrValidationTokenManager;
use crate::quic::connection::ServerInitialMetadata;
use crate::quic::connection::SharedConnectionIdGenerator;
use crate::quic::hooks::canonical_ip;
use crate::quic::hooks::StatelessRetryDecision;
use crate::quic::router::NewConnection;
use crate::quic::ClientInitialInfo;
use crate::quic::ConnectionHook;
use crate::quic::Incoming;
use crate::settings::Config;
use crate::QuicResultExt;

use super::InitialPacketHandler;

/// A [`ConnectionAcceptor`] is an [`InitialPacketHandler`] that acts as a
/// server and accepts quic connections.
pub(crate) struct ConnectionAcceptor<S, M> {
    config: ConnectionAcceptorConfig,
    socket: Arc<S>,
    token_manager: AddrValidationTokenManager,
    cid_generator: SharedConnectionIdGenerator,
    metrics: M,
}

pub(crate) struct ConnectionAcceptorConfig {
    pub(crate) connection_hook:
        Option<Arc<dyn ConnectionHook + Send + Sync + 'static>>,
    #[cfg(target_os = "linux")]
    pub(crate) with_pktinfo: bool,
}

impl ConnectionAcceptorConfig {
    fn fixed_peer_ip(
        &self, profile_index: Option<usize>, peer_addr: SocketAddr,
    ) -> Option<IpAddr> {
        self.connection_hook
            .as_ref()
            .filter(|hook| {
                hook.server_config_profile_requires_fixed_peer_ip(profile_index)
            })
            .map(|_| canonical_ip(peer_addr.ip()))
    }

    fn stateless_retry_decision(
        &self, profile_index: Option<usize>, source: IpAddr,
    ) -> StatelessRetryDecision {
        self.connection_hook.as_ref().map_or(
            StatelessRetryDecision::Allow,
            |hook| {
                hook.stateless_retry_decision(profile_index, canonical_ip(source))
            },
        )
    }
}

impl<S, M> ConnectionAcceptor<S, M>
where
    S: DatagramSocketSend + Send + 'static,
    M: Metrics,
{
    pub(crate) fn new(
        config: ConnectionAcceptorConfig, socket: Arc<S>,
        token_manager: AddrValidationTokenManager,
        cid_generator: SharedConnectionIdGenerator, metrics: M,
    ) -> Self {
        Self {
            config,
            socket,
            token_manager,
            cid_generator,
            metrics,
        }
    }

    fn accept_conn(
        &mut self, incoming: Incoming, retry_cids: Option<RetryConnectionIds>,
        pending_cid: ConnectionId<'static>, config: &mut Config,
        profile_index: Option<usize>,
    ) -> io::Result<Option<NewConnection>> {
        let handshake_start_time = Instant::now();
        let server_initial_metadata = Some(ServerInitialMetadata::new(
            profile_index,
            incoming.peer_addr.ip(),
            handshake_start_time,
            config.server_config_identity.clone(),
        ));
        let scid = self.cid_generator.new_connection_id();

        let Some(mut profile) = config.server_profile_config_mut(profile_index)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                server_profile_not_found(profile_index),
            ));
        };

        let fixed_peer_ip =
            self.config.fixed_peer_ip(profile_index, incoming.peer_addr);

        let mut conn = {
            let quiche_config = profile.quiche_config_mut();
            if let Some(retry_cids) = retry_cids {
                quiche::accept_with_retry(
                    &scid,
                    retry_cids,
                    incoming.local_addr,
                    incoming.peer_addr,
                    quiche_config,
                )
            } else {
                quiche::accept_with_buf_factory(
                    &scid,
                    None,
                    incoming.local_addr,
                    incoming.peer_addr,
                    quiche_config,
                )
            }
        }
        .into_io()?;

        let profile_snapshot = profile.snapshot();

        if let Some(qlog_dir) = &profile_snapshot.qlog_dir {
            let id = format!("{:?}", scid);
            let path = std::path::Path::new(qlog_dir)
                .join(qlog_file_name(&id, profile_snapshot.qlog_compression));
            if let Ok(writer) = make_qlog_writer_from_path(
                &path,
                profile_snapshot.qlog_compression,
            ) {
                conn.set_qlog(
                    writer,
                    "tokio-quiche qlog".to_string(),
                    format!("tokio-quiche qlog id={id}"),
                );
            }
        }

        if let Some(keylog_file) = profile_snapshot.keylog_file {
            if let Ok(keylog_clone) = keylog_file.try_clone() {
                conn.set_keylog(Box::new(keylog_clone));
            }
        }

        Ok(Some(NewConnection {
            conn: Box::new(conn),
            server_config: Some(profile_snapshot.connection_config),
            handshake_start_time,
            pending_cid: Some(pending_cid),
            cid_generator: Some(Arc::clone(&self.cid_generator)),
            initial_pkt: Some(incoming),
            fixed_peer_ip,
            server_initial_metadata,
        }))
    }

    fn handshake_reply(
        &self, incoming: Incoming,
        writer: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> io::Result<Option<NewConnection>> {
        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE];
        let written = writer(&mut send_buf)?;
        let socket = Arc::clone(&self.socket);
        #[cfg(target_os = "linux")]
        let with_pktinfo = self.config.with_pktinfo;
        #[cfg(target_os = "linux")]
        let would_block_metric = self
            .metrics
            .write_errors(labels::QuicWriteError::WouldBlock);
        #[cfg(target_os = "linux")]
        let send_to_wouldblock_duration_s =
            self.metrics.send_to_wouldblock_duration_s();

        spawn_with_killswitch(async move {
            let send_buf = &send_buf[..written];
            let to = incoming.peer_addr;

            #[allow(unused_variables)]
            let Some(udp) = socket.as_udp_socket() else {
                let _ = socket.send_to(send_buf, to).await;
                return;
            };

            #[cfg(target_os = "linux")]
            {
                let from = with_pktinfo.then_some(incoming.local_addr);
                let _ = crate::quic::io::gso::send_to(
                    udp,
                    to,
                    from,
                    send_buf,
                    send_buf.len(),
                    None,
                    would_block_metric,
                    send_to_wouldblock_duration_s,
                )
                .await;
            }

            #[cfg(not(target_os = "linux"))]
            let _ = socket.send_to(send_buf, to).await;
        });

        Ok(None)
    }

    fn stateless_retry(
        &mut self, incoming: Incoming, hdr: Header,
    ) -> io::Result<Option<NewConnection>> {
        let scid = self.cid_generator.new_connection_id();

        let token = self.token_manager.gen(&hdr.dcid, incoming.peer_addr);

        self.handshake_reply(incoming, move |buf| {
            quiche::retry(&hdr.scid, &hdr.dcid, &scid, &token, hdr.version, buf)
                .into_io()
        })
    }

    fn select_profile(&self, incoming: &Incoming, hdr: &Header) -> Option<usize> {
        let token_present =
            hdr.token.as_ref().is_some_and(|token| !token.is_empty());
        self.config.connection_hook.as_ref().and_then(|hook| {
            hook.select_server_config_profile(&ClientInitialInfo {
                peer_addr: incoming.peer_addr,
                local_addr: incoming.local_addr,
                version: hdr.version,
                scid: &hdr.scid,
                dcid: &hdr.dcid,
                token_present,
            })
        })
    }
}

impl<S, M> InitialPacketHandler for ConnectionAcceptor<S, M>
where
    S: DatagramSocketSend + Send + 'static,
    M: Metrics,
{
    fn handle_initials(
        &mut self, incoming: Incoming, hdr: quiche::Header<'static>,
        config: &mut Config,
    ) -> io::Result<Option<NewConnection>> {
        if hdr.ty != PacketType::Initial {
            // Non-initial packets should have a valid CID, but we want to have
            // some telemetry if this isn't the case.
            if let Err(e) = self.cid_generator.verify_connection_id(&hdr.dcid) {
                self.metrics.invalid_cid_packet_count(e).inc();
            }

            Err(labels::QuicInvalidInitialPacketError::WrongType(hdr.ty))?;
        }

        if !quiche::version_is_supported(hdr.version) {
            return self.handshake_reply(incoming, |buf| {
                quiche::negotiate_version(&hdr.scid, &hdr.dcid, buf).into_io()
            });
        }

        let profile_index = self.select_profile(&incoming, &hdr);

        let Some(disable_client_ip_validation) =
            config.server_profile_disable_client_ip_validation(profile_index)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                server_profile_not_found(profile_index),
            ));
        };

        if disable_client_ip_validation {
            return self.accept_conn(
                incoming,
                None,
                hdr.dcid,
                config,
                profile_index,
            );
        }

        // NOTE: token is always present in Initial packets
        let token = hdr.token.as_ref().unwrap();
        if token.is_empty() {
            if self
                .config
                .stateless_retry_decision(profile_index, incoming.peer_addr.ip()) ==
                StatelessRetryDecision::Drop
            {
                return Ok(None);
            }
            return self.stateless_retry(incoming, hdr);
        }

        let original_dcid = self
            .token_manager
            .validate_and_extract_original_dcid(token, incoming.peer_addr)
            .or(Err(
                labels::QuicInvalidInitialPacketError::TokenValidationFail,
            ))?;

        let retry_cids = Some(RetryConnectionIds {
            original_destination_cid: &original_dcid,
            retry_source_cid: &hdr.dcid,
        });

        self.accept_conn(
            incoming,
            retry_cids,
            hdr.dcid.clone(),
            config,
            profile_index,
        )
    }
}

fn server_profile_not_found(index: Option<usize>) -> String {
    match index {
        Some(index) => format!("unknown server config profile index {index}"),
        None => "default server config profile is missing".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::DefaultMetrics;
    use crate::quic::connection::ConnectionIdGenerator;
    use crate::settings::ConnectionParams;
    use crate::settings::Hooks;
    use crate::settings::QuicSettings;
    use crate::settings::TlsCertificatePaths;
    use crate::socket::SocketCapabilities;
    use crate::QuicResult;
    use boring::ssl::SslContextBuilder;
    use datagram_socket::DatagramSocketSend;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::task::Context;
    use std::task::Poll;

    const TEST_CERT_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/",
        "../quiche/examples/cert.crt"
    );
    const TEST_KEY_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/",
        "../quiche/examples/cert.key"
    );

    struct RecordingHook(Mutex<Vec<Option<usize>>>);

    impl ConnectionHook for RecordingHook {
        fn create_custom_ssl_context_builder(
            &self, _settings: Option<TlsCertificatePaths<'_>>,
            _profile_index: Option<usize>,
        ) -> QuicResult<Option<SslContextBuilder>> {
            Ok(None)
        }

        fn server_config_profile_requires_fixed_peer_ip(
            &self, profile_index: Option<usize>,
        ) -> bool {
            self.0.lock().unwrap().push(profile_index);
            true
        }
    }

    #[test]
    fn fixed_peer_ip_policy_receives_selected_profile() {
        let hook = Arc::new(RecordingHook(Mutex::new(Vec::new())));
        let config = ConnectionAcceptorConfig {
            connection_hook: Some(hook.clone()),
            #[cfg(target_os = "linux")]
            with_pktinfo: false,
        };
        let peer_addr = "[::ffff:192.0.2.1]:443".parse().unwrap();

        assert_eq!(
            config.fixed_peer_ip(Some(2), peer_addr),
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(*hook.0.lock().unwrap(), vec![Some(2)]);
    }

    struct RetryHook {
        decision: StatelessRetryDecision,
        selected_profile: Option<usize>,
        calls: Mutex<Vec<(Option<usize>, IpAddr)>>,
    }

    impl ConnectionHook for RetryHook {
        fn create_custom_ssl_context_builder(
            &self, _settings: Option<TlsCertificatePaths<'_>>,
            _profile_index: Option<usize>,
        ) -> QuicResult<Option<SslContextBuilder>> {
            Ok(None)
        }

        fn stateless_retry_decision(
            &self, profile_index: Option<usize>, canonical_source: IpAddr,
        ) -> StatelessRetryDecision {
            self.calls
                .lock()
                .unwrap()
                .push((profile_index, canonical_source));
            self.decision
        }

        fn select_server_config_profile(
            &self, _info: &ClientInitialInfo<'_>,
        ) -> Option<usize> {
            self.selected_profile
        }
    }

    #[derive(Default)]
    struct CountingCidGenerator(AtomicUsize);

    impl ConnectionIdGenerator<'static> for CountingCidGenerator {
        fn new_connection_id(&self) -> ConnectionId<'static> {
            let next = self.0.fetch_add(1, Ordering::Relaxed) as u8;
            ConnectionId::from_vec(vec![next; quiche::MAX_CONN_ID_LEN])
        }

        fn verify_connection_id(
            &self, _cid: &ConnectionId<'_>,
        ) -> QuicResult<()> {
            Ok(())
        }
    }

    struct RecordingSender {
        calls: AtomicUsize,
        fail: bool,
    }

    impl DatagramSocketSend for RecordingSender {
        fn poll_send(
            &self, _cx: &mut Context, buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                Poll::Ready(Err(io::Error::other("injected send failure")))
            } else {
                Poll::Ready(Ok(buf.len()))
            }
        }

        fn poll_send_to(
            &self, _cx: &mut Context, buf: &[u8], _addr: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            self.poll_send(_cx, buf)
        }
    }

    fn initial_packet() -> (Incoming, Header<'static>) {
        let client_addr = "[::ffff:192.0.2.1]:1234".parse().unwrap();
        let server_addr = "[2001:db8::1]:443".parse().unwrap();
        let scid = ConnectionId::from_ref(&[0x42; quiche::MAX_CONN_ID_LEN]);
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config.verify_peer(false);
        config.set_application_protos(&[b"test"]).unwrap();
        let mut connection =
            quiche::connect(None, &scid, client_addr, server_addr, &mut config)
                .unwrap();
        let mut packet = vec![0; 1_350];
        let (written, _) = connection.send(&mut packet).unwrap();
        packet.truncate(written);
        let header =
            Header::from_slice(&mut packet, quiche::MAX_CONN_ID_LEN).unwrap();

        (
            Incoming {
                peer_addr: client_addr,
                local_addr: server_addr,
                rx_time: None,
                buf: packet,
                gro: None,
                #[cfg(target_os = "linux")]
                so_mark_data: None,
            },
            header,
        )
    }

    struct RetryHarness {
        acceptor: ConnectionAcceptor<RecordingSender, DefaultMetrics>,
        config: Config,
        hook: Arc<RetryHook>,
        sender: Arc<RecordingSender>,
        cid_generator: Arc<CountingCidGenerator>,
    }

    fn retry_acceptor(
        decision: StatelessRetryDecision, fail_send: bool,
    ) -> RetryHarness {
        retry_acceptor_with_profile(decision, fail_send, false, None)
    }

    fn retry_acceptor_with_profile(
        decision: StatelessRetryDecision, fail_send: bool,
        disable_client_ip_validation: bool, selected_profile: Option<usize>,
    ) -> RetryHarness {
        let hook = Arc::new(RetryHook {
            decision,
            selected_profile,
            calls: Mutex::new(Vec::new()),
        });
        let sender = Arc::new(RecordingSender {
            calls: AtomicUsize::new(0),
            fail: fail_send,
        });
        let cid_generator = Arc::new(CountingCidGenerator::default());
        let settings = QuicSettings {
            disable_client_ip_validation,
            ..QuicSettings::default()
        };
        let params = ConnectionParams::new_server(
            settings,
            TlsCertificatePaths {
                cert: TEST_CERT_FILE,
                private_key: TEST_KEY_FILE,
                kind: crate::settings::CertificateKind::X509,
            },
            Hooks {
                connection_hook: Some(hook.clone()),
            },
        );
        let config = Config::new(&params, SocketCapabilities::default()).unwrap();
        let acceptor = ConnectionAcceptor::new(
            ConnectionAcceptorConfig {
                connection_hook: Some(hook.clone()),
                #[cfg(target_os = "linux")]
                with_pktinfo: false,
            },
            sender.clone(),
            AddrValidationTokenManager::default(),
            cid_generator.clone(),
            DefaultMetrics,
        );

        RetryHarness {
            acceptor,
            config,
            hook,
            sender,
            cid_generator,
        }
    }

    #[test]
    fn retry_drop_precedes_cid_token_and_send_work() {
        let mut harness = retry_acceptor(StatelessRetryDecision::Drop, false);
        let (incoming, header) = initial_packet();

        assert!(harness
            .acceptor
            .handle_initials(incoming, header, &mut harness.config)
            .unwrap()
            .is_none());
        assert_eq!(*harness.hook.calls.lock().unwrap(), vec![(
            None,
            "192.0.2.1".parse().unwrap()
        )]);
        assert_eq!(harness.cid_generator.0.load(Ordering::Relaxed), 0);
        assert_eq!(harness.sender.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn nonempty_invalid_token_never_calls_retry_hook() {
        let mut harness = retry_acceptor(StatelessRetryDecision::Allow, false);
        let (incoming, mut header) = initial_packet();
        header.token = Some(vec![0; 1]);

        assert!(harness
            .acceptor
            .handle_initials(incoming, header, &mut harness.config)
            .is_err());
        assert!(harness.hook.calls.lock().unwrap().is_empty());
        assert_eq!(harness.cid_generator.0.load(Ordering::Relaxed), 0);
        assert_eq!(harness.sender.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn valid_token_accepts_with_frozen_metadata_without_retry_hook() {
        let mut harness = retry_acceptor(StatelessRetryDecision::Drop, false);
        let (incoming, mut header) = initial_packet();
        header.token = Some(
            harness
                .acceptor
                .token_manager
                .gen(&header.dcid, incoming.peer_addr),
        );

        let accepted = harness
            .acceptor
            .handle_initials(incoming, header, &mut harness.config)
            .unwrap()
            .unwrap();
        let metadata = accepted.server_initial_metadata.as_ref().unwrap();

        assert!(harness.hook.calls.lock().unwrap().is_empty());
        assert_eq!(metadata.profile_index(), None);
        assert_eq!(
            metadata.canonical_source(),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(metadata.handshake_start(), accepted.handshake_start_time);
        assert_eq!(harness.cid_generator.0.load(Ordering::Relaxed), 1);
        assert_eq!(harness.sender.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn wrong_type_does_not_call_retry_hook() {
        let mut harness = retry_acceptor(StatelessRetryDecision::Allow, false);
        let (incoming, mut header) = initial_packet();
        header.ty = PacketType::Short;

        assert!(harness
            .acceptor
            .handle_initials(incoming, header, &mut harness.config)
            .is_err());
        assert!(harness.hook.calls.lock().unwrap().is_empty());
        assert_eq!(harness.cid_generator.0.load(Ordering::Relaxed), 0);
        assert_eq!(harness.sender.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn unsupported_version_bypasses_retry_hook_and_sends_negotiation() {
        let mut harness = retry_acceptor(StatelessRetryDecision::Allow, false);
        let (incoming, mut header) = initial_packet();
        header.version = 0xdead_beef;

        assert!(harness
            .acceptor
            .handle_initials(incoming, header, &mut harness.config)
            .unwrap()
            .is_none());
        tokio::task::yield_now().await;

        assert!(harness.hook.calls.lock().unwrap().is_empty());
        assert_eq!(harness.cid_generator.0.load(Ordering::Relaxed), 0);
        assert_eq!(harness.sender.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn missing_selected_profile_fails_before_retry_hook() {
        let mut harness = retry_acceptor_with_profile(
            StatelessRetryDecision::Allow,
            false,
            false,
            Some(99),
        );
        let (incoming, header) = initial_packet();

        assert!(harness
            .acceptor
            .handle_initials(incoming, header, &mut harness.config)
            .is_err());
        assert!(harness.hook.calls.lock().unwrap().is_empty());
        assert_eq!(harness.cid_generator.0.load(Ordering::Relaxed), 0);
        assert_eq!(harness.sender.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn validation_disabled_accepts_directly_without_retry_hook() {
        let mut harness = retry_acceptor_with_profile(
            StatelessRetryDecision::Drop,
            false,
            true,
            None,
        );
        let (incoming, header) = initial_packet();

        let accepted = harness
            .acceptor
            .handle_initials(incoming, header, &mut harness.config)
            .unwrap()
            .unwrap();

        assert!(harness.hook.calls.lock().unwrap().is_empty());
        assert_eq!(
            accepted
                .server_initial_metadata
                .as_ref()
                .unwrap()
                .profile_index(),
            None
        );
        assert_eq!(harness.cid_generator.0.load(Ordering::Relaxed), 1);
        assert_eq!(harness.sender.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn retry_allow_is_not_rolled_back_by_send_failure() {
        let mut harness = retry_acceptor(StatelessRetryDecision::Allow, true);
        let (incoming, header) = initial_packet();

        assert!(harness
            .acceptor
            .handle_initials(incoming, header, &mut harness.config)
            .unwrap()
            .is_none());
        tokio::task::yield_now().await;

        assert_eq!(harness.hook.calls.lock().unwrap().len(), 1);
        assert_eq!(harness.cid_generator.0.load(Ordering::Relaxed), 1);
        assert_eq!(harness.sender.calls.load(Ordering::Relaxed), 1);
    }
}
