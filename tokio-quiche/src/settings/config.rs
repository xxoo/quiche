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

use foundations::telemetry::log;
use std::borrow::Cow;
use std::fs::File;
use std::time::Duration;

use qlog::writer::QlogCompression;

use crate::result::QuicResult;
use crate::settings::CertificateKind;
use crate::settings::ConnectionParams;
use crate::settings::Hooks;
use crate::settings::PeerTrustRoots;
use crate::settings::QuicSettings;
use crate::settings::TlsCertificatePaths;
use crate::socket::SocketCapabilities;

/// Whether `--cfg capture_keylogs` was set at build time. We keep supporting
/// the `capture_keylogs` feature for backward compatibility.
const KEYLOGFILE_ENABLED: bool =
    cfg!(capture_keylogs) || cfg!(feature = "capture_keylogs");

/// Internal representation of the combined configuration for a QUIC connection.
pub(crate) struct Config {
    pub quiche_config: quiche::Config,
    pub disable_client_ip_validation: bool,
    pub qlog_dir: Option<String>,
    pub qlog_compression: QlogCompression,
    pub has_gso: bool,
    pub pacing_offload: bool,
    pub enable_expensive_packet_count_metrics: bool,
    pub keylog_file: Option<File>,
    pub listen_backlog: usize,
    pub handshake_timeout: Option<Duration>,
    pub has_ippktinfo: bool,
    pub has_ipv6pktinfo: bool,
    server_config_profiles: Vec<ServerProfileConfig>,
}

impl AsMut<quiche::Config> for Config {
    fn as_mut(&mut self) -> &mut quiche::Config {
        &mut self.quiche_config
    }
}

impl Config {
    pub(crate) fn new(
        params: &ConnectionParams, socket_capabilities: SocketCapabilities,
    ) -> QuicResult<Self> {
        let quic_settings = &params.settings;
        let keylog_file = make_keylog_file(quic_settings, true);

        let has_gso = socket_capabilities.has_gso;
        let pacing_offload =
            make_pacing_offload(quic_settings, &socket_capabilities);
        let has_ippktinfo = socket_capabilities.has_ippktinfo;
        let has_ipv6pktinfo = socket_capabilities.has_ipv6pktinfo;
        let server_config_profiles =
            make_server_config_profiles(params, &socket_capabilities)?;

        Ok(Config {
            quiche_config: make_quiche_config_with_settings(
                quic_settings,
                params.tls_cert,
                &params.hooks,
                keylog_file.is_some(),
            )?,
            disable_client_ip_validation: quic_settings
                .disable_client_ip_validation,
            qlog_dir: quic_settings.qlog_dir.clone(),
            qlog_compression: quic_settings.qlog_compression,
            has_gso,
            pacing_offload,
            enable_expensive_packet_count_metrics: quic_settings
                .enable_expensive_packet_count_metrics,
            keylog_file,
            listen_backlog: quic_settings.listen_backlog,
            handshake_timeout: quic_settings.handshake_timeout,
            has_ippktinfo,
            has_ipv6pktinfo,
            server_config_profiles,
        })
    }

    pub(crate) fn server_profile_config_mut(
        &mut self, index: Option<usize>,
    ) -> Option<ServerProfileConfigMut<'_>> {
        match index {
            None => Some(ServerProfileConfigMut::Default(self)),
            Some(index) => self
                .server_config_profiles
                .get_mut(index)
                .map(ServerProfileConfigMut::Additional),
        }
    }

    pub(crate) fn server_profile_disable_client_ip_validation(
        &self, index: Option<usize>,
    ) -> Option<bool> {
        match index {
            None => Some(self.disable_client_ip_validation),
            Some(index) => self
                .server_config_profiles
                .get(index)
                .map(|profile| profile.disable_client_ip_validation),
        }
    }
}

pub(crate) struct ServerConnectionConfig {
    pub(crate) pacing_offload: bool,
    pub(crate) handshake_timeout: Option<Duration>,
}

pub(crate) struct ServerProfileSnapshot<'a> {
    pub(crate) qlog_dir: Option<&'a str>,
    pub(crate) qlog_compression: QlogCompression,
    pub(crate) keylog_file: Option<&'a File>,
    pub(crate) connection_config: ServerConnectionConfig,
}

pub(crate) enum ServerProfileConfigMut<'a> {
    Default(&'a mut Config),
    Additional(&'a mut ServerProfileConfig),
}

impl ServerProfileConfigMut<'_> {
    pub(crate) fn snapshot(&self) -> ServerProfileSnapshot<'_> {
        match self {
            Self::Default(config) => ServerProfileSnapshot {
                qlog_dir: config.qlog_dir.as_deref(),
                qlog_compression: config.qlog_compression,
                keylog_file: config.keylog_file.as_ref(),
                connection_config: ServerConnectionConfig {
                    pacing_offload: config.pacing_offload,
                    handshake_timeout: config.handshake_timeout,
                },
            },

            Self::Additional(profile) => ServerProfileSnapshot {
                qlog_dir: profile.qlog_dir.as_deref(),
                qlog_compression: profile.qlog_compression,
                keylog_file: profile.keylog_file.as_ref(),
                connection_config: ServerConnectionConfig {
                    pacing_offload: profile.pacing_offload,
                    handshake_timeout: profile.handshake_timeout,
                },
            },
        }
    }

    pub(crate) fn quiche_config_mut(&mut self) -> &mut quiche::Config {
        match self {
            Self::Default(config) => &mut config.quiche_config,
            Self::Additional(profile) => &mut profile.quiche_config,
        }
    }
}

pub(crate) struct ServerProfileConfig {
    quiche_config: quiche::Config,
    qlog_dir: Option<String>,
    qlog_compression: QlogCompression,
    keylog_file: Option<File>,
    disable_client_ip_validation: bool,
    pacing_offload: bool,
    handshake_timeout: Option<Duration>,
}

fn make_quiche_config_with_settings(
    quic_settings: &QuicSettings, tls_cert: Option<TlsCertificatePaths>,
    hooks: &Hooks, should_log_keys: bool,
) -> QuicResult<quiche::Config> {
    let peer_trust_roots = quic_settings.peer_trust_roots.as_ref();
    let ssl_ctx_builder = hooks
        .connection_hook
        .as_ref()
        .zip(tls_cert)
        .and_then(|(hook, tls)| hook.create_custom_ssl_context_builder(tls));

    let mut peer_trust_roots_applied = false;
    let mut config = if let Some(mut builder) = ssl_ctx_builder {
        apply_peer_trust_roots_to_ssl_builder(&mut builder, peer_trust_roots)?;
        peer_trust_roots_applied = peer_trust_roots.is_some();

        quiche::Config::with_boring_ssl_ctx_builder(
            quiche::PROTOCOL_VERSION,
            builder,
        )?
    } else {
        quiche_config_with_tls(
            tls_cert,
            should_load_system_trust_roots(peer_trust_roots),
        )?
    };

    if !peer_trust_roots_applied {
        apply_peer_trust_roots_to_quiche_config(&mut config, peer_trust_roots)?;
    }

    let alpns: Vec<&[u8]> =
        quic_settings.alpn.iter().map(Vec::as_slice).collect();
    config.set_application_protos(&alpns).unwrap();

    if let Some(timeout) = quic_settings.max_idle_timeout {
        let ms = timeout
            .as_millis()
            .try_into()
            .map_err(|_| "QuicSettings::max_idle_timeout exceeds u64")?;
        config.set_max_idle_timeout(ms);
    }

    config.enable_dgram(
        quic_settings.enable_dgram,
        quic_settings.dgram_recv_max_queue_len,
        quic_settings.dgram_send_max_queue_len,
    );

    config.set_max_recv_udp_payload_size(quic_settings.max_recv_udp_payload_size);
    config.set_max_send_udp_payload_size(quic_settings.max_send_udp_payload_size);
    config.set_initial_max_data(quic_settings.initial_max_data);
    config.set_initial_max_stream_data_bidi_local(
        quic_settings.initial_max_stream_data_bidi_local,
    );
    config.set_initial_max_stream_data_bidi_remote(
        quic_settings.initial_max_stream_data_bidi_remote,
    );
    config.set_initial_max_stream_data_uni(
        quic_settings.initial_max_stream_data_uni,
    );
    config.set_initial_max_streams_bidi(quic_settings.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(quic_settings.initial_max_streams_uni);
    config.set_disable_active_migration(quic_settings.disable_active_migration);
    config
        .set_active_connection_id_limit(quic_settings.active_connection_id_limit);
    config.set_cc_algorithm_name(quic_settings.cc_algorithm.as_str())?;
    config.set_initial_congestion_window_packets(
        quic_settings.initial_congestion_window_packets,
    );
    config.set_enable_relaxed_loss_threshold(
        quic_settings.enable_relaxed_loss_threshold,
    );
    config.discover_pmtu(quic_settings.discover_path_mtu);
    config.set_pmtud_max_probes(quic_settings.pmtud_max_probes);
    config.enable_hystart(quic_settings.enable_hystart);

    config.enable_pacing(quic_settings.enable_pacing);
    if let Some(max_pacing_rate) = quic_settings.max_pacing_rate {
        config.set_max_pacing_rate(max_pacing_rate);
    }

    if quic_settings.verify_peer {
        config.verify_peer(quic_settings.verify_peer);
    }

    config.set_max_connection_window(quic_settings.max_connection_window);
    config.set_max_stream_window(quic_settings.max_stream_window);
    config.set_use_initial_max_data_as_flow_control_win(
        quic_settings.use_initial_max_data_as_fc_window,
    );
    config.set_enable_send_streams_blocked(
        quic_settings.enable_send_streams_blocked,
    );
    config.grease(quic_settings.grease);
    config.set_max_amplification_factor(quic_settings.max_amplification_factor);
    config.set_send_capacity_factor(quic_settings.send_capacity_factor);
    config.set_ack_delay_exponent(quic_settings.ack_delay_exponent);
    config.set_max_ack_delay(quic_settings.max_ack_delay);
    config.set_path_challenge_recv_max_queue_len(
        quic_settings.max_path_challenge_recv_queue_len,
    );
    config.set_stateless_reset_token(quic_settings.stateless_reset_token);
    config.set_disable_dcid_reuse(quic_settings.disable_dcid_reuse);

    if let Some(track_unknown_transport_params) =
        quic_settings.track_unknown_transport_parameters
    {
        config.enable_track_unknown_transport_parameters(
            track_unknown_transport_params,
        );
    }
    if quic_settings.enable_early_data {
        config.enable_early_data();
    }

    if should_log_keys {
        config.log_keys();
    }

    Ok(config)
}

fn make_server_config_profiles(
    params: &ConnectionParams, socket_capabilities: &SocketCapabilities,
) -> QuicResult<Vec<ServerProfileConfig>> {
    let mut profiles = Vec::with_capacity(params.server_config_profiles.len());

    for profile in &params.server_config_profiles {
        let mut settings = params.settings.clone();
        profile.apply_to(&mut settings);

        let keylog_file =
            make_keylog_file(&settings, profile.keylog_file.is_none());
        let disable_client_ip_validation = settings.disable_client_ip_validation;
        let quiche_config = make_quiche_config_with_settings(
            &settings,
            profile.tls_cert.or(params.tls_cert),
            &params.hooks,
            keylog_file.is_some(),
        )?;
        let pacing_offload = make_pacing_offload(&settings, socket_capabilities);
        let handshake_timeout = settings.handshake_timeout;

        profiles.push(ServerProfileConfig {
            quiche_config,
            qlog_dir: settings.qlog_dir,
            qlog_compression: settings.qlog_compression,
            keylog_file,
            disable_client_ip_validation,
            pacing_offload,
            handshake_timeout,
        });
    }

    Ok(profiles)
}

fn make_keylog_file(
    quic_settings: &QuicSettings, use_env_fallback: bool,
) -> Option<File> {
    let keylog_path = match &quic_settings.keylog_file {
        Some(f) => Some(Cow::Borrowed(f.as_ref())),
        None if use_env_fallback =>
            std::env::var_os("SSLKEYLOGFILE").map(Cow::from),
        None => None,
    };

    keylog_path.and_then(|path| {
        if KEYLOGFILE_ENABLED {
            File::options().create(true).append(true).open(path)
                .inspect_err(|e| log::warn!("failed to open SSLKEYLOGFILE"; "error" => e))
                .ok()
        } else {
            log::warn!("SSLKEYLOGFILE is set, but `--cfg capture_keylogs` was not enabled. No keys will be logged.");
            None
        }
    })
}

fn make_pacing_offload(
    quic_settings: &QuicSettings, socket_capabilities: &SocketCapabilities,
) -> bool {
    let pacing_offload = socket_capabilities.has_txtime;

    #[cfg(feature = "gcongestion")]
    let pacing_offload = quic_settings.enable_pacing && pacing_offload;

    #[cfg(not(feature = "gcongestion"))]
    let _ = quic_settings;

    pacing_offload
}

fn quiche_config_with_tls(
    tls_cert: Option<TlsCertificatePaths>, load_system_trust_roots: bool,
) -> QuicResult<quiche::Config> {
    let Some(tls) = tls_cert else {
        return quiche_config(load_system_trust_roots);
    };

    match tls.kind {
        #[cfg(not(feature = "rpk"))]
        CertificateKind::RawPublicKey => {
            // TODO: don't compile this enum variant unless rpk feature is enabled
            panic!("Can't use RPK when compiled without rpk feature");
        },
        #[cfg(feature = "rpk")]
        CertificateKind::RawPublicKey => {
            let mut ssl_ctx_builder = boring::ssl::SslContextBuilder::new_rpk()?;
            let raw_public_key = read_file(tls.cert)?;
            ssl_ctx_builder.set_rpk_certificate(&raw_public_key)?;

            let raw_private_key = read_file(tls.private_key)?;
            let pkey =
                boring::pkey::PKey::private_key_from_pem(&raw_private_key)?;
            ssl_ctx_builder.set_null_chain_private_key(&pkey)?;

            Ok(quiche::Config::with_boring_ssl_ctx_builder(
                quiche::PROTOCOL_VERSION,
                ssl_ctx_builder,
            )?)
        },
        CertificateKind::X509 => {
            let mut config = quiche_config(load_system_trust_roots)?;
            config.load_cert_chain_from_pem_file(tls.cert)?;
            config.load_priv_key_from_pem_file(tls.private_key)?;
            Ok(config)
        },
    }
}

fn quiche_config(load_system_trust_roots: bool) -> QuicResult<quiche::Config> {
    if load_system_trust_roots {
        return Ok(quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap());
    }

    let builder =
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())?;

    Ok(quiche::Config::with_boring_ssl_ctx_builder(
        quiche::PROTOCOL_VERSION,
        builder,
    )?)
}

fn should_load_system_trust_roots(
    peer_trust_roots: Option<&PeerTrustRoots>,
) -> bool {
    !matches!(
        peer_trust_roots,
        Some(PeerTrustRoots::CustomFile(roots))
            if !roots.include_system_roots
    )
}

fn apply_peer_trust_roots_to_quiche_config(
    config: &mut quiche::Config, peer_trust_roots: Option<&PeerTrustRoots>,
) -> QuicResult<()> {
    if let Some(PeerTrustRoots::CustomFile(roots)) = peer_trust_roots {
        config.load_verify_locations_from_file(&roots.path)?;
    }

    Ok(())
}

fn apply_peer_trust_roots_to_ssl_builder(
    builder: &mut boring::ssl::SslContextBuilder,
    peer_trust_roots: Option<&PeerTrustRoots>,
) -> QuicResult<()> {
    match peer_trust_roots {
        None => {},

        Some(PeerTrustRoots::System) => {
            builder.set_default_verify_paths()?;
        },

        Some(PeerTrustRoots::CustomFile(roots)) => {
            if roots.include_system_roots {
                builder.set_default_verify_paths()?;
            }

            builder.set_ca_file(&roots.path)?;
        },
    }

    Ok(())
}

#[cfg(feature = "rpk")]
fn read_file(path: &str) -> QuicResult<Vec<u8>> {
    use anyhow::Context as _;
    std::fs::read(path)
        .with_context(|| format!("read {path}"))
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::settings::ConnectionParams;
    use crate::settings::ServerConfigOverrides;
    use crate::socket::SocketCapabilities;
    use std::time::Duration;

    #[test]
    fn server_config_profiles_apply_overrides() {
        let mut params = ConnectionParams::default();
        params.server_config_profiles.push(ServerConfigOverrides {
            qlog_dir: Some(Some("/tmp/tokio-quiche-qlog".to_string())),
            handshake_timeout: Some(Some(Duration::from_secs(7))),
            disable_client_ip_validation: Some(true),
            max_amplification_factor: Some(10),
            verify_peer: Some(true),
            ..Default::default()
        });

        let mut config =
            Config::new(&params, SocketCapabilities::default()).unwrap();
        let profile = config.server_profile_config_mut(Some(0)).unwrap();
        let snapshot = profile.snapshot();

        assert_eq!(snapshot.qlog_dir.as_deref(), Some("/tmp/tokio-quiche-qlog"));
        assert_eq!(
            snapshot.connection_config.handshake_timeout,
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            config.server_profile_disable_client_ip_validation(Some(0)),
            Some(true)
        );
    }

    #[test]
    fn server_config_profiles_default_index_uses_base_settings() {
        let mut params = ConnectionParams::default();
        params.settings.disable_client_ip_validation = true;

        let config = Config::new(&params, SocketCapabilities::default()).unwrap();

        assert_eq!(
            config.server_profile_disable_client_ip_validation(None),
            Some(true)
        );
    }

    #[test]
    fn server_config_profiles_unknown_index_is_absent() {
        let mut params = ConnectionParams::default();
        params
            .server_config_profiles
            .push(ServerConfigOverrides::default());

        let config = Config::new(&params, SocketCapabilities::default()).unwrap();

        assert_eq!(
            config.server_profile_disable_client_ip_validation(Some(1)),
            None
        );
    }
}
