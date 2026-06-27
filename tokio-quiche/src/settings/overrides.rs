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

use std::time::Duration;

use qlog::writer::QlogCompression;

use super::QuicSettings;
use super::TlsCertificatePaths;

/// Optional per-profile server config overrides.
///
/// Fields that quiche can already adjust during the handshake are intentionally
/// excluded. Use these overrides for values that must be fixed before creating
/// the server-side [`quiche::Connection`], such as TLS peer verification,
/// transport parameters, and per-connection observability.
#[derive(Clone, Debug, Default)]
pub struct ServerConfigOverrides<'a> {
    /// Optional TLS credentials for this profile.
    ///
    /// If unset, the profile inherits the listener's TLS credentials.
    pub tls_cert: Option<TlsCertificatePaths<'a>>,
    /// Overrides whether client IP validation is disabled.
    ///
    /// When set to `true`, Initial packets can immediately create a connection.
    /// When set to `false`, clients must pass stateless retry before the
    /// connection is accepted.
    pub disable_client_ip_validation: Option<bool>,

    /// Overrides the supported application protocols.
    pub alpn: Option<Vec<Vec<u8>>>,

    /// Overrides whether DATAGRAM frame support is enabled.
    pub enable_dgram: Option<bool>,

    /// Overrides the maximum received DATAGRAM queue length.
    pub dgram_recv_max_queue_len: Option<usize>,

    /// Overrides the maximum sent DATAGRAM queue length.
    pub dgram_send_max_queue_len: Option<usize>,

    /// Overrides whether early data is enabled.
    pub enable_early_data: Option<bool>,

    /// Overrides the `initial_max_data` transport parameter.
    pub initial_max_data: Option<u64>,

    /// Overrides the `initial_max_stream_data_bidi_local` transport parameter.
    pub initial_max_stream_data_bidi_local: Option<u64>,

    /// Overrides the `initial_max_stream_data_bidi_remote` transport parameter.
    pub initial_max_stream_data_bidi_remote: Option<u64>,

    /// Overrides the `initial_max_stream_data_uni` transport parameter.
    pub initial_max_stream_data_uni: Option<u64>,

    /// Overrides the `initial_max_streams_uni` transport parameter.
    pub initial_max_streams_uni: Option<u64>,

    /// Overrides whether active connection migration is disabled.
    pub disable_active_migration: Option<bool>,

    /// Overrides the active connection ID limit.
    pub active_connection_id_limit: Option<u64>,

    /// Overrides the maximum incoming UDP payload size.
    pub max_recv_udp_payload_size: Option<usize>,

    /// Overrides the maximum number of PMTUD probes.
    pub pmtud_max_probes: Option<u8>,

    /// Overrides whether to verify the peer's certificate.
    pub verify_peer: Option<bool>,

    /// Overrides the maximum connection flow control window.
    pub max_connection_window: Option<u64>,

    /// Overrides the maximum stream flow control window.
    pub max_stream_window: Option<u64>,

    /// Overrides whether advisory STREAMS_BLOCKED frames are enabled.
    pub enable_send_streams_blocked: Option<bool>,

    /// Overrides whether to send GREASE values.
    pub grease: Option<bool>,

    /// Overrides the anti-amplification limit factor.
    pub max_amplification_factor: Option<usize>,

    /// Overrides the `ack_delay_exponent` transport parameter.
    pub ack_delay_exponent: Option<u64>,

    /// Overrides the `max_ack_delay` transport parameter.
    pub max_ack_delay: Option<u64>,

    /// Overrides the maximum queued PATH_CHALLENGE frame count.
    pub max_path_challenge_recv_queue_len: Option<usize>,

    /// Overrides the initial stateless reset token.
    pub stateless_reset_token: Option<Option<u128>>,

    /// Overrides whether DCID reuse is disabled.
    pub disable_dcid_reuse: Option<bool>,

    /// Overrides unknown transport parameter tracking.
    pub track_unknown_transport_parameters: Option<Option<usize>>,

    /// Overrides the QLOG output directory.
    pub qlog_dir: Option<Option<String>>,

    /// Overrides the QLOG output compression.
    pub qlog_compression: Option<QlogCompression>,

    /// Overrides the TLS keylog file path.
    pub keylog_file: Option<Option<String>>,

    /// Overrides the QUIC handshake timeout.
    pub handshake_timeout: Option<Option<Duration>>,
}

impl<'a> ServerConfigOverrides<'a> {
    pub(crate) fn apply_to(&self, settings: &mut QuicSettings) {
        apply_override(
            &mut settings.disable_client_ip_validation,
            &self.disable_client_ip_validation,
        );
        apply_override(&mut settings.alpn, &self.alpn);
        apply_override(&mut settings.enable_dgram, &self.enable_dgram);
        apply_override(
            &mut settings.dgram_recv_max_queue_len,
            &self.dgram_recv_max_queue_len,
        );
        apply_override(
            &mut settings.dgram_send_max_queue_len,
            &self.dgram_send_max_queue_len,
        );
        apply_override(&mut settings.enable_early_data, &self.enable_early_data);
        apply_override(&mut settings.initial_max_data, &self.initial_max_data);
        apply_override(
            &mut settings.initial_max_stream_data_bidi_local,
            &self.initial_max_stream_data_bidi_local,
        );
        apply_override(
            &mut settings.initial_max_stream_data_bidi_remote,
            &self.initial_max_stream_data_bidi_remote,
        );
        apply_override(
            &mut settings.initial_max_stream_data_uni,
            &self.initial_max_stream_data_uni,
        );
        apply_override(
            &mut settings.initial_max_streams_uni,
            &self.initial_max_streams_uni,
        );
        apply_override(
            &mut settings.disable_active_migration,
            &self.disable_active_migration,
        );
        apply_override(
            &mut settings.active_connection_id_limit,
            &self.active_connection_id_limit,
        );
        apply_override(
            &mut settings.max_recv_udp_payload_size,
            &self.max_recv_udp_payload_size,
        );
        apply_override(&mut settings.pmtud_max_probes, &self.pmtud_max_probes);
        apply_override(&mut settings.verify_peer, &self.verify_peer);
        apply_override(
            &mut settings.max_connection_window,
            &self.max_connection_window,
        );
        apply_override(&mut settings.max_stream_window, &self.max_stream_window);
        apply_override(
            &mut settings.enable_send_streams_blocked,
            &self.enable_send_streams_blocked,
        );
        apply_override(&mut settings.grease, &self.grease);
        apply_override(
            &mut settings.max_amplification_factor,
            &self.max_amplification_factor,
        );
        apply_override(
            &mut settings.ack_delay_exponent,
            &self.ack_delay_exponent,
        );
        apply_override(&mut settings.max_ack_delay, &self.max_ack_delay);
        apply_override(
            &mut settings.max_path_challenge_recv_queue_len,
            &self.max_path_challenge_recv_queue_len,
        );
        apply_override(
            &mut settings.stateless_reset_token,
            &self.stateless_reset_token,
        );
        apply_override(
            &mut settings.disable_dcid_reuse,
            &self.disable_dcid_reuse,
        );
        apply_override(
            &mut settings.track_unknown_transport_parameters,
            &self.track_unknown_transport_parameters,
        );
        apply_override(&mut settings.qlog_dir, &self.qlog_dir);
        apply_override(&mut settings.qlog_compression, &self.qlog_compression);
        apply_override(&mut settings.keylog_file, &self.keylog_file);
        apply_override(&mut settings.handshake_timeout, &self.handshake_timeout);
    }
}

fn apply_override<T: Clone>(target: &mut T, value: &Option<T>) {
    if let Some(value) = value {
        *target = value.clone();
    }
}
