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

//! Configuration for QUIC connections.

mod config;
mod hooks;
mod overrides;
mod quic;
mod tls;

pub(crate) use self::config::*;

pub use self::hooks::*;
pub use self::overrides::*;
pub use self::quic::*;
pub use self::tls::*;

/// Combined configuration parameters required to establish a QUIC connection.
///
/// [`ConnectionParams`] aggregates the parameters required for all QUIC
/// connections, regardless of whether it's a client- or server-side connection.
/// To construct them, either `ConnectionParams::new_server` or
/// `ConnectionParams::new_client` must be used. The parameters can be modified
/// freely after construction.
#[derive(Default)]
#[non_exhaustive] // force use of constructor functions
pub struct ConnectionParams<'a> {
    /// QUIC connection settings.
    pub settings: QuicSettings,
    /// Optional TLS credentials to authenticate with.
    pub tls_cert: Option<TlsCertificatePaths<'a>>,
    /// Hooks to use for the connection.
    pub hooks: Hooks,
    /// Additional server config profiles available for server connections.
    ///
    /// The default profile is built from [`settings`](Self::settings) and
    /// [`tls_cert`](Self::tls_cert). Additional profiles inherit those values
    /// unless their profile overrides replace them.
    pub server_config_profiles: Vec<ServerConfigOverrides<'a>>,
    /// Set the session to attempt resumption.
    pub session: Option<Vec<u8>>,
    /// Raw QUIC DATAGRAM payloads to send as 0-RTT data on client connections.
    ///
    /// These payloads are sent before [`connect_with_config()`] returns, but
    /// the function still only resolves after the QUIC handshake has
    /// completed. A resumption session and early data support are required.
    ///
    /// [`connect_with_config()`]: crate::quic::connect_with_config
    pub zero_rtt_dgrams: Vec<Vec<u8>>,
    /// Data to send on client-initiated bidirectional streams as 0-RTT data on
    /// client connections.
    ///
    /// Stream IDs are assigned by the entry's index in this vector. Use
    /// [`ConnectionParams::zero_rtt_stream_id()`] to map an index to the
    /// stream ID that applications should read or write.
    ///
    /// These payloads are sent before [`connect_with_config()`] returns, but
    /// the function still only resolves after the QUIC handshake has
    /// completed. A resumption session and early data support are required.
    ///
    /// [`connect_with_config()`]: crate::quic::connect_with_config
    pub zero_rtt_streams: Vec<ZeroRttStream>,
    /// Custom destination connection ID to use for client connections.
    ///
    /// Be aware that [RFC 9000] places requirements for unpredictability and
    /// length on the client DCID field. Setting this field is dangerous if
    /// these requirements are not satisfied.
    ///
    /// Has no effect on server-side [`ConnectionParams`].
    ///
    /// [RFC 9000]: <https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-3>
    #[cfg(feature = "custom-client-dcid")]
    pub dcid: Option<quiche::ConnectionId<'static>>,
}

impl core::fmt::Debug for ConnectionParams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid printing 'session' since it contains connection secrets.
        let mut s = f.debug_struct("ConnectionParams");
        s.field("settings", &self.settings)
            .field("tls_cert", &self.tls_cert)
            .field("hooks", &self.hooks)
            .field("server_config_profiles", &self.server_config_profiles);

        #[cfg(feature = "custom-client-dcid")]
        s.field("dcid", &self.dcid);

        s.finish()
    }
}

impl<'a> ConnectionParams<'a> {
    /// Creates [`ConnectionParams`] for a QUIC server.
    /// Servers should always specify TLS credentials.
    #[inline]
    pub fn new_server(
        settings: QuicSettings, tls_cert: TlsCertificatePaths<'a>, hooks: Hooks,
    ) -> Self {
        Self {
            settings,
            tls_cert: Some(tls_cert),
            hooks,
            server_config_profiles: Vec::new(),
            session: None,
            zero_rtt_dgrams: Vec::new(),
            zero_rtt_streams: Vec::new(),
            #[cfg(feature = "custom-client-dcid")]
            dcid: None,
        }
    }

    /// Creates [`ConnectionParams`] for a QUIC client.
    /// Clients may enable mTLS by specifying TLS credentials.
    #[inline]
    pub fn new_client(
        settings: QuicSettings, tls_cert: Option<TlsCertificatePaths<'a>>,
        hooks: Hooks,
    ) -> Self {
        Self {
            settings,
            tls_cert,
            hooks,
            server_config_profiles: Vec::new(),
            session: None,
            zero_rtt_dgrams: Vec::new(),
            zero_rtt_streams: Vec::new(),
            #[cfg(feature = "custom-client-dcid")]
            dcid: None,
        }
    }

    /// Returns the stream ID used for the configured 0-RTT stream at `index`.
    ///
    /// Applications can use this to map `zero_rtt_streams[index]` to the stream
    /// that carries the server's response.
    pub fn zero_rtt_stream_id(index: usize) -> Option<u64> {
        const MAX_ZERO_RTT_STREAM_INDEX: u64 = 1 << 60;

        let index = u64::try_from(index).ok()?;

        if index >= MAX_ZERO_RTT_STREAM_INDEX {
            return None;
        }

        Some(index << 2)
    }
}

/// Data to send on a predictable 0-RTT stream.
#[derive(Clone, Debug, Default)]
pub struct ZeroRttStream {
    /// Payload to write on the stream.
    pub data: Vec<u8>,

    /// Whether to finish the stream after writing `data`.
    pub fin: bool,
}
