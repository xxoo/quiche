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

use crate::settings::TlsCertificatePaths;
use boring::ssl::SslContextBuilder;
use quiche::ConnectionId;
use std::net::SocketAddr;

/// Client information available while handling an Initial packet.
///
/// This information is intentionally limited to data that is available before
/// creating the server-side [`quiche::Connection`]. TLS and HTTP/3 information
/// such as SNI, ALPN, peer certificates, and request headers are not available
/// at this point.
pub struct ClientInitialInfo<'a> {
    /// The address that sent the Initial packet.
    pub peer_addr: SocketAddr,

    /// The local address that received the Initial packet.
    pub local_addr: SocketAddr,

    /// The QUIC version from the packet header.
    pub version: u32,

    /// The source connection ID from the packet header.
    pub scid: &'a ConnectionId<'a>,

    /// The destination connection ID from the packet header.
    pub dcid: &'a ConnectionId<'a>,

    /// Whether the Initial packet carried a non-empty token.
    pub token_present: bool,
}

/// A set of hooks executed at the level of a [quiche::Connection].
pub trait ConnectionHook {
    /// Constructs an optional [`SslContextBuilder`].
    ///
    /// This method allows full customization of quiche's SSL context, for
    /// example to specify async callbacks during the QUIC handshake. It is
    /// called once for the default profile during initial setup, and once for
    /// each additional server config profile.
    ///
    /// Only called if both the hook and [`TlsCertificatePaths`] are set in
    /// [`ConnectionParams`](crate::ConnectionParams).
    fn create_custom_ssl_context_builder(
        &self, settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder>;

    /// Selects a server config profile for an Initial packet.
    ///
    /// Returning `None` selects the default server config profile.
    fn select_server_config_profile(
        &self, _info: &ClientInitialInfo<'_>,
    ) -> Option<usize> {
        None
    }
}
