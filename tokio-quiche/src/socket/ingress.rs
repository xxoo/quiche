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

//! Linux UDP writers shared by paths on the same listener and interface.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;

use nix::sys::socket::setsockopt;
use nix::sys::socket::sockopt;
use socket2::Domain;
use socket2::Protocol;
use socket2::SockRef;
use socket2::Socket;
use socket2::Type;
use tokio::net::UdpSocket;

use super::capabilities::SocketCapabilitiesBuilder;

/// Only the listener owns the receive side. A writer reserves the listener's
/// UDP source port on a multicast address: it cannot intercept any unicast
/// QUIC packet, and IP_PKTINFO supplies the actual unicast source per send.
/// The strong device binding is needed even with IPV6_PKTINFO: a policy table
/// can otherwise select a different IPv6 interface.
#[derive(Debug)]
pub(crate) struct ReplySockets {
    port: u16,
    gso: bool,
    txtime: bool,
    sockets: Mutex<HashMap<(bool, NonZeroU32), Weak<UdpSocket>>>,
}

impl ReplySockets {
    pub(crate) fn prepare(
        socket: &UdpSocket, gso: bool, txtime: bool,
    ) -> io::Result<Self> {
        let local = socket.local_addr()?;
        let socket = SockRef::from(socket);
        socket.set_reuse_port(true)?;
        if local.is_ipv4() || !socket.only_v6()? {
            setsockopt(&*socket, sockopt::Ipv4PacketInfo, &true)?;
        }
        if local.is_ipv6() {
            setsockopt(&*socket, sockopt::Ipv6RecvPacketInfo, &true)?;
        }
        Ok(Self {
            port: local.port(),
            gso,
            txtime,
            sockets: Mutex::default(),
        })
    }

    pub(crate) fn writer(
        &self, addr: SocketAddr, index: NonZeroU32,
    ) -> io::Result<Arc<UdpSocket>> {
        let v4 = addr.ip().to_canonical().is_ipv4();
        let mut sockets = self.sockets.lock().unwrap();
        if let Some(socket) = sockets.get(&(v4, index)).and_then(Weak::upgrade) {
            return Ok(socket);
        }
        sockets.retain(|_, socket| socket.strong_count() != 0);
        let socket = self.open_socket(v4, index).map_err(|error| io::Error::new(
            error.kind(), format!("QUIC ingress reply path unavailable on interface {index} for {addr}: {error}"),
        ))?;
        let socket = Arc::new(socket);
        sockets.insert((v4, index), Arc::downgrade(&socket));
        Ok(socket)
    }

    fn open_socket(&self, v4: bool, index: NonZeroU32) -> io::Result<UdpSocket> {
        let socket = Socket::new(
            if v4 { Domain::IPV4 } else { Domain::IPV6 },
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        socket.set_reuse_port(true)?;
        // On Linux SO_BINDTOIFINDEX applies to either family.
        socket.bind_device_by_index_v4(Some(index))?;
        let anchor = if v4 {
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(239, 255, 0, 1),
                self.port,
            ))
        } else {
            socket.set_only_v6(true)?;
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from([0xff12, 0, 0, 0, 0, 0, 0, 1]),
                self.port,
                0,
                index.get(),
            ))
        };
        socket.bind(&anchor.into())?;
        let mut caps = SocketCapabilitiesBuilder::new(&socket);
        if self.gso {
            caps.gso()?;
        }
        if self.txtime {
            caps.txtime()?;
        }
        if v4 {
            caps.ip_mtu_discover_probe()?;
        } else {
            caps.ipv6_mtu_discover_probe()?;
        }
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }
}
