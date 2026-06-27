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

use datagram_socket::DatagramSocketRecv;
use datagram_socket::DatagramSocketSend;
use futures_util::task::AtomicWaker;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Poll;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

#[derive(Debug)]
struct MigratableUdpSocketInner {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

/// A connected UDP socket wrapper whose underlying socket can be replaced.
#[derive(Clone, Debug)]
pub(crate) struct MigratableUdpSocket {
    inner: Arc<Mutex<MigratableUdpSocketInner>>,
    recv_waker: Arc<AtomicWaker>,
}

impl MigratableUdpSocket {
    pub(crate) fn new(socket: UdpSocket) -> io::Result<Self> {
        let local_addr = socket.local_addr()?;
        let peer_addr = socket.peer_addr()?;

        Ok(Self {
            inner: Arc::new(Mutex::new(MigratableUdpSocketInner {
                socket: Arc::new(socket),
                local_addr,
                peer_addr,
            })),
            recv_waker: Arc::new(AtomicWaker::new()),
        })
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.inner.lock().unwrap().local_addr
    }

    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.inner.lock().unwrap().peer_addr
    }

    pub(crate) fn replace(
        &self, socket: UdpSocket, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> io::Result<SocketAddr> {
        let mut inner = self.inner.lock().unwrap();

        if peer_addr != inner.peer_addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "migrated UDP socket peer address changed",
            ));
        }

        let previous_local_addr = inner.local_addr;
        inner.socket = Arc::new(socket);
        inner.local_addr = local_addr;
        inner.peer_addr = peer_addr;

        drop(inner);
        self.recv_waker.wake();

        Ok(previous_local_addr)
    }

    fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.inner.lock().unwrap().socket)
    }
}

impl DatagramSocketSend for MigratableUdpSocket {
    #[inline]
    fn poll_send(
        &self, cx: &mut std::task::Context, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.socket().poll_send(cx, buf)
    }

    #[inline]
    fn poll_send_to(
        &self, cx: &mut std::task::Context, buf: &[u8], addr: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.socket().poll_send_to(cx, buf, addr)
    }

    #[inline]
    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(self.peer_addr())
    }
}

impl DatagramSocketRecv for MigratableUdpSocket {
    #[inline]
    fn poll_recv(
        &mut self, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.recv_waker.register(cx.waker());
        self.socket().poll_recv(cx, buf)
    }

    #[inline]
    fn poll_recv_from(
        &mut self, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.recv_waker.register(cx.waker());
        self.socket().poll_recv_from(cx, buf)
    }
}
