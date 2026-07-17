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

use super::Incoming;
use super::InitialQuicConnection;
use super::RouteOwner;
use crate::metrics::Metrics;
use crate::quic::hooks::peer_ip_matches;

use datagram_socket::DatagramSocketSend;
use quiche::ConnectionId;
use quiche::MAX_CONN_ID_LEN;
use std::collections::BTreeMap;
use std::net::IpAddr;
use tokio::sync::mpsc;

const U64_SZ: usize = std::mem::size_of::<u64>();
const MAX_CONN_ID_QUADS: usize = MAX_CONN_ID_LEN.div_ceil(U64_SZ);
const CONN_ID_USABLE_LEN: usize = min_usize(
    // Last byte in CidOwned::Optimized stores CID length
    MAX_CONN_ID_QUADS * U64_SZ - 1,
    // CID length must fit in 1 byte
    min_usize(MAX_CONN_ID_LEN, u8::MAX as _),
);

const fn min_usize(v1: usize, v2: usize) -> usize {
    if v1 < v2 {
        v1
    } else {
        v2
    }
}

/// A non unique connection identifier, multiple Cids can map to the same
/// conenction.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum CidOwned {
    /// The QUIC connections IDs theoretically have unbounded length, so for the
    /// generic case a boxed slice is used to store the ID.
    Generic(Box<[u8]>),
    /// For QUIC version 1 (the one that actually exists) the maximal ID size is
    /// `20`, which should correspond to the `MAX_CONN_ID_LEN` value. For
    /// this common case, we store the ID in a u64 array for faster
    /// comparison (and therefore BTreeMap lookups).
    Optimized([u64; MAX_CONN_ID_QUADS]),
}

impl From<&ConnectionId<'_>> for CidOwned {
    #[inline(always)]
    fn from(value: &ConnectionId<'_>) -> Self {
        if value.len() > CONN_ID_USABLE_LEN {
            return CidOwned::Generic(value.as_ref().into());
        }

        let mut cid = [0; MAX_CONN_ID_QUADS];

        value
            .chunks(U64_SZ)
            .map(|c| match c.try_into() {
                Ok(v) => u64::from_le_bytes(v),
                Err(_) => {
                    let mut remainder = [0u8; U64_SZ];
                    remainder[..c.len()].copy_from_slice(c);
                    u64::from_le_bytes(remainder)
                },
            })
            .enumerate()
            .for_each(|(i, v)| cid[i] = v);

        // In order to differentiate cids with zeroes as opposed to shorter cids,
        // append the cid length.
        *cid.last_mut().unwrap() |= (value.len() as u64) << 56;

        CidOwned::Optimized(cid)
    }
}

/// A map for QUIC connections.
///
/// Due to the fact that QUIC connections can be identified by multiple QUIC
/// connection IDs, we have to be able to map multiple IDs to the same
/// connection.
#[derive(Default)]
pub(crate) struct ConnectionMap {
    quic_id_map: BTreeMap<CidOwned, RoutedConnection>,
}

#[derive(Clone)]
pub(crate) struct RoutedConnection {
    owner: RouteOwner,
    sender: mpsc::Sender<Incoming>,
    fixed_peer_ip: Option<IpAddr>,
}

impl RoutedConnection {
    pub(crate) fn enqueue(&self, incoming: Incoming) {
        if peer_ip_matches(self.fixed_peer_ip, incoming.peer_addr.ip()) {
            let _ = self.sender.try_send(incoming);
        }
    }
}

impl ConnectionMap {
    pub(crate) fn insert<Tx, M>(
        &mut self, owner: &RouteOwner, cid: &ConnectionId<'_>,
        conn: &InitialQuicConnection<Tx, M>,
    ) -> bool
    where
        Tx: DatagramSocketSend + Send + 'static,
        M: Metrics,
    {
        let cid = cid.into();
        if self
            .quic_id_map
            .get(&cid)
            .is_some_and(|connection| !connection.owner.matches(owner))
        {
            return false;
        }
        self.quic_id_map.insert(cid, RoutedConnection {
            owner: owner.clone(),
            sender: conn.incoming_ev_sender.clone(),
            fixed_peer_ip: conn.fixed_peer_ip(),
        });
        true
    }

    pub(crate) fn map_cid(
        &mut self, owner: &RouteOwner, existing_cid: &ConnectionId<'_>,
        new_cid: &ConnectionId<'_>,
    ) -> bool {
        let new_cid = new_cid.into();
        // A duplicate target is a collision even when it already belongs to
        // this owner. Treating it as success could let the worker attempt to
        // register the same quiche CID with a different reset token and then
        // unmap the still-live route when that registration fails.
        if self.quic_id_map.contains_key(&new_cid) {
            return false;
        }
        if let Some(connection) = self
            .quic_id_map
            .get(&existing_cid.into())
            .filter(|connection| connection.owner.matches(owner))
        {
            self.quic_id_map.insert(new_cid, connection.clone());
            true
        } else {
            false
        }
    }

    pub(crate) fn unmap_cid(
        &mut self, owner: &RouteOwner, cid: &ConnectionId<'_>,
    ) {
        let cid = cid.into();
        if self
            .quic_id_map
            .get(&cid)
            .is_some_and(|connection| connection.owner.matches(owner))
        {
            self.quic_id_map.remove(&cid);
        }
    }

    pub(crate) fn get(&self, id: &ConnectionId) -> Option<&RoutedConnection> {
        if id.len() == MAX_CONN_ID_LEN {
            // Although both branches run the same code, the one here will
            // generate an optimized version for the length we are
            // using, as opposed to temporary cids sent by clients.
            self.quic_id_map.get(&id.into())
        } else {
            self.quic_id_map.get(&id.into())
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.quic_id_map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::ConnectionId;
    use std::net::SocketAddr;

    fn incoming(peer_addr: &str) -> Incoming {
        Incoming {
            peer_addr: peer_addr.parse().unwrap(),
            local_addr: "192.0.2.1:443".parse().unwrap(),
            rx_time: None,
            buf: vec![1],
            gro: None,
            #[cfg(target_os = "linux")]
            so_mark_data: None,
        }
    }

    #[test]
    fn cid_storage() {
        let max_v1_cid = ConnectionId::from_ref(&[0xfa; MAX_CONN_ID_LEN]);
        let optimized = CidOwned::from(&max_v1_cid);
        assert!(
            matches!(optimized, CidOwned::Optimized(_)),
            "QUIC v1 CID is not stored inline"
        );

        let oversize_cid = ConnectionId::from_ref(&[0x1b; MAX_CONN_ID_LEN + 20]);
        let boxed = CidOwned::from(&oversize_cid);
        assert!(
            matches!(boxed, CidOwned::Generic(_)),
            "Oversized CID is not boxed"
        );
    }

    #[test]
    fn fixed_peer_ip_is_filtered_before_the_connection_queue() {
        let (sender, mut receiver) = mpsc::channel(2);
        let route = RoutedConnection {
            owner: RouteOwner::new(),
            sender,
            fixed_peer_ip: Some("192.0.2.2".parse().unwrap()),
        };

        route.enqueue(incoming("192.0.2.3:1234"));
        assert!(receiver.try_recv().is_err());

        route.enqueue(incoming("[::ffff:192.0.2.2]:5678"));
        assert_eq!(
            receiver.try_recv().unwrap().peer_addr,
            "[::ffff:192.0.2.2]:5678".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn stale_owner_cannot_unmap_or_extend_reused_cid() {
        let (sender, _receiver) = mpsc::channel(1);
        let stale_owner = RouteOwner::new();
        let current_owner = RouteOwner::new();
        let existing_cid = ConnectionId::from_ref(b"reused");
        let new_cid = ConnectionId::from_ref(b"new");
        let mut map = ConnectionMap::default();
        map.quic_id_map
            .insert((&existing_cid).into(), RoutedConnection {
                owner: current_owner.clone(),
                sender,
                fixed_peer_ip: None,
            });

        assert!(!map.map_cid(&stale_owner, &existing_cid, &new_cid));
        map.unmap_cid(&stale_owner, &existing_cid);
        assert!(map.get(&existing_cid).is_some());
        assert!(map.get(&new_cid).is_none());

        assert!(map.map_cid(&current_owner, &existing_cid, &new_cid));
        assert!(map.get(&new_cid).is_some());
        map.unmap_cid(&current_owner, &existing_cid);
        assert!(map.get(&existing_cid).is_none());
    }

    #[test]
    fn delayed_map_cannot_overwrite_target_owned_by_another_connection() {
        let (sender, _receiver) = mpsc::channel(1);
        let delayed_owner = RouteOwner::new();
        let target_owner = RouteOwner::new();
        let existing_cid = ConnectionId::from_ref(b"existing");
        let target_cid = ConnectionId::from_ref(b"target");
        let mut map = ConnectionMap::default();
        map.quic_id_map
            .insert((&existing_cid).into(), RoutedConnection {
                owner: delayed_owner.clone(),
                sender: sender.clone(),
                fixed_peer_ip: None,
            });
        map.quic_id_map
            .insert((&target_cid).into(), RoutedConnection {
                owner: target_owner.clone(),
                sender,
                fixed_peer_ip: None,
            });

        assert!(!map.map_cid(&delayed_owner, &existing_cid, &target_cid));
        assert!(map.get(&target_cid).unwrap().owner.matches(&target_owner));
    }

    #[test]
    fn duplicate_target_from_same_owner_is_a_collision() {
        let (sender, _receiver) = mpsc::channel(1);
        let owner = RouteOwner::new();
        let existing_cid = ConnectionId::from_ref(b"existing");
        let target_cid = ConnectionId::from_ref(b"target");
        let mut map = ConnectionMap::default();
        for cid in [&existing_cid, &target_cid] {
            map.quic_id_map.insert(cid.into(), RoutedConnection {
                owner: owner.clone(),
                sender: sender.clone(),
                fixed_peer_ip: None,
            });
        }

        assert!(!map.map_cid(&owner, &existing_cid, &target_cid));
        assert!(map.get(&existing_cid).unwrap().owner.matches(&owner));
        assert!(map.get(&target_cid).unwrap().owner.matches(&owner));
        assert_eq!(map.len(), 2);
    }
}
