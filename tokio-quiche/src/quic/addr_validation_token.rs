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

use quiche::ConnectionId;
use std::io::Write;
use std::io::{
    self,
};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use crate::QuicResultExt;

const HMAC_KEY_LEN: usize = 32;
const HMAC_TAG_LEN: usize = 32;
const ISSUED_AT_LEN: usize = size_of::<u64>();
const TOKEN_VALIDITY: Duration = Duration::from_secs(30);

pub(crate) struct AddrValidationTokenManager {
    sign_key: [u8; HMAC_KEY_LEN],
    epoch: Instant,
}

impl Default for AddrValidationTokenManager {
    fn default() -> Self {
        let mut key_bytes = [0; HMAC_KEY_LEN];
        boring::rand::rand_bytes(&mut key_bytes).unwrap();

        AddrValidationTokenManager {
            sign_key: key_bytes,
            epoch: Instant::now(),
        }
    }
}

impl AddrValidationTokenManager {
    pub(super) fn gen(
        &self, original_dcid: &[u8], client_addr: SocketAddr,
    ) -> Vec<u8> {
        self.gen_at(original_dcid, client_addr, Instant::now())
    }

    fn gen_at(
        &self, original_dcid: &[u8], client_addr: SocketAddr, now: Instant,
    ) -> Vec<u8> {
        let ip_bytes = match client_addr.ip() {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        let issued_at: u64 = now
            .checked_duration_since(self.epoch)
            .expect("monotonic clock precedes token epoch")
            .as_millis()
            .try_into()
            .expect("token manager lifetime exceeds u64 milliseconds");

        let token_len =
            HMAC_TAG_LEN + ISSUED_AT_LEN + ip_bytes.len() + original_dcid.len();
        let mut token = io::Cursor::new(vec![0u8; token_len]);

        token.set_position(HMAC_TAG_LEN as u64);
        token.write_all(&issued_at.to_be_bytes()).unwrap();
        token.write_all(&ip_bytes).unwrap();
        token.write_all(original_dcid).unwrap();

        let tag = boring::hash::hmac_sha256(
            &self.sign_key,
            &token.get_ref()[HMAC_TAG_LEN..],
        )
        .unwrap();

        token.set_position(0);
        token.write_all(tag.as_ref()).unwrap();

        token.into_inner()
    }

    pub(super) fn validate_and_extract_original_dcid<'t>(
        &self, token: &'t [u8], client_addr: SocketAddr,
    ) -> io::Result<ConnectionId<'t>> {
        self.validate_and_extract_original_dcid_at(
            token,
            client_addr,
            Instant::now(),
        )
    }

    fn validate_and_extract_original_dcid_at<'t>(
        &self, token: &'t [u8], client_addr: SocketAddr, now: Instant,
    ) -> io::Result<ConnectionId<'t>> {
        let ip_bytes = match client_addr.ip() {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };

        let token_prefix_len = HMAC_TAG_LEN + ISSUED_AT_LEN + ip_bytes.len();

        if token.len() < token_prefix_len {
            return Err("token is too short").into_io();
        }

        let (tag, payload) = token.split_at(HMAC_TAG_LEN);

        let expected_tag =
            boring::hash::hmac_sha256(&self.sign_key, payload).unwrap();

        if !boring::memcmp::eq(&expected_tag, tag) {
            return Err("signature verification failed").into_io();
        }

        let issued_at =
            u64::from_be_bytes(payload[..ISSUED_AT_LEN].try_into().unwrap());
        let now: u64 = now
            .checked_duration_since(self.epoch)
            .ok_or("monotonic clock precedes token epoch")
            .into_io()?
            .as_millis()
            .try_into()
            .map_err(|_| "token manager lifetime exceeds u64 milliseconds")
            .into_io()?;
        let age = now
            .checked_sub(issued_at)
            .ok_or("token was issued in the future")
            .into_io()?;

        if Duration::from_millis(age) > TOKEN_VALIDITY {
            return Err("token expired").into_io();
        }

        if payload[ISSUED_AT_LEN..ISSUED_AT_LEN + ip_bytes.len()] != *ip_bytes {
            return Err("IPs don't match").into_io();
        }

        Ok(ConnectionId::from_ref(&token[token_prefix_len..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_encodes_monotonic_time_ip_and_dcid() {
        let manager = AddrValidationTokenManager::default();
        let issued_at = manager.epoch + Duration::from_secs(7);

        let token =
            manager.gen_at(b"foo", "127.0.0.1:1337".parse().unwrap(), issued_at);
        let payload = &token[HMAC_TAG_LEN..];

        assert!(token[..HMAC_TAG_LEN].iter().any(|byte| *byte != 0));
        assert_eq!(
            u64::from_be_bytes(payload[..ISSUED_AT_LEN].try_into().unwrap()),
            7_000
        );
        assert_eq!(&payload[ISSUED_AT_LEN..ISSUED_AT_LEN + 4], &[127, 0, 0, 1]);
        assert_eq!(&payload[ISSUED_AT_LEN + 4..], b"foo");

        let token =
            manager.gen_at(b"bar", "[::1]:1338".parse().unwrap(), issued_at);
        let payload = &token[HMAC_TAG_LEN + ISSUED_AT_LEN..];
        assert_eq!(payload[..16], [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]);
        assert_eq!(&payload[16..], b"bar");
    }

    #[test]
    fn validate_binds_ip_not_port_and_preserves_dcid() {
        let manager = AddrValidationTokenManager::default();
        let issued_at = manager.epoch + Duration::from_secs(1);
        let addr = "127.0.0.1:1337".parse().unwrap();
        let token = manager.gen_at(b"original-dcid", addr, issued_at);

        let dcid = manager
            .validate_and_extract_original_dcid_at(
                &token,
                "127.0.0.1:9999".parse().unwrap(),
                issued_at,
            )
            .unwrap();
        assert_eq!(dcid, ConnectionId::from_ref(b"original-dcid"));
        assert!(manager
            .validate_and_extract_original_dcid_at(
                &token,
                "127.0.0.2:1337".parse().unwrap(),
                issued_at,
            )
            .is_err());

        let v6_addr = "[::1]:1338".parse().unwrap();
        let v6_token = manager.gen_at(b"v6-dcid", v6_addr, issued_at);
        assert_eq!(
            manager
                .validate_and_extract_original_dcid_at(
                    &v6_token,
                    "[::1]:9999".parse().unwrap(),
                    issued_at,
                )
                .unwrap(),
            ConnectionId::from_ref(b"v6-dcid")
        );
    }

    #[test]
    fn validate_enforces_thirty_second_window_and_allows_replay() {
        let manager = AddrValidationTokenManager::default();
        let addr = "127.0.0.1:1337".parse().unwrap();
        let issued_at =
            manager.epoch + Duration::from_secs(5) + Duration::from_micros(500);
        let token = manager.gen_at(b"foo", addr, issued_at);
        let boundary = issued_at + TOKEN_VALIDITY;

        // Stateless tokens intentionally allow same-IP replay within the
        // validity window.
        for _ in 0..2 {
            assert!(manager
                .validate_and_extract_original_dcid_at(&token, addr, boundary)
                .is_ok());
        }

        assert!(manager
            .validate_and_extract_original_dcid_at(
                &token,
                addr,
                boundary + Duration::from_millis(1),
            )
            .is_err());
        assert!(manager
            .validate_and_extract_original_dcid_at(
                &token,
                addr,
                issued_at - Duration::from_millis(1),
            )
            .is_err());
    }

    #[test]
    fn validate_rejects_tampered_mac_and_dcid() {
        let manager = AddrValidationTokenManager::default();
        let addr = "127.0.0.1:1337".parse().unwrap();
        let issued_at = manager.epoch + Duration::from_secs(1);
        let token = manager.gen_at(b"foo", addr, issued_at);

        let mut bad_mac = token.clone();
        bad_mac[0] ^= 1;
        assert!(manager
            .validate_and_extract_original_dcid_at(&bad_mac, addr, issued_at)
            .is_err());

        let mut bad_dcid = token;
        *bad_dcid.last_mut().unwrap() ^= 1;
        assert!(manager
            .validate_and_extract_original_dcid_at(&bad_dcid, addr, issued_at)
            .is_err());
    }

    #[test]
    fn validate_err_short_token() {
        let manager = AddrValidationTokenManager::default();
        let v4_addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let v6_addr = "[::1]:1338".parse().unwrap();

        for addr in [v4_addr, v6_addr] {
            let ip_len = match addr.ip() {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 16,
            };
            let too_short = vec![1; HMAC_TAG_LEN + ISSUED_AT_LEN + ip_len - 1];
            assert!(manager
                .validate_and_extract_original_dcid(&too_short, addr)
                .is_err());
        }
    }
}
