// Copyright (C) 2018-2019, Cloudflare, Inc.
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

//! Fixed-size Retry proofs carried only inside the standard opaque token.
//! Possession of the public key permits decoding, but not signing new proofs.
//! All public errors and Debug implementations intentionally omit key material.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::aead::Payload;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use std::fmt;
use zeroize::Zeroizing;

/// Fixed token length shared by ordinary opaque tokens and enhanced proofs.
pub const TOKEN_LEN: usize = 256;
const NONCE_LEN: usize = 24;
const MESSAGE_LEN: usize = 152;
const PLAINTEXT_LEN: usize = 216;
/// Maximum length of the caller's original address-validation token.
pub const MAX_ADDRESS_TOKEN_LEN: usize = 80;
const SIGN_CONTEXT: &[u8] = b"quiche/retry-proof/v1";
const COVER_CONTEXT: &[u8] = b"quiche/retry-cover/v1";
const ADDRESS_CONTEXT: &[u8] = b"quiche/retry-address-cover/v1";

/// Explicit, fixed cryptographic suite. No wire algorithm negotiation occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suite {
    /// Ed25519 signatures, HKDF-SHA256, and XChaCha20-Poly1305 encryption.
    Ed25519HkdfSha256XChaCha20Poly1305,
}

/// Sanitized configuration, encoding, or verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The public key is invalid, weak, or non-canonically encoded.
    InvalidKey,
    /// The token, signature, or connection binding is invalid.
    InvalidToken,
    /// A caller supplied an oversized CID or address token.
    Capacity,
    /// The operating system did not provide secure randomness.
    Entropy,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Retry protection: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Public connection identifiers bound to one Retry attempt.
#[derive(Clone, Copy)]
pub struct Binding<'a> {
    /// QUIC version of this attempt.
    pub version: u32,
    /// Destination CID from the client's original Initial.
    pub original_dcid: &'a [u8],
    /// Source CID from the client's original and repeated Initials.
    pub client_scid: &'a [u8],
    /// Server source CID in Retry, repeated as the new Initial's destination.
    pub retry_scid: &'a [u8],
}

/// Client verifier; also used by a server to unwrap a returned proof.
#[derive(Clone)]
pub struct PublicKey {
    bytes: Zeroizing<[u8; 32]>,
    cover_key: Zeroizing<[u8; 32]>,
}
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetryPublicKey(<redacted>)")
    }
}
impl PublicKey {
    /// Parses a canonical, non-weak prime-order Ed25519 public key.
    pub fn new(_suite: Suite, bytes: [u8; 32]) -> Result<Self, Error> {
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidKey)?;
        let point = key.to_edwards();
        if key.is_weak() ||
            !point.is_torsion_free() ||
            point.compress().to_bytes() != bytes
        {
            return Err(Error::InvalidKey);
        }
        let mut cover_key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(COVER_CONTEXT), &bytes)
            .expand(COVER_CONTEXT, &mut *cover_key)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            cover_key,
        })
    }

    /// Exposes the canonical bytes for confidential out-of-band distribution.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Verifies all connection identifiers before a client adopts Retry state.
    pub fn verify(
        &self, token: &[u8], binding: Binding<'_>,
    ) -> Result<(), Error> {
        let verified = self.open(
            token,
            binding.version,
            binding.client_scid,
            binding.retry_scid,
        )?;
        if verified.original_dcid != binding.original_dcid {
            return Err(Error::InvalidToken);
        }
        Ok(())
    }

    /// Verifies a proof returned by an ordinary or enhanced client. The caller
    /// must still validate the extracted address token's MAC, address and age.
    pub fn open(
        &self, token: &[u8], version: u32, client_scid: &[u8], retry_scid: &[u8],
    ) -> Result<VerifiedToken, Error> {
        let plain = decrypt(&self.cover_key, COVER_CONTEXT, token)?;
        let mut signed = Zeroizing::new(Vec::with_capacity(
            SIGN_CONTEXT.len() + NONCE_LEN + MESSAGE_LEN,
        ));
        signed.extend_from_slice(SIGN_CONTEXT);
        signed.extend_from_slice(&token[..NONCE_LEN]);
        signed.extend_from_slice(&plain[..MESSAGE_LEN]);
        let signature = Signature::from_slice(&plain[MESSAGE_LEN..])
            .map_err(|_| Error::InvalidToken)?;
        VerifyingKey::from_bytes(&self.bytes)
            .map_err(|_| Error::InvalidKey)?
            .verify_strict(&signed, &signature)
            .map_err(|_| Error::InvalidToken)?;
        if plain[0] != 1 ||
            plain[1..5] != version.to_be_bytes() ||
            cid(&plain, 26)? != client_scid ||
            cid(&plain, 47)? != retry_scid
        {
            return Err(Error::InvalidToken);
        }
        let original_dcid = cid(&plain, 5)?.to_vec();
        let len = plain[68] as usize;
        if len == 0 || len > MAX_ADDRESS_TOKEN_LEN {
            return Err(Error::InvalidToken);
        }
        Ok(VerifiedToken {
            original_dcid,
            address_token: plain[69..69 + len].to_vec(),
        })
    }
}

/// Signed and decrypted data; address validation is still the caller's job.
pub struct VerifiedToken {
    /// Original destination CID authenticated by the proof.
    pub original_dcid: Vec<u8>,
    /// Unmodified token generated by the server's address-validation algorithm.
    pub address_token: Vec<u8>,
}

/// Server signing key. Clones share no mutable nonce counter or global state.
pub struct SigningIdentity {
    key: SigningKey,
    public: PublicKey,
}
impl fmt::Debug for SigningIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetrySigningIdentity(<redacted>)")
    }
}
impl SigningIdentity {
    /// Constructs an identity from an Ed25519 seed stored in sensitive config.
    pub fn from_seed(suite: Suite, seed: &[u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::from_bytes(seed);
        let public = PublicKey::new(suite, key.verifying_key().to_bytes())?;
        Ok(Self { key, public })
    }

    /// Returns the verifier corresponding to this signing identity.
    pub fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    /// Signs the fixed payload and its fresh 192-bit random nonce, then hides
    /// both under the public-key-derived cover key. RNG failure is fatal.
    pub fn seal(
        &self, binding: Binding<'_>, address_token: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if address_token.is_empty() || address_token.len() > MAX_ADDRESS_TOKEN_LEN
        {
            return Err(Error::Capacity);
        }
        let mut plain = Zeroizing::new(vec![0; PLAINTEXT_LEN]);
        getrandom::getrandom(&mut plain).map_err(|_| Error::Entropy)?;
        plain[0] = 1;
        plain[1..5].copy_from_slice(&binding.version.to_be_bytes());
        put_cid(&mut plain, 5, binding.original_dcid)?;
        put_cid(&mut plain, 26, binding.client_scid)?;
        put_cid(&mut plain, 47, binding.retry_scid)?;
        plain[68] = address_token.len() as u8;
        plain[69..69 + address_token.len()].copy_from_slice(address_token);
        let nonce = fresh_nonce()?;
        let mut signed = Zeroizing::new(Vec::with_capacity(
            SIGN_CONTEXT.len() + NONCE_LEN + MESSAGE_LEN,
        ));
        signed.extend_from_slice(SIGN_CONTEXT);
        signed.extend_from_slice(&nonce);
        signed.extend_from_slice(&plain[..MESSAGE_LEN]);
        plain[MESSAGE_LEN..].copy_from_slice(&self.key.sign(&signed).to_bytes());
        encrypt(&self.public.cover_key, COVER_CONTEXT, &nonce, &plain)
    }
}

/// Process-local cover key for standard address tokens. This gives ordinary
/// and enhanced tokens the same length and opaque outer representation.
pub struct OpaqueTokenKey(Zeroizing<[u8; 32]>);
impl OpaqueTokenKey {
    /// Creates a fresh process-local key; never reuses one after restart.
    pub fn new() -> Result<Self, Error> {
        let mut key = Zeroizing::new([0; 32]);
        getrandom::getrandom(&mut *key).map_err(|_| Error::Entropy)?;
        Ok(Self(key))
    }

    /// Pads and encrypts a raw address token to the common token length.
    pub fn seal(&self, address_token: &[u8]) -> Result<Vec<u8>, Error> {
        if address_token.is_empty() || address_token.len() > MAX_ADDRESS_TOKEN_LEN
        {
            return Err(Error::Capacity);
        }
        let mut plain = Zeroizing::new(vec![0; PLAINTEXT_LEN]);
        getrandom::getrandom(&mut plain).map_err(|_| Error::Entropy)?;
        plain[0] = address_token.len() as u8;
        plain[1..1 + address_token.len()].copy_from_slice(address_token);
        encrypt(&self.0, ADDRESS_CONTEXT, &fresh_nonce()?, &plain)
    }

    /// Returns the raw token for the caller's existing address/age validation.
    pub fn open(&self, token: &[u8]) -> Result<Vec<u8>, Error> {
        let plain = decrypt(&self.0, ADDRESS_CONTEXT, token)?;
        let len = plain[0] as usize;
        if len == 0 || len > MAX_ADDRESS_TOKEN_LEN {
            return Err(Error::InvalidToken);
        }
        Ok(plain[1..1 + len].to_vec())
    }
}
fn cid(plain: &[u8], at: usize) -> Result<&[u8], Error> {
    let len = plain[at] as usize;
    if len > 20 {
        return Err(Error::InvalidToken);
    }
    Ok(&plain[at + 1..at + 1 + len])
}
fn put_cid(plain: &mut [u8], at: usize, value: &[u8]) -> Result<(), Error> {
    if value.len() > 20 {
        return Err(Error::Capacity);
    }
    plain[at] = value.len() as u8;
    plain[at + 1..at + 1 + value.len()].copy_from_slice(value);
    Ok(())
}
fn fresh_nonce() -> Result<[u8; NONCE_LEN], Error> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Entropy)?;
    Ok(nonce)
}
fn encrypt(
    key: &[u8; 32], context: &[u8], nonce: &[u8; NONCE_LEN], plain: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce), Payload {
            msg: plain,
            aad: context,
        })
        .map_err(|_| Error::InvalidToken)?;
    let mut token = Vec::with_capacity(TOKEN_LEN);
    token.extend_from_slice(nonce);
    token.extend_from_slice(&ciphertext);
    Ok(token)
}
fn decrypt(
    key: &[u8; 32], context: &[u8], token: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if token.len() != TOKEN_LEN {
        return Err(Error::InvalidToken);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let plain = cipher
        .decrypt(XNonce::from_slice(&token[..NONCE_LEN]), Payload {
            msg: &token[NONCE_LEN..],
            aad: context,
        })
        .map_err(|_| Error::InvalidToken)?;
    Ok(Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> SigningIdentity {
        SigningIdentity::from_seed(
            Suite::Ed25519HkdfSha256XChaCha20Poly1305,
            &[7; 32],
        )
        .unwrap()
    }
    fn binding() -> Binding<'static> {
        Binding {
            version: 1,
            original_dcid: b"original",
            client_scid: b"client",
            retry_scid: b"retry",
        }
    }
    #[test]
    fn fixed_size_unique_nonce_roundtrip_and_bindings() {
        let identity = identity();
        let key = identity.public_key();
        let first = identity.seal(binding(), &[1; 76]).unwrap();
        let second = identity.seal(binding(), &[1; 76]).unwrap();
        assert_eq!(first.len(), TOKEN_LEN);
        assert_ne!(&first[..NONCE_LEN], &second[..NONCE_LEN]);
        assert!(key.verify(&first, binding()).is_ok());
        let raw = key.open(&first, 1, b"client", b"retry").unwrap();
        assert_eq!(raw.address_token, [1; 76]);
        assert_eq!(raw.original_dcid, b"original");
        for bad in [
            Binding {
                version: 2,
                ..binding()
            },
            Binding {
                original_dcid: b"other",
                ..binding()
            },
            Binding {
                client_scid: b"other",
                ..binding()
            },
            Binding {
                retry_scid: b"other",
                ..binding()
            },
        ] {
            assert!(key.verify(&first, bad).is_err());
        }
        let wrong = SigningIdentity::from_seed(
            Suite::Ed25519HkdfSha256XChaCha20Poly1305,
            &[9; 32],
        )
        .unwrap();
        assert!(wrong.public_key().verify(&first, binding()).is_err());
    }
    #[test]
    fn truncation_tamper_and_oversize_fail_closed() {
        let identity = identity();
        let token = identity.seal(binding(), b"raw").unwrap();
        for len in 0..TOKEN_LEN {
            assert!(identity
                .public_key()
                .verify(&token[..len], binding())
                .is_err());
        }
        for offset in 0..TOKEN_LEN {
            let mut changed = token.clone();
            changed[offset] ^= 1;
            assert!(identity.public_key().verify(&changed, binding()).is_err());
        }
        assert!(identity.seal(binding(), &[]).is_err());
        assert!(identity.seal(binding(), &[0; 81]).is_err());
        assert!(identity
            .seal(
                Binding {
                    client_scid: &[0; 21],
                    ..binding()
                },
                b"raw"
            )
            .is_err());
    }
    #[test]
    fn public_key_holder_cannot_reseal_new_content_or_nonce() {
        let identity = identity();
        let public = identity.public_key();
        let token = identity.seal(binding(), b"raw").unwrap();
        let plain = decrypt(&public.cover_key, COVER_CONTEXT, &token).unwrap();
        let nonce = fresh_nonce().unwrap();
        // Public holder can decrypt and correctly recompute the AEAD tag.
        let resealed =
            encrypt(&public.cover_key, COVER_CONTEXT, &nonce, &plain).unwrap();
        assert!(public.verify(&resealed, binding()).is_err());
        let mut forged = plain.clone();
        forged[69] ^= 1;
        let nonce: [u8; NONCE_LEN] = token[..NONCE_LEN].try_into().unwrap();
        let resealed =
            encrypt(&public.cover_key, COVER_CONTEXT, &nonce, &forged).unwrap();
        assert!(public.verify(&resealed, binding()).is_err());
    }
    #[test]
    fn ordinary_tokens_share_envelope_but_not_signing_authority() {
        let cover = OpaqueTokenKey::new().unwrap();
        let token = cover.seal(&[3; 80]).unwrap();
        assert_eq!(token.len(), TOKEN_LEN);
        assert_eq!(cover.open(&token).unwrap(), [3; 80]);
        assert!(OpaqueTokenKey::new().unwrap().open(&token).is_err());
        assert!(identity().public_key().verify(&token, binding()).is_err());
        assert!(cover
            .open(&identity().seal(binding(), b"raw").unwrap())
            .is_err());
    }
    #[test]
    fn invalid_weak_and_noncanonical_public_keys_are_rejected() {
        for bytes in [
            [0; 32],
            [0xff; 32],
            {
                let mut b = [0; 32];
                b[0] = 1;
                b
            },
            {
                let mut b = [0xff; 32];
                b[0] = 0xed;
                b[31] = 0x7f;
                b
            },
        ] {
            assert!(PublicKey::new(
                Suite::Ed25519HkdfSha256XChaCha20Poly1305,
                bytes
            )
            .is_err());
        }
        assert_eq!(
            format!("{:?}", identity()),
            "RetrySigningIdentity(<redacted>)"
        );
    }
}
