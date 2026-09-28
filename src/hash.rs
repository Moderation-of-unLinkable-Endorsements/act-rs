// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Hashing and derivation under the ACT protocol context: RFC 9380's
//! `expand_message_xmd` over SHA-256, and the IHAT group's `HashToScalar`,
//! `DeriveScalar`, and `DeriveNonce`.

use subtle::CtOption;
use zeroize::Zeroize;

use crate::Error;
use crate::backend::{Backend, SCALAR_LENGTH, Scalar, Sha256};

/// Domain separation tag of `HashToGroup`.
pub(crate) const DST_HASH_TO_GROUP: &[u8] = b"HashToGroup-ACTv1-P256-SHA256";
/// Domain separation tag of `HashToScalar`.
pub(crate) const DST_HASH_TO_SCALAR: &[u8] = b"HashToScalar-ACTv1-P256-SHA256";
const DST_DERIVE_SCALAR: &[u8] = b"DeriveScalar-ACTv1-P256-SHA256";
const DST_DERIVE_NONCE: &[u8] = b"DeriveNonce-ACTv1-P256-SHA256";

/// The seed length `Nseed`.
pub(crate) const NSEED: usize = crate::SEED_LENGTH;

/// Output length of every `expand_message_xmd` call in the draft.
const XMD_LENGTH: usize = 48;

/// `expand_message_xmd` with SHA-256 (RFC 9380, Section 5.3.1), with the
/// message split into a prefix absorbed once and a suffix supplied per call.
///
/// `DeriveNonce` hashes the same witness and relation for every nonce of a
/// proof; sharing the prefix state makes that cost linear instead of
/// quadratic in the relation size.
pub(crate) struct XmdPrefix<H: Sha256> {
    hasher: H,
}

impl<H: Sha256> XmdPrefix<H> {
    /// Absorbs `Z_pad || prefix`.
    pub(crate) fn new(prefix: &[&[u8]]) -> Self {
        let mut hasher = H::new();
        hasher.update(&[0u8; 64]);
        for part in prefix {
            hasher.update(part);
        }
        Self { hasher }
    }

    /// `expand_message_xmd(prefix || suffix, dst, XMD_LENGTH)`.
    pub(crate) fn expand(&self, suffix: &[&[u8]], dst: &[u8]) -> [u8; XMD_LENGTH] {
        let mut out = [0u8; XMD_LENGTH];
        self.expand_into(suffix, dst, &mut out);
        out
    }

    /// `expand_message_xmd(prefix || suffix, dst, len(out))`.
    ///
    /// `dst` is at most 255 bytes and `out` at most `255 * 32` bytes; the
    /// tags of this crate are short constants and every output is 48 bytes.
    pub(crate) fn expand_into(&self, suffix: &[&[u8]], dst: &[u8], out: &mut [u8]) {
        debug_assert!(dst.len() <= 255 && out.len() <= 255 * 32);
        let dst_prime_tail = [dst.len() as u8];
        let mut hasher = self.hasher.clone();
        for part in suffix {
            hasher.update(part);
        }
        hasher.update(&(out.len() as u16).to_be_bytes());
        hasher.update(&[0]);
        hasher.update(dst);
        hasher.update(&dst_prime_tail);
        let mut b0 = hasher.finalize();

        let mut previous = [0u8; 32];
        for (i, chunk) in out.chunks_mut(32).enumerate() {
            // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime); for
            // i = 1 the previous block is zero, so the xor leaves b_0.
            let mut block = b0;
            for (byte, prev) in block.iter_mut().zip(previous) {
                *byte ^= prev;
            }
            let mut hasher = H::new();
            hasher.update(&block);
            block.zeroize();
            hasher.update(&[i as u8 + 1]);
            hasher.update(dst);
            hasher.update(&dst_prime_tail);
            previous = hasher.finalize();
            chunk.copy_from_slice(&previous[..chunk.len()]);
        }
        b0.zeroize();
        previous.zeroize();
    }
}

/// A scalar from a 24-byte big-endian integer, which is below the order.
fn scalar_from_u192<B: Backend>(bytes: &[u8]) -> B::Scalar {
    let mut padded = [0u8; SCALAR_LENGTH];
    padded[8..].copy_from_slice(bytes);
    B::Scalar::from_bytes(&padded).unwrap_or(B::Scalar::default())
}

/// The scalar `2^192`.
fn two_to_192<B: Backend>() -> B::Scalar {
    let mut bytes = [0u8; SCALAR_LENGTH];
    bytes[7] = 1;
    B::Scalar::from_bytes(&bytes).unwrap_or(B::Scalar::default())
}

/// Reduces a 48-byte big-endian integer modulo the order, in constant time,
/// as `hi * 2^192 + lo` over two canonical halves.
pub(crate) fn reduce_be_48<B: Backend>(bytes: &[u8; XMD_LENGTH]) -> B::Scalar {
    let (hi, lo) = bytes.split_at(24);
    scalar_from_u192::<B>(hi) * two_to_192::<B>() + scalar_from_u192::<B>(lo)
}

/// Reduces a 48-byte little-endian integer modulo the order, as the
/// Fiat-Shamir `DecodeUint` requires.
pub(crate) fn reduce_le_48<B: Backend>(bytes: &[u8; XMD_LENGTH]) -> B::Scalar {
    let mut reversed = [0u8; XMD_LENGTH];
    for (dst, src) in reversed.iter_mut().zip(bytes.iter().rev()) {
        *dst = *src;
    }
    reduce_be_48::<B>(&reversed)
}

/// `G.HashToScalar(msg)` under `dst`.
pub(crate) fn hash_to_scalar<B: Backend>(msg: &[&[u8]], dst: &[u8]) -> B::Scalar {
    let mut uniform = XmdPrefix::<B::Sha256>::new(&[]).expand(msg, dst);
    let scalar = reduce_be_48::<B>(&uniform);
    uniform.zeroize();
    scalar
}

/// `G.DeriveScalar(seed, info)`: a nonzero scalar from a fresh seed.
///
/// The counter loop exits on the first nonzero output, a branch taken with
/// probability about `2^-256`; the draft specifies it.
pub(crate) fn derive_scalar<B: Backend>(
    seed: &[u8; NSEED],
    info: &[u8],
) -> Result<B::Scalar, Error> {
    let info_len = u16::try_from(info.len()).map_err(|_| Error::InvalidInput)?;
    let prefix = XmdPrefix::<B::Sha256>::new(&[seed, &info_len.to_be_bytes(), info]);
    for counter in 0..=u8::MAX {
        let mut uniform = prefix.expand(&[&[counter]], DST_DERIVE_SCALAR);
        let scalar = reduce_be_48::<B>(&uniform);
        uniform.zeroize();
        if !bool::from(scalar.is_zero()) {
            return Ok(scalar);
        }
    }
    Err(Error::Derive)
}

/// `G.DeriveNonce(secret, label, instance, aux)`: a scalar that is a
/// pseudorandom function of the secret and the instance, refreshed by `aux`.
pub(crate) fn derive_nonce<B: Backend>(
    secret: &[u8],
    label: &[u8],
    instance: &[&[u8]],
    aux: &[u8; NSEED],
) -> Result<B::Scalar, Error> {
    NoncePrefix::<B>::with_trailing(secret, label, instance, 0)?.derive(&[], aux)
}

/// The fixed part of a `DeriveNonce` input: everything but the trailing
/// bytes of `instance` and `aux`.
pub(crate) struct NoncePrefix<B: Backend> {
    xmd: XmdPrefix<B::Sha256>,
    label: alloc::vec::Vec<u8>,
}

impl<B: Backend> NoncePrefix<B> {
    /// Absorbs `U16Prefixed(label) || I2OSP(len(secret), 4) || secret ||
    /// I2OSP(instance_len, 4) || instance`, where `instance_len` counts the
    /// bytes of `instance` plus `trailing` bytes supplied to [`Self::derive`].
    pub(crate) fn with_trailing(
        secret: &[u8],
        label: &[u8],
        instance: &[&[u8]],
        trailing: usize,
    ) -> Result<Self, Error> {
        let label_len = u16::try_from(label.len()).map_err(|_| Error::InvalidInput)?;
        let secret_len = u32::try_from(secret.len()).map_err(|_| Error::InvalidInput)?;
        let instance_len = instance.iter().map(|part| part.len()).sum::<usize>() + trailing;
        let instance_len = u32::try_from(instance_len).map_err(|_| Error::InvalidInput)?;
        let (label_len_bytes, secret_len_bytes, instance_len_bytes) = (
            label_len.to_be_bytes(),
            secret_len.to_be_bytes(),
            instance_len.to_be_bytes(),
        );
        let mut parts: alloc::vec::Vec<&[u8]> = alloc::vec![
            &label_len_bytes,
            label,
            &secret_len_bytes,
            secret,
            &instance_len_bytes
        ];
        parts.extend_from_slice(instance);
        Ok(Self {
            xmd: XmdPrefix::new(&parts),
            label: label.to_vec(),
        })
    }

    /// Completes the input with `trailing || U16Prefixed(aux)` and derives
    /// the nonce with `DeriveScalar(seed, label)`.
    pub(crate) fn derive(&self, trailing: &[u8], aux: &[u8; NSEED]) -> Result<B::Scalar, Error> {
        let aux_len = (NSEED as u16).to_be_bytes();
        let mut seed = self
            .xmd
            .expand(&[trailing, &aux_len, aux], DST_DERIVE_NONCE);
        let scalar = derive_scalar::<B>(&seed, &self.label);
        seed.zeroize();
        scalar
    }
}

/// Checks that a `CtOption` holds a value, mapping absence to `error`.
pub(crate) fn require<T>(value: CtOption<T>, error: Error) -> Result<T, Error> {
    value.into_option().ok_or(error)
}
