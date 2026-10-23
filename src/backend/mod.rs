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

//! Group and hash primitives behind the protocol.
//!
//! The common P-256, SHA-256, hash-to-curve, and randomness implementation is
//! provided by `ec_ihat`. ACT extends that backend with fixed-base tables and
//! SHAKE128, which are specific to its proofs.

use core::fmt::Debug;

use zeroize::Zeroizing;

use crate::SEED_LENGTH;

pub use ec_ihat::backend::{ORDER, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar, Sha256};

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

#[cfg(feature = "boringssl")]
pub mod boringssl;

pub mod shake;

/// A point prepared for repeated multiplication by secret scalars.
///
/// The ciphersuite generators `H1` to `H4` are the bases of most
/// multiplications in a proof, so a backend may precompute tables for them
/// once per [`crate::Params`]. Multiplication must be constant time in the
/// scalar; the point itself is public.
pub trait FixedBase<P: Point>: Clone + Debug + Send + Sync {
    /// Prepares `point`.
    fn new(point: P) -> Self;

    /// The point.
    fn point(&self) -> &P;

    /// `scalar * point`.
    fn mul(&self, scalar: &P::Scalar) -> P;
}

/// An absorbing SHAKE128 sponge.
///
/// The Fiat-Shamir transform derives session identifiers and challenges
/// from it. Every input is public.
pub trait Shake128: Sized {
    /// The squeezing half of the sponge.
    type Reader: Shake128Reader;

    /// A fresh sponge.
    fn new() -> Self;

    /// Absorbs `data`; splitting the input across calls does not change the
    /// output.
    fn absorb(&mut self, data: &[u8]);

    /// Pads the input and switches to squeezing.
    fn finalize(self) -> Self::Reader;
}

/// A squeezing SHAKE128 sponge. Consecutive reads continue one stream.
pub trait Shake128Reader {
    /// Fills `out` with the next bytes of the output stream.
    fn read(&mut self, out: &mut [u8]);
}

/// The primitives the protocol is built on.
///
/// A backend is a zero-sized marker type. It must be safe to use from any
/// thread.
pub trait Backend: 'static + Copy + Debug + Default + PartialEq + Eq + Send + Sync {
    /// Scalars of the P-256 field.
    type Scalar: Scalar;

    /// Points of the P-256 group.
    type Point: Point<Scalar = Self::Scalar>;

    /// Points with precomputation.
    type FixedBase: FixedBase<Self::Point>;

    /// Incremental SHA-256.
    type Sha256: Sha256;

    /// SHAKE128.
    type Shake128: Shake128;

    /// Hashes `msg` to P-256 under the concatenated domain separation tag.
    fn hash_to_curve(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point>;

    /// Fills `buf` from the operating system's cryptographic random generator.
    fn random_bytes(buf: &mut [u8]);

    /// A fresh seed for [`SecretKey::from_seed`](crate::SecretKey::from_seed).
    fn generate_seed() -> Zeroizing<[u8; SEED_LENGTH]> {
        let mut seed = Zeroizing::new([0u8; SEED_LENGTH]);
        Self::random_bytes(seed.as_mut());
        seed
    }
}
