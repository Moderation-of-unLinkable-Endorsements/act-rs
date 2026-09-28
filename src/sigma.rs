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

//! Compact NARG strings (`draft-irtf-cfrg-sigma-protocols-03`, Section 5.5)
//! under the Fiat-Shamir transform of `draft-irtf-cfrg-fiat-shamir-03`.
//!
//! The generic construction serializes a sparse linear relation, absorbs it
//! and the prover's commitments into a SHAKE128 duplex sponge, and squeezes
//! the challenge. This module keeps that byte-for-byte, but the relations of
//! ACT are fixed, so each is a [`Statement`] that writes its own
//! serialization and evaluates its own equations, sharing bases and
//! intermediate values that a generic evaluator would recompute.

use alloc::vec::Vec;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::backend::{
    Backend, ORDER, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar, Shake128, Shake128Reader,
};
use crate::hash::{self, NSEED, NoncePrefix};
use crate::random::Random;
use crate::{Error, PROTOCOL_CONTEXT};

/// The Sigma protocol ciphersuite identifier, carried in every tag.
pub(crate) const SIGMA_SUITE: &[u8] = b"sigma-proofs_Shake128_P256";

/// The domain-separation label of `DeriveSessionID`, itself a session id.
const SESSION_ID_LABEL: &[u8; 32] = b"irtf-cfrg-fiat-shamir/session-id";

/// The SHAKE128 rate; `DS.Init` pads the session id to it with zeros.
const RATE: usize = 168;
const INIT_PADDING: [u8; RATE - 32] = [0; RATE - 32];

/// A coefficient of one.
pub(crate) const ONE: [u8; SCALAR_LENGTH] = coefficient(1);

/// A coefficient of minus one.
pub(crate) const MINUS_ONE: [u8; SCALAR_LENGTH] = order_minus(1);

/// The scalar `value`, serialized as a coefficient.
pub(crate) const fn coefficient(value: u64) -> [u8; SCALAR_LENGTH] {
    let mut out = [0u8; SCALAR_LENGTH];
    let bytes = value.to_be_bytes();
    let mut i = 0;
    while i < 8 {
        out[SCALAR_LENGTH - 8 + i] = bytes[i];
        i += 1;
    }
    out
}

/// The scalar `-value` modulo the order, serialized as a coefficient.
pub(crate) const fn order_minus(value: u64) -> [u8; SCALAR_LENGTH] {
    if value == 0 {
        return [0u8; SCALAR_LENGTH];
    }
    let subtrahend = coefficient(value);
    let mut out = [0u8; SCALAR_LENGTH];
    let mut borrow = 0u16;
    let mut i = SCALAR_LENGTH;
    while i > 0 {
        i -= 1;
        let minuend = ORDER[i] as u16;
        let sub = subtrahend[i] as u16 + borrow;
        if minuend >= sub {
            out[i] = (minuend - sub) as u8;
            borrow = 0;
        } else {
            out[i] = (minuend + 256 - sub) as u8;
            borrow = 1;
        }
    }
    out
}

/// `Tag(label, bindings)`: the application tag of a proof.
pub(crate) fn tag(label: &[u8], bindings: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let mut tag = Vec::with_capacity(64 + bindings.iter().map(|b| b.len() + 2).sum::<usize>());
    tag.extend_from_slice(PROTOCOL_CONTEXT);
    tag.push(b'-');
    tag.extend_from_slice(label);
    tag.extend_from_slice(b"-CMPT-with-");
    tag.extend_from_slice(SIGMA_SUITE);
    for binding in bindings {
        let len = u16::try_from(binding.len()).map_err(|_| Error::InvalidInput)?;
        tag.extend_from_slice(&len.to_be_bytes());
        tag.extend_from_slice(binding);
    }
    Ok(tag)
}

/// `DeriveSessionID(tag)`.
pub(crate) fn session_id<B: Backend>(tag: &[u8]) -> [u8; 32] {
    let mut sponge = B::Shake128::new();
    sponge.absorb(SESSION_ID_LABEL);
    sponge.absorb(&INIT_PADDING);
    sponge.absorb(tag);
    let mut out = [0u8; 32];
    sponge.finalize().read(&mut out);
    out
}

/// `DeriveChallenge`: the sponge initialized with the session id absorbs
/// the serialized relation and commitments, and the challenge is the
/// little-endian reduction of `Ns + 16` squeezed bytes.
fn challenge<B: Backend>(session_id: &[u8; 32], relation: &[u8], commitments: &[u8]) -> B::Scalar {
    let mut sponge = B::Shake128::new();
    sponge.absorb(session_id);
    sponge.absorb(&INIT_PADDING);
    sponge.absorb(relation);
    sponge.absorb(commitments);
    let mut out = [0u8; 48];
    sponge.finalize().read(&mut out);
    hash::reduce_le_48::<B>(&out)
}

/// A linear relation with a fixed shape.
///
/// Implementations correspond to the `Relation` blocks of the draft. Their
/// serialization must equal `SerializeLinearRelation` of the compiled
/// relation, and `commit` and `simulate` must equal `map(instance, nonces)`
/// and `map(instance, response) - challenge * image(instance)`, equation by
/// equation.
pub(crate) trait Statement<B: Backend> {
    /// `num_scalars(instance)`: the witness length.
    fn num_scalars(&self) -> usize;

    /// `ValidateInstance`, restricted to what does not hold by construction:
    /// the structural checks are fixed by the shape, and deserialization
    /// already rejects the identity, so this checks the computed elements,
    /// the images, and the shape against the public amounts.
    fn validate(&self) -> Result<(), Error>;

    /// `SerializeLinearRelation(instance)`, appended to `out`.
    fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error>;

    /// The prover's commitments, one per equation, in constant time with
    /// respect to `nonces`.
    fn commit(&self, nonces: &[B::Scalar], out: &mut Vec<B::Point>);

    /// The simulator's commitments, one per equation.
    fn simulate(&self, challenge: &B::Scalar, response: &[B::Scalar], out: &mut Vec<B::Point>);
}

/// Writes the sparse-matrix encoding of a relation.
pub(crate) struct RelationWriter<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> RelationWriter<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    fn count(&mut self, value: usize) {
        // Shapes are bounded by `L <= 64`; the draft caps counts at 2^32.
        self.out.extend_from_slice(&(value as u32).to_le_bytes());
    }

    /// `LE(num_equations, 4)`.
    pub(crate) fn equations(&mut self, count: usize) {
        self.count(count);
    }

    /// An equation's image: its term count, then `(element, coeff)` pairs.
    pub(crate) fn image(&mut self, terms: &[(usize, &[u8; SCALAR_LENGTH])]) {
        self.begin(terms.len());
        for (element, coeff) in terms {
            self.image_term(*element, coeff);
        }
    }

    /// An equation's terms: the count, then `(scalar, element, coeff)`.
    pub(crate) fn terms(&mut self, terms: &[(usize, usize, &[u8; SCALAR_LENGTH])]) {
        self.begin(terms.len());
        for (scalar, element, coeff) in terms {
            self.term(*scalar, *element, coeff);
        }
    }

    /// Begins an image or term list of `count` entries, for callers that
    /// stream long lists.
    pub(crate) fn begin(&mut self, count: usize) {
        self.count(count);
    }

    /// One image term.
    pub(crate) fn image_term(&mut self, element: usize, coeff: &[u8; SCALAR_LENGTH]) {
        self.count(element);
        self.out.extend_from_slice(coeff);
    }

    /// One right-hand-side term.
    pub(crate) fn term(&mut self, scalar: usize, element: usize, coeff: &[u8; SCALAR_LENGTH]) {
        self.count(scalar);
        self.count(element);
        self.out.extend_from_slice(coeff);
    }

    /// A statement element, at index 1 onwards; the generator is implicit.
    pub(crate) fn element<P: Point>(&mut self, point: &P) -> Result<(), Error> {
        let bytes = point.to_bytes().ok_or(Error::Verify)?;
        self.out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// `ProverNonces` of the draft: one nonce per witness scalar, each derived
/// with `DeriveNonce` from the witness, the session, the relation, and its
/// own `Nseed` bytes of fresh randomness.
fn prover_nonces<B: Backend, R: Random>(
    witness: &[B::Scalar],
    session_id: &[u8; 32],
    relation: &[u8],
    rng: &mut R,
) -> Result<Vec<B::Scalar>, Error> {
    let mut secret = Vec::with_capacity(witness.len() * SCALAR_LENGTH);
    for scalar in witness {
        secret.extend_from_slice(&scalar.to_bytes());
    }
    let relation_len = u32::try_from(relation.len()).map_err(|_| Error::InvalidInput)?;
    // The instance is `session_id || I2OSP(len(relation), 4) || relation ||
    // I2OSP(i, 4)`; the counter comes last, so one hash prefix serves all.
    let prefix = NoncePrefix::<B>::with_trailing(
        &secret,
        b"nonce",
        &[session_id, &relation_len.to_be_bytes(), relation],
        4,
    );
    secret.zeroize();
    let prefix = prefix?;

    let mut rand = alloc::vec![0u8; witness.len() * NSEED];
    rng.fill(&mut rand);
    let nonces = rand
        .chunks_exact(NSEED)
        .enumerate()
        .map(|(i, aux)| {
            let aux: &[u8; NSEED] = aux.try_into().map_err(|_| Error::InvalidInput)?;
            prefix.derive(&(i as u32).to_be_bytes(), aux)
        })
        .collect();
    rand.zeroize();
    nonces
}

/// `ProveCompact` for `statement` under `session_id`.
pub(crate) fn prove<B: Backend, S: Statement<B>, R: Random>(
    session_id: &[u8; 32],
    statement: &S,
    witness: &[B::Scalar],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    statement.validate()?;
    let n = statement.num_scalars();
    debug_assert_eq!(witness.len(), n);

    let mut relation = Vec::new();
    statement.serialize(&mut relation)?;

    let mut nonces = prover_nonces::<B, _>(witness, session_id, &relation, rng)?;

    let mut commitments = Vec::new();
    statement.commit(&nonces, &mut commitments);
    let mut commitment_bytes = Vec::with_capacity(commitments.len() * POINT_LENGTH);
    for commitment in &commitments {
        // A commitment equal to the identity has no encoding; the
        // probability is negligible for a valid instance.
        commitment_bytes.extend_from_slice(&commitment.to_bytes().ok_or(Error::Derive)?);
    }

    let challenge = challenge::<B>(session_id, &relation, &commitment_bytes);
    let mut proof = Vec::with_capacity((n + 1) * SCALAR_LENGTH);
    proof.extend_from_slice(&challenge.to_bytes());
    for (nonce, scalar) in nonces.iter().zip(witness) {
        let mut response = *nonce + *scalar * challenge;
        proof.extend_from_slice(&response.to_bytes());
        response.zeroize();
    }
    nonces.zeroize();
    Ok(proof)
}

/// `VerifyCompact` for `statement` under `session_id`.
pub(crate) fn verify<B: Backend, S: Statement<B>>(
    session_id: &[u8; 32],
    statement: &S,
    proof: &[u8],
) -> Result<(), Error> {
    statement.validate()?;
    let n = statement.num_scalars();
    if proof.len() != (n + 1) * SCALAR_LENGTH {
        return Err(Error::Verify);
    }
    let scalars: Vec<B::Scalar> = proof
        .chunks_exact(SCALAR_LENGTH)
        .map(|chunk| {
            let bytes: &[u8; SCALAR_LENGTH] = chunk.try_into().map_err(|_| Error::Verify)?;
            hash::require(B::Scalar::from_bytes(bytes), Error::Verify)
        })
        .collect::<Result<_, _>>()?;
    let (claimed, response) = scalars.split_first().ok_or(Error::Verify)?;

    let mut relation = Vec::new();
    statement.serialize(&mut relation)?;

    let mut commitments = Vec::new();
    statement.simulate(claimed, response, &mut commitments);
    let mut commitment_bytes = Vec::with_capacity(commitments.len() * POINT_LENGTH);
    for commitment in &commitments {
        // Step 7: a simulated commitment equal to the identity is rejected.
        commitment_bytes.extend_from_slice(&commitment.to_bytes().ok_or(Error::Verify)?);
    }

    let expected = challenge::<B>(session_id, &relation, &commitment_bytes);
    if bool::from(claimed.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(Error::Verify)
    }
}
