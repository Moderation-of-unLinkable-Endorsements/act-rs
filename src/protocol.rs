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

//! The credential scheme: configuration, keys, issuance, spending, and
//! refunds, following Section 5 of the draft.

use alloc::vec::Vec;
use core::fmt;

use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::backend::{Backend, FixedBase, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::hash::{self, NSEED};
use crate::random::{Random, SystemRandom};
use crate::sigma;
use crate::statements::{Commitment, Signature, Spend, fixed, horner_points, horner_scalars};
use crate::{DefaultBackend, Error, MAX_BALANCE_WIDTH};

/// The group generator `B` and the four ciphersuite generators, the latter
/// with whatever precomputation the backend offers.
///
/// `H1` commits to the balance, `H2` to the nullifier, `H3` is the
/// blinding base, and `H4` binds the credential context.
#[derive(Clone, Debug)]
pub(crate) struct Generators<B: Backend> {
    pub(crate) g: B::Point,
    pub(crate) h1: B::FixedBase,
    pub(crate) h2: B::FixedBase,
    pub(crate) h3: B::FixedBase,
    pub(crate) h4: B::FixedBase,
}

/// The ACT configuration: the `P256-SHA256` ciphersuite at a balance width.
///
/// Balances and amounts are integers in `[0, 2^L)`. `L` is fixed for the
/// lifetime of a key and credential context, and every party of a
/// deployment uses the same value.
#[derive(Clone, Debug)]
pub struct Params<B: Backend = DefaultBackend> {
    l: u8,
    max_amount: u64,
    gens: Generators<B>,
    sid_issue_request: [u8; 32],
    sid_issue_response: [u8; 32],
    sid_refund: [u8; 32],
}

impl<B: Backend> Params<B> {
    /// Instantiates the ciphersuite at balance width `balance_width`, which
    /// must be in `1..=64`.
    pub fn new(balance_width: u8) -> Result<Self, Error> {
        if balance_width == 0 || balance_width > MAX_BALANCE_WIDTH {
            return Err(Error::InvalidInput);
        }
        let generator = |label: &[u8]| {
            B::hash_to_curve(&[label], &[hash::DST_HASH_TO_GROUP])
                .map(B::FixedBase::new)
                .ok_or(Error::Derive)
        };
        let gens = Generators {
            g: B::Point::generator(),
            h1: generator(b"GenH1")?,
            h2: generator(b"GenH2")?,
            h3: generator(b"GenH3")?,
            h4: generator(b"GenH4")?,
        };
        let session_id =
            |label: &[u8]| Ok::<_, Error>(sigma::session_id::<B>(&sigma::tag(label, &[])?));
        Ok(Self {
            l: balance_width,
            max_amount: u64::MAX >> (64 - u32::from(balance_width)),
            gens,
            sid_issue_request: session_id(b"IssueRequest")?,
            sid_issue_response: session_id(b"IssueResponse")?,
            sid_refund: session_id(b"Refund")?,
        })
    }

    /// The balance width `L`.
    pub fn balance_width(&self) -> u8 {
        self.l
    }

    /// The largest balance or amount, `2^L - 1`.
    pub fn max_amount(&self) -> u64 {
        self.max_amount
    }

    pub(crate) fn check_amount(&self, amount: u64) -> Result<(), Error> {
        if amount > self.max_amount {
            Err(Error::Amount)
        } else {
            Ok(())
        }
    }

    fn l(&self) -> usize {
        usize::from(self.l)
    }

    #[cfg(test)]
    pub(crate) fn generators(&self) -> &Generators<B> {
        &self.gens
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The Moderator's key pair. The secret scalar both signs and verifies.
#[derive(Clone)]
pub struct SecretKey<B: Backend = DefaultBackend> {
    sk: B::Scalar,
    pk: B::Point,
}

impl<B: Backend> SecretKey<B> {
    /// `G.GenerateKeyPair()`: a key pair from fresh randomness.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with(&mut SystemRandom::<B>::new())
    }

    pub(crate) fn generate_with<R: Random>(rng: &mut R) -> Result<Self, Error> {
        let mut seed = [0u8; NSEED];
        rng.fill(&mut seed);
        let key = Self::from_seed(&seed, b"GenerateKeyPair");
        seed.zeroize();
        key
    }

    /// `G.DeriveKeyPair(seed, info)`: a key pair from a seed of `Nseed`
    /// uniformly random bytes that is used for nothing else.
    pub fn from_seed(seed: &[u8; NSEED], info: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_scalar(hash::derive_scalar::<B>(seed, info)?))
    }

    /// The key pair whose secret scalar is `bytes`, big-endian.
    pub fn from_bytes(bytes: &[u8; SCALAR_LENGTH]) -> Result<Self, Error> {
        let sk = hash::require(B::Scalar::from_bytes(bytes), Error::Deserialize)?;
        if bool::from(sk.is_zero()) {
            return Err(Error::Deserialize);
        }
        Ok(Self::from_scalar(sk))
    }

    fn from_scalar(sk: B::Scalar) -> Self {
        let pk = B::Point::mul_generator(&sk);
        Self { sk, pk }
    }

    /// The secret scalar `skM`, big-endian.
    pub fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        self.sk.to_bytes()
    }

    /// The public key `pkM`.
    pub fn public_key(&self) -> PublicKey<B> {
        PublicKey {
            pk: self.pk.clone(),
        }
    }
}

impl<B: Backend> Zeroize for SecretKey<B> {
    fn zeroize(&mut self) {
        self.sk.zeroize();
        self.pk.zeroize();
    }
}

impl<B: Backend> Drop for SecretKey<B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<B: Backend> ZeroizeOnDrop for SecretKey<B> {}

impl<B: Backend> fmt::Debug for SecretKey<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("pk", &self.pk)
            .finish_non_exhaustive()
    }
}

/// The Moderator's public key `pkM`, published in its configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<B: Backend = DefaultBackend> {
    pk: B::Point,
}

impl<B: Backend> PublicKey<B> {
    /// `SerializeElement(pkM)`.
    pub fn to_bytes(&self) -> [u8; POINT_LENGTH] {
        point_bytes(&self.pk)
    }

    /// Parses `SerializeElement(pkM)`.
    pub fn from_bytes(bytes: &[u8; POINT_LENGTH]) -> Result<Self, Error> {
        Ok(Self {
            pk: hash::require(B::Point::from_bytes(bytes), Error::Deserialize)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// The Client's state between `issue_request` and `finalize_issue`.
///
/// Holds the nullifier `k` and blinding factor `r` of the Credential being
/// issued. It must be finalized against at most one response.
pub struct ClientIssuanceState<B: Backend = DefaultBackend> {
    pub(crate) k: B::Scalar,
    pub(crate) r: B::Scalar,
    pub(crate) k_commitment: B::Point,
}

/// The Client's opening message of issuance: `(K, pok)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueRequestMessage<B: Backend = DefaultBackend> {
    pub(crate) k_commitment: B::Point,
    pub(crate) pok: [u8; 3 * SCALAR_LENGTH],
}

/// The Moderator's response to an issuance request: `(A, e, c, pok)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueResponseMessage<B: Backend = DefaultBackend> {
    pub(crate) a: B::Point,
    pub(crate) e: B::Scalar,
    pub(crate) c: u64,
    pub(crate) pok: [u8; 2 * SCALAR_LENGTH],
}

impl<B: Backend> IssueResponseMessage<B> {
    /// The balance `c` the Moderator chose.
    pub fn balance(&self) -> u64 {
        self.c
    }
}

/// A Credential `(k, c, r, A, e)`: a signature on the hidden balance `c`,
/// nullifier `k`, and blinding factor `r`, under the context it was issued
/// under. It is held by the Client and never sent.
pub struct Credential<B: Backend = DefaultBackend> {
    pub(crate) k: B::Scalar,
    pub(crate) c: u64,
    pub(crate) r: B::Scalar,
    pub(crate) a: B::Point,
    pub(crate) e: B::Scalar,
}

impl<B: Backend> Credential<B> {
    /// The balance `c`.
    pub fn balance(&self) -> u64 {
        self.c
    }
}

/// The Client's state between `prove_spend` and `finalize_refund`.
///
/// Holds everything `finalize_refund` needs: the next Credential's
/// nullifier `kstar` and blinding factor `r_star`, the remainder `v1`, the
/// amounts, and the commitment `K_prime` the refund signs. It must be
/// stored durably before the spend proof leaves the Client, and finalized
/// against at most one refund.
pub struct ClientSpendState<B: Backend = DefaultBackend> {
    pub(crate) kstar: B::Scalar,
    pub(crate) r_star: B::Scalar,
    pub(crate) v1: u64,
    pub(crate) s: u64,
    pub(crate) a: u64,
    pub(crate) k_prime: B::Point,
}

impl<B: Backend> ClientSpendState<B> {
    /// The remainder `c - s` that the refund tops up.
    pub fn remainder(&self) -> u64 {
        self.v1
    }
}

/// A spend: the nullifier, the public amounts, the rerandomized signature,
/// the commitments, and the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendMessage<B: Backend = DefaultBackend> {
    pub(crate) k: B::Scalar,
    pub(crate) s: u64,
    pub(crate) a: u64,
    pub(crate) a_prime: B::Point,
    pub(crate) b_bar: B::Point,
    pub(crate) k_n: B::Point,
    pub(crate) com1: Vec<B::Point>,
    pub(crate) com_c: Option<B::Point>,
    pub(crate) com2: Vec<B::Point>,
    pub(crate) pok: Vec<u8>,
}

impl<B: Backend> SpendMessage<B> {
    /// The nullifier `k` of the spent Credential, big-endian.
    ///
    /// The Moderator must reject a spend whose nullifier it has recorded,
    /// and record it atomically with verification and the refund.
    pub fn nullifier(&self) -> [u8; SCALAR_LENGTH] {
        self.k.to_bytes()
    }

    /// The spent amount `s`.
    pub fn amount(&self) -> u64 {
        self.s
    }

    /// The top-up allowance `a`.
    pub fn allowance(&self) -> u64 {
        self.a
    }
}

/// The Moderator's refund: a signature on the remainder plus `t`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundMessage<B: Backend = DefaultBackend> {
    pub(crate) a: B::Point,
    pub(crate) e: B::Scalar,
    pub(crate) t: u64,
    pub(crate) pok: [u8; 2 * SCALAR_LENGTH],
}

impl<B: Backend> RefundMessage<B> {
    /// The return amount `t`.
    pub fn return_amount(&self) -> u64 {
        self.t
    }
}

/// A record that holds secrets: zeroized on drop and redacted in `Debug`.
macro_rules! secret_record {
    ($type:ident { $($scalar:ident),* ; $($point:ident),* ; $($plain:ident),* }) => {
        impl<B: Backend> Zeroize for $type<B> {
            fn zeroize(&mut self) {
                $(self.$scalar.zeroize();)*
                $(self.$point.zeroize();)*
                $(self.$plain.zeroize();)*
            }
        }

        impl<B: Backend> Drop for $type<B> {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl<B: Backend> ZeroizeOnDrop for $type<B> {}

        impl<B: Backend> fmt::Debug for $type<B> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($type)).finish_non_exhaustive()
            }
        }
    };
}

secret_record!(ClientIssuanceState { k, r; k_commitment; });
secret_record!(Credential { k, r, e; a; c });
secret_record!(ClientSpendState { kstar, r_star; k_prime; v1, s, a });

// ---------------------------------------------------------------------------
// Shared computations
// ---------------------------------------------------------------------------

/// `CreateContextScalar(ctx_cred)`.
fn context_scalar<B: Backend>(ctx_cred: &[u8]) -> Result<B::Scalar, Error> {
    let len = u16::try_from(ctx_cred.len()).map_err(|_| Error::InvalidInput)?;
    Ok(hash::hash_to_scalar::<B>(
        &[&len.to_be_bytes(), ctx_cred, b"CredentialContext"],
        hash::DST_HASH_TO_SCALAR,
    ))
}

/// `B + c * H1 + ctx * H4 + K`, the message an issuance signs.
fn issuance_message<B: Backend>(
    gens: &Generators<B>,
    c: u64,
    ctx: &B::Scalar,
    k: &B::Point,
) -> B::Point {
    fixed::<B, 2>([(&gens.h1, &B::Scalar::from(c)), (&gens.h4, ctx)])
        .add(&gens.g)
        .add(k)
}

/// `SigningExponent`: the exponent `e` of a signature on `x_a`, derived
/// from the signing key and the message, and `x = e + skM`.
fn signing_exponent<B: Backend, R: Random>(
    key: &SecretKey<B>,
    label: &[u8],
    x_a: &B::Point,
    rng: &mut R,
) -> Result<(B::Scalar, B::Scalar), Error> {
    let x_a_bytes = x_a.to_bytes().ok_or(Error::Verify)?;
    let label_len = u16::try_from(label.len()).map_err(|_| Error::InvalidInput)?;
    let mut aux = [0u8; NSEED];
    rng.fill(&mut aux);
    let mut sk_bytes = key.sk.to_bytes();
    let e = hash::derive_nonce::<B>(
        &sk_bytes,
        b"e",
        &[
            &label_len.to_be_bytes(),
            label,
            &(POINT_LENGTH as u16).to_be_bytes(),
            &x_a_bytes,
        ],
        &aux,
    );
    sk_bytes.zeroize();
    aux.zeroize();
    let e = e?;
    let x = e + key.sk;
    if bool::from(x.is_zero()) {
        return Err(Error::Derive);
    }
    Ok((e, x))
}

/// A signature `(A, e)` with its `Signature` proof.
type SignedMessage<B> = (
    <B as Backend>::Point,
    <B as Backend>::Scalar,
    [u8; 2 * SCALAR_LENGTH],
);

/// Signs `x_a` as `(A, e)` with `A = x_a / (e + skM)` and proves it.
fn sign<B: Backend, R: Random>(
    key: &SecretKey<B>,
    label: &[u8],
    session_id: &[u8; 32],
    x_a: &B::Point,
    rng: &mut R,
) -> Result<SignedMessage<B>, Error> {
    let (e, mut x) = signing_exponent(key, label, x_a, rng)?;
    let mut x_inv = hash::require(x.invert(), Error::Derive)?;
    let a = x_a.mul(&x_inv);
    x_inv.zeroize();
    let x_g = B::Point::mul_generator(&x);
    let statement = Signature {
        a: &a,
        x_a,
        x_g: &x_g,
    };
    let pok = sigma::prove::<B, _, _>(session_id, &statement, &[x], rng);
    x.zeroize();
    Ok((a, e, proof_array(pok?)?))
}

/// Verifies the `Signature` proof of `(a, e)` on `x_a` under `pk`.
fn verify_signature<B: Backend>(
    session_id: &[u8; 32],
    pk: &PublicKey<B>,
    a: &B::Point,
    e: &B::Scalar,
    x_a: &B::Point,
    pok: &[u8],
) -> Result<(), Error> {
    let x_g = B::Point::mul_generator(e).add(&pk.pk);
    sigma::verify::<B, _>(session_id, &Signature { a, x_a, x_g: &x_g }, pok)
}

/// `Bits(x)`: the `l` low bits of `x` as scalars, in constant time.
fn bits<B: Backend>(x: u64, l: usize) -> Vec<B::Scalar> {
    let (zero, one) = (B::Scalar::default(), B::Scalar::from(1));
    (0..l)
        .map(|j| {
            let bit = Choice::from(((x >> j) & 1) as u8);
            B::Scalar::conditional_select(&zero, &one, bit)
        })
        .collect()
}

/// `Seed(rand, index)`.
fn seed(rand: &[u8], index: usize) -> Result<&[u8; NSEED], Error> {
    rand.get(index * NSEED..(index + 1) * NSEED)
        .and_then(|chunk| chunk.try_into().ok())
        .ok_or(Error::InvalidInput)
}

fn proof_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Verify)
}

/// Encodes a point that is not the identity by construction.
pub(crate) fn point_bytes<P: Point>(point: &P) -> [u8; POINT_LENGTH] {
    debug_assert!(!bool::from(point.is_identity()));
    // The identity cannot occur here; the all-zero string, which never
    // decodes, stands in rather than a panic.
    point.to_bytes().unwrap_or([0; POINT_LENGTH])
}

/// A range block over `value`: the bit commitments `Com[j] = b[j] * H1 +
/// s[j] * H3`, with the bits, blindings, and products `u[j] = (1 - b[j]) *
/// s[j]` appended to `witness` in that order. Returns the commitments and
/// `sum_j 2^j * s[j]`, the block's contribution to the blinding factor of
/// the refunded Credential. Constant time in `value`.
fn range_block<B: Backend>(
    gens: &Generators<B>,
    l: usize,
    value: u64,
    label: &[u8; 2],
    rand: &[u8],
    next_seed: usize,
    witness: &mut Vec<B::Scalar>,
) -> Result<(Vec<B::Point>, B::Scalar), Error> {
    let one = B::Scalar::from(1);
    let mut bits = bits::<B>(value, l);
    let mut blindings = Vec::with_capacity(l);
    let mut commitments = Vec::with_capacity(l);
    for (j, bit) in bits.iter().enumerate() {
        let info = [label[0], label[1], j as u8];
        let blinding = hash::derive_scalar::<B>(seed(rand, next_seed + j)?, &info)?;
        commitments.push(fixed::<B, 2>([(&gens.h1, bit), (&gens.h3, &blinding)]));
        blindings.push(blinding);
    }
    let mut products: Vec<B::Scalar> = bits
        .iter()
        .zip(&blindings)
        .map(|(b, s)| (one - *b) * *s)
        .collect();
    let blinding_sum = horner_scalars(&blindings);
    witness.extend_from_slice(&bits);
    witness.extend_from_slice(&blindings);
    witness.extend_from_slice(&products);
    bits.zeroize();
    blindings.zeroize();
    products.zeroize();
    Ok((commitments, blinding_sum))
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// `IssueRequest`: commits to a fresh nullifier and blinding factor.
pub fn issue_request<B: Backend>(
    params: &Params<B>,
) -> Result<(ClientIssuanceState<B>, IssueRequestMessage<B>), Error> {
    issue_request_with(params, &mut SystemRandom::<B>::new())
}

pub(crate) fn issue_request_with<B: Backend, R: Random>(
    params: &Params<B>,
    rng: &mut R,
) -> Result<(ClientIssuanceState<B>, IssueRequestMessage<B>), Error> {
    let gens = &params.gens;
    let mut rand = [0u8; 2 * NSEED];
    rng.fill(&mut rand);
    let k = hash::derive_scalar::<B>(seed(&rand, 0)?, b"k");
    let r = hash::derive_scalar::<B>(seed(&rand, 1)?, b"r");
    rand.zeroize();
    let (k, r) = (k?, r?);

    let k_commitment = fixed::<B, 2>([(&gens.h2, &k), (&gens.h3, &r)]);
    let statement = Commitment {
        gens,
        k: &k_commitment,
    };
    let pok = sigma::prove::<B, _, _>(&params.sid_issue_request, &statement, &[k, r], rng)?;

    Ok((
        ClientIssuanceState {
            k,
            r,
            k_commitment: k_commitment.clone(),
        },
        IssueRequestMessage {
            k_commitment,
            pok: proof_array(pok)?,
        },
    ))
}

/// `IssueResponse`: checks the request and signs a Credential with balance
/// `c` under `ctx_cred`.
pub fn issue_response<B: Backend>(
    params: &Params<B>,
    key: &SecretKey<B>,
    ctx_cred: &[u8],
    c: u64,
    request: &IssueRequestMessage<B>,
) -> Result<IssueResponseMessage<B>, Error> {
    issue_response_with(
        params,
        key,
        ctx_cred,
        c,
        request,
        &mut SystemRandom::<B>::new(),
    )
}

pub(crate) fn issue_response_with<B: Backend, R: Random>(
    params: &Params<B>,
    key: &SecretKey<B>,
    ctx_cred: &[u8],
    c: u64,
    request: &IssueRequestMessage<B>,
    rng: &mut R,
) -> Result<IssueResponseMessage<B>, Error> {
    let gens = &params.gens;
    params.check_amount(c)?;
    let statement = Commitment {
        gens,
        k: &request.k_commitment,
    };
    sigma::verify::<B, _>(&params.sid_issue_request, &statement, &request.pok)?;

    let ctx = context_scalar::<B>(ctx_cred)?;
    let x_a = issuance_message(gens, c, &ctx, &request.k_commitment);
    let (a, e, pok) = sign(key, b"IssueResponse", &params.sid_issue_response, &x_a, rng)?;
    Ok(IssueResponseMessage { a, e, c, pok })
}

/// `FinalizeIssue`: checks the response and assembles the Credential.
///
/// Consumes `state`; the Client must not finalize one state against two
/// responses.
pub fn finalize_issue<B: Backend>(
    params: &Params<B>,
    public_key: &PublicKey<B>,
    ctx_cred: &[u8],
    state: ClientIssuanceState<B>,
    response: &IssueResponseMessage<B>,
) -> Result<Credential<B>, Error> {
    let gens = &params.gens;
    params.check_amount(response.c)?;
    let ctx = context_scalar::<B>(ctx_cred)?;
    let x_a = issuance_message(gens, response.c, &ctx, &state.k_commitment);
    verify_signature(
        &params.sid_issue_response,
        public_key,
        &response.a,
        &response.e,
        &x_a,
        &response.pok,
    )?;
    Ok(Credential {
        k: state.k,
        c: response.c,
        r: state.r,
        a: response.a.clone(),
        e: response.e,
    })
}

// ---------------------------------------------------------------------------
// Spending
// ---------------------------------------------------------------------------

/// `ProveSpend`: spends `s` credits of `credential` with top-up allowance
/// `a`, bound to `ctx_spend`.
///
/// Consumes the Credential. The returned state must be stored durably
/// before the message leaves the Client; the refund is unusable without
/// it, and a second proof from the same Credential reveals the same
/// nullifier.
pub fn prove_spend<B: Backend>(
    params: &Params<B>,
    credential: Credential<B>,
    ctx_cred: &[u8],
    s: u64,
    a: u64,
    ctx_spend: &[u8],
) -> Result<(ClientSpendState<B>, SpendMessage<B>), Error> {
    prove_spend_with(
        params,
        credential,
        ctx_cred,
        s,
        a,
        ctx_spend,
        &mut SystemRandom::<B>::new(),
    )
}

pub(crate) fn prove_spend_with<B: Backend, R: Random>(
    params: &Params<B>,
    credential: Credential<B>,
    ctx_cred: &[u8],
    s: u64,
    a: u64,
    ctx_spend: &[u8],
    rng: &mut R,
) -> Result<(ClientSpendState<B>, SpendMessage<B>), Error> {
    let gens = &params.gens;
    let l = params.l();
    params.check_amount(s)?;
    params.check_amount(a)?;
    let c = credential.c;
    // Over the integers: `s <= c` and `c + a < 2^L`.
    if s > c || u128::from(c) + u128::from(a) > u128::from(params.max_amount) {
        return Err(Error::Amount);
    }
    let v1 = c - s;
    let v2 = c + a;

    let ctx = context_scalar::<B>(ctx_cred)?;
    let tag = sigma::tag(b"Spend", &[ctx_spend])?;
    let session_id = sigma::session_id::<B>(&tag);

    // One seed per scalar: four fixed ones, then L for the bits of the
    // remainder or one for its commitment, then L for the bits of the
    // topped-up balance.
    let seeds = 4 + if s > 0 { l } else { 1 } + if a > 0 { l } else { 0 };
    let mut rand = alloc::vec![0u8; seeds * NSEED];
    rng.fill(&mut rand);
    let mut r1 = hash::derive_scalar::<B>(seed(&rand, 0)?, b"r1")?;
    let mut r2 = hash::derive_scalar::<B>(seed(&rand, 1)?, b"r2")?;
    let kstar = hash::derive_scalar::<B>(seed(&rand, 2)?, b"kstar")?;
    let mut rn = hash::derive_scalar::<B>(seed(&rand, 3)?, b"rn")?;
    let mut next_seed = 4;

    // Rerandomize the signature.
    let mut c_scalar = B::Scalar::from(c);
    let mut b_msg = fixed::<B, 4>([
        (&gens.h1, &c_scalar),
        (&gens.h2, &credential.k),
        (&gens.h3, &credential.r),
        (&gens.h4, &ctx),
    ])
    .add(&gens.g);
    let a_prime = credential.a.mul(&(r1 * r2));
    let b_bar = b_msg.mul(&r1);
    let mut r3 = hash::require(r1.invert(), Error::Derive)?;
    let mut a_bar = B::Point::lincomb([(&b_bar, &r2), (&a_prime, &-credential.e)]);

    // Commit to the next Credential's nullifier.
    let k_n = fixed::<B, 2>([(&gens.h2, &kstar), (&gens.h3, &rn)]);

    let mut witness: Vec<B::Scalar> =
        alloc::vec![credential.e, r2, r3, c_scalar, credential.r, kstar, rn];
    let mut com1 = Vec::new();
    let mut com_c = None;
    let mut com2 = Vec::new();

    // Commit to the remainder: bitwise when it must be shown to be
    // nonnegative, in one commitment when it is the balance itself.
    let r_star;
    if s > 0 {
        let (commitments, blinding_sum) =
            range_block::<B>(gens, l, v1, b"s1", &rand, next_seed, &mut witness)?;
        com1 = commitments;
        r_star = rn + blinding_sum;
        next_seed += l;
    } else {
        let mut rc = hash::derive_scalar::<B>(seed(&rand, next_seed)?, b"rc")?;
        com_c = Some(fixed::<B, 2>([(&gens.h1, &c_scalar), (&gens.h3, &rc)]));
        r_star = rn + rc;
        witness.push(rc);
        rc.zeroize();
        next_seed += 1;
    }

    // Commit to the topped-up balance when there is a top-up.
    if a > 0 {
        let (commitments, _) =
            range_block::<B>(gens, l, v2, b"s2", &rand, next_seed, &mut witness)?;
        com2 = commitments;
    }
    rand.zeroize();

    let h1_prime = fixed::<B, 2>([(&gens.h2, &credential.k), (&gens.h4, &ctx)]).add(&gens.g);
    let statement = Spend::new(
        gens,
        l,
        &a_prime,
        &b_bar,
        &a_bar,
        &h1_prime,
        &k_n,
        s,
        a,
        &com1,
        com_c.as_ref(),
        &com2,
    )?;
    let pok = sigma::prove::<B, _, _>(&session_id, &statement, &witness, rng);
    // Everything derived from the balance or the blinding factors, beyond
    // what the state and the message carry, is cleared before returning.
    witness.zeroize();
    b_msg.zeroize();
    a_bar.zeroize();
    for scalar in [&mut r1, &mut r2, &mut r3, &mut c_scalar, &mut rn] {
        scalar.zeroize();
    }
    let pok = pok?;

    // The commitment the refund will sign, opened by the new Credential's
    // secrets; the Moderator recomputes it from the message.
    let k_prime = fixed::<B, 3>([
        (&gens.h1, &B::Scalar::from(v1)),
        (&gens.h2, &kstar),
        (&gens.h3, &r_star),
    ]);

    let state = ClientSpendState {
        kstar,
        r_star,
        v1,
        s,
        a,
        k_prime,
    };
    let message = SpendMessage {
        k: credential.k,
        s,
        a,
        a_prime,
        b_bar,
        k_n,
        com1,
        com_c,
        com2,
        pok,
    };
    Ok((state, message))
}

/// `VerifySpend`: checks a spend proof under the Moderator's key and
/// contexts.
///
/// Does not check the nullifier against the Moderator's record, nor
/// whether the Moderator grants the allowance `a`; the caller must do both.
pub fn verify_spend<B: Backend>(
    params: &Params<B>,
    key: &SecretKey<B>,
    ctx_cred: &[u8],
    ctx_spend: &[u8],
    spend: &SpendMessage<B>,
) -> Result<(), Error> {
    let gens = &params.gens;
    params.check_amount(spend.s)?;
    params.check_amount(spend.a)?;
    let ctx = context_scalar::<B>(ctx_cred)?;
    let mut a_bar = spend.a_prime.mul(&key.sk);
    let h1_prime = fixed::<B, 2>([(&gens.h2, &spend.k), (&gens.h4, &ctx)]).add(&gens.g);
    let tag = sigma::tag(b"Spend", &[ctx_spend])?;
    let result = spend_statement(params, spend, &a_bar, &h1_prime).and_then(|statement| {
        sigma::verify::<B, _>(&sigma::session_id::<B>(&tag), &statement, &spend.pok)
    });
    // `A_bar` is a function of the signing key; it does not outlive the check.
    a_bar.zeroize();
    result
}

fn spend_statement<'a, B: Backend>(
    params: &'a Params<B>,
    spend: &'a SpendMessage<B>,
    a_bar: &'a B::Point,
    h1_prime: &'a B::Point,
) -> Result<Spend<'a, B>, Error> {
    Spend::new(
        &params.gens,
        params.l(),
        &spend.a_prime,
        &spend.b_bar,
        a_bar,
        h1_prime,
        &spend.k_n,
        spend.s,
        spend.a,
        &spend.com1,
        spend.com_c.as_ref(),
        &spend.com2,
    )
}

/// `BalanceCommitment(proof)`: `K_n + V1`, which the refund signs, with
/// `V1` the bit commitments combined or, for `s = 0`, `Com_c`.
fn balance_commitment<B: Backend>(
    params: &Params<B>,
    spend: &SpendMessage<B>,
) -> Result<B::Point, Error> {
    let v1 = match (&spend.com_c, spend.s) {
        (None, s) if s > 0 && spend.com1.len() == params.l() => horner_points(&spend.com1),
        (Some(com_c), 0) => com_c.clone(),
        _ => return Err(Error::Verify),
    };
    Ok(spend.k_n.add(&v1))
}

/// `B + K_prime + t * H1 + ctx * H4`, the message a refund signs.
fn refund_message<B: Backend>(
    gens: &Generators<B>,
    k_prime: &B::Point,
    t: u64,
    ctx: &B::Scalar,
) -> B::Point {
    fixed::<B, 2>([(&gens.h1, &B::Scalar::from(t)), (&gens.h4, ctx)])
        .add(&gens.g)
        .add(k_prime)
}

/// `IssueRefund`: after a successful `verify_spend`, signs the remainder
/// plus the return amount `t`, where `t <= s + a`.
pub fn issue_refund<B: Backend>(
    params: &Params<B>,
    key: &SecretKey<B>,
    ctx_cred: &[u8],
    spend: &SpendMessage<B>,
    t: u64,
) -> Result<RefundMessage<B>, Error> {
    issue_refund_with(
        params,
        key,
        ctx_cred,
        spend,
        t,
        &mut SystemRandom::<B>::new(),
    )
}

pub(crate) fn issue_refund_with<B: Backend, R: Random>(
    params: &Params<B>,
    key: &SecretKey<B>,
    ctx_cred: &[u8],
    spend: &SpendMessage<B>,
    t: u64,
    rng: &mut R,
) -> Result<RefundMessage<B>, Error> {
    params.check_amount(t)?;
    if u128::from(t) > u128::from(spend.s) + u128::from(spend.a) {
        return Err(Error::Amount);
    }
    let ctx = context_scalar::<B>(ctx_cred)?;
    let k_prime = balance_commitment(params, spend)?;
    let x_a = refund_message(&params.gens, &k_prime, t, &ctx);
    let (a, e, pok) = sign(key, b"Refund", &params.sid_refund, &x_a, rng)?;
    Ok(RefundMessage { a, e, t, pok })
}

/// `FinalizeRefund`: checks the refund and assembles the new Credential,
/// with balance `c - s + t`.
///
/// Consumes `state`; the Client must not finalize one state against two
/// refunds.
pub fn finalize_refund<B: Backend>(
    params: &Params<B>,
    public_key: &PublicKey<B>,
    ctx_cred: &[u8],
    state: ClientSpendState<B>,
    refund: &RefundMessage<B>,
) -> Result<Credential<B>, Error> {
    let t = refund.t;
    params.check_amount(t)?;
    let (s, a, v1) = (
        u128::from(state.s),
        u128::from(state.a),
        u128::from(state.v1),
    );
    if u128::from(t) > s + a || v1 + u128::from(t) > u128::from(params.max_amount) {
        return Err(Error::Amount);
    }
    let ctx = context_scalar::<B>(ctx_cred)?;
    let x_a = refund_message(&params.gens, &state.k_prime, t, &ctx);
    verify_signature(
        &params.sid_refund,
        public_key,
        &refund.a,
        &refund.e,
        &x_a,
        &refund.pok,
    )?;
    Ok(Credential {
        k: state.kstar,
        c: state.v1 + t,
        r: state.r_star,
        a: refund.a.clone(),
        e: refund.e,
    })
}

#[cfg(test)]
pub(crate) fn context_scalar_for_tests<B: Backend>(ctx_cred: &[u8]) -> B::Scalar {
    context_scalar::<B>(ctx_cred).unwrap_or_default()
}
