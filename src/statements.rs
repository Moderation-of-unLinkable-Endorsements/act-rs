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

//! The three relations of the draft as fixed-shape statements.
//!
//! Each `impl` documents the compiled index layout of its `Relation` block:
//! elements are numbered in declaration order with the generator at 0, and
//! witness scalars likewise. The serialization written here must match
//! `SerializeLinearRelation` of that compiled relation byte for byte, which
//! the test vectors pin.
//!
//! Terms on the ciphersuite generators go through the backend's fixed-base
//! multiplication; terms on statement-specific points use `Point::lincomb`.

use alloc::vec::Vec;

use crate::Error;
use crate::backend::{Backend, FixedBase, Point, SCALAR_LENGTH, Scalar};
use crate::protocol::Generators;
use crate::sigma::{MINUS_ONE, ONE, RelationWriter, Statement, coefficient, order_minus};

/// Rejects the identity element among statement elements or images.
fn nonidentity<P: Point>(point: &P) -> Result<(), Error> {
    if bool::from(point.is_identity()) {
        Err(Error::Verify)
    } else {
        Ok(())
    }
}

/// `sum_i scalar_i * base_i` over precomputed bases.
pub(crate) fn fixed<B: Backend, const N: usize>(
    terms: [(&B::FixedBase, &B::Scalar); N],
) -> B::Point {
    let mut terms = terms.into_iter();
    let Some((base, scalar)) = terms.next() else {
        return B::Point::identity();
    };
    terms.fold(base.mul(scalar), |acc, (base, scalar)| {
        acc.add(&base.mul(scalar))
    })
}

/// `sum_j 2^j * x[j]` by Horner's rule, in constant time.
pub(crate) fn horner_scalars<S: Scalar>(scalars: &[S]) -> S {
    scalars
        .iter()
        .rev()
        .fold(S::default(), |acc, x| acc + acc + *x)
}

/// `sum_j 2^j * P[j]` by Horner's rule: doublings and additions instead of
/// scalar multiplications.
pub(crate) fn horner_points<P: Point>(points: &[P]) -> P {
    points
        .iter()
        .rev()
        .fold(P::identity(), |acc, p| acc.double().add(p))
}

// ---------------------------------------------------------------------------
// Relation Commitment(H2, H3, K): Witness k, r; K = k * H2 + r * H3
//   elements: G 0, H2 1, H3 2, K 3      scalars: k 0, r 1
// ---------------------------------------------------------------------------

/// The `Commitment` relation of the issuance request.
pub(crate) struct Commitment<'a, B: Backend> {
    pub(crate) gens: &'a Generators<B>,
    pub(crate) k: &'a B::Point,
}

impl<B: Backend> Statement<B> for Commitment<'_, B> {
    fn num_scalars(&self) -> usize {
        2
    }

    fn num_equations(&self) -> usize {
        1
    }

    fn validate(&self) -> Result<(), Error> {
        nonidentity(self.k)
    }

    fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = RelationWriter::new(out);
        w.equations(self.num_equations());
        w.image(&[(3, &ONE)]);
        w.terms(&[(0, 1, &ONE), (1, 2, &ONE)]);
        w.element(self.gens.h2.point())?;
        w.element(self.gens.h3.point())?;
        w.element(self.k)
    }

    fn commit(&self, n: &[B::Scalar], out: &mut Vec<B::Point>) {
        out.push(fixed::<B, 2>([
            (&self.gens.h2, &n[0]),
            (&self.gens.h3, &n[1]),
        ]));
    }

    fn simulate(&self, c: &B::Scalar, z: &[B::Scalar], out: &mut Vec<B::Point>) {
        let generators = fixed::<B, 2>([(&self.gens.h2, &z[0]), (&self.gens.h3, &z[1])]);
        out.push(generators.add(&self.k.mul(&-*c)));
    }
}

// ---------------------------------------------------------------------------
// Relation Signature(A, X_A, X_G): Witness x; X_A = x * A, X_G = x * G
//   elements: G 0, A 1, X_A 2, X_G 3     scalars: x 0
// ---------------------------------------------------------------------------

/// The `Signature` relation of the issuance response and the refund.
pub(crate) struct Signature<'a, B: Backend> {
    pub(crate) a: &'a B::Point,
    pub(crate) x_a: &'a B::Point,
    pub(crate) x_g: &'a B::Point,
}

impl<B: Backend> Statement<B> for Signature<'_, B> {
    fn num_scalars(&self) -> usize {
        1
    }

    fn num_equations(&self) -> usize {
        2
    }

    fn validate(&self) -> Result<(), Error> {
        nonidentity(self.a)?;
        nonidentity(self.x_a)?;
        nonidentity(self.x_g)
    }

    fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = RelationWriter::new(out);
        w.equations(self.num_equations());
        w.image(&[(2, &ONE)]);
        w.terms(&[(0, 1, &ONE)]);
        w.image(&[(3, &ONE)]);
        w.terms(&[(0, 0, &ONE)]);
        w.element(self.a)?;
        w.element(self.x_a)?;
        w.element(self.x_g)
    }

    fn commit(&self, n: &[B::Scalar], out: &mut Vec<B::Point>) {
        out.push(self.a.mul(&n[0]));
        out.push(B::Point::mul_generator(&n[0]));
    }

    fn simulate(&self, c: &B::Scalar, z: &[B::Scalar], out: &mut Vec<B::Point>) {
        let minus_c = -*c;
        out.push(B::Point::lincomb([(self.a, &z[0]), (self.x_a, &minus_c)]));
        out.push(B::Point::mul_generator(&z[0]).add(&self.x_g.mul(&minus_c)));
    }
}

// ---------------------------------------------------------------------------
// Relation Spend(H1, H2, H3, A_prime, B_bar, A_bar, H1_prime, K_n, s, a,
//                Com1[0..L] (s > 0) | Com_c (s = 0), Com2[0..L] (a > 0))
//   elements: G 0, H1 1, H2 2, H3 3, A_prime 4, B_bar 5, A_bar 6,
//             H1_prime 7, K_n 8, Com1[j] 9+j | Com_c 9, Com2[j] base2+j
//   scalars:  e 0, r2 1, r3 2, c 3, r 4, kstar 5, rn 6,
//             b1[j] 7+j, s1[j] 7+L+j, u1[j] 7+2L+j | rc 7,
//             b2[j] w2+j, s2[j] w2+L+j, u2[j] w2+2L+j
//   equations, in order:
//     A_bar    = -e * A_prime + r2 * B_bar
//     H1_prime = r3 * B_bar - c * H1 - r * H3
//     K_n      = kstar * H2 + rn * H3
//     s > 0:  for j: Com1[j] = b1[j] * H1 + s1[j] * H3
//                    Com1[j] = b1[j] * Com1[j] + u1[j] * H3
//             s * H1 + sum 2^j Com1[j] = c * H1 + sum 2^j s1[j] * H3
//     s = 0:  Com_c = c * H1 + rc * H3
//     a > 0:  as for s > 0 with Com2, b2, s2, u2, and -a * H1
// ---------------------------------------------------------------------------

/// Witness index of `e`.
const E: usize = 0;
const R2: usize = 1;
const R3: usize = 2;
const C: usize = 3;
const R: usize = 4;
const KSTAR: usize = 5;
const RN: usize = 6;
/// First witness index after the seven fixed scalars.
const FIXED_SCALARS: usize = 7;

/// Element indices of the fixed statement elements.
const EL_H1: usize = 1;
const EL_H2: usize = 2;
const EL_H3: usize = 3;
const EL_A_PRIME: usize = 4;
const EL_B_BAR: usize = 5;
const EL_A_BAR: usize = 6;
const EL_H1_PRIME: usize = 7;
const EL_K_N: usize = 8;
const FIXED_ELEMENTS: usize = 9;

/// The witness length of the spend relation, `Nw`.
pub(crate) fn spend_witness_count(l: usize, s: u64, a: u64) -> usize {
    FIXED_SCALARS + if s > 0 { 3 * l } else { 1 } + if a > 0 { 3 * l } else { 0 }
}

/// A range block: `L` bit commitments to a value that, plus a public
/// offset under `H1`, equals the hidden balance.
struct Range<'a, B: Backend> {
    /// Commitments `Com[j]`.
    com: &'a [B::Point],
    /// `sum_j 2^j * Com[j]`.
    sum: B::Point,
    /// The coefficient of `H1` in the sum equation's image: `s` or `-a`.
    offset: [u8; SCALAR_LENGTH],
    /// The scalar `s` or `-a`.
    offset_scalar: B::Scalar,
    /// Element index of `Com[0]`.
    element_base: usize,
    /// Witness index of `b[0]`; `s[0]` and `u[0]` follow at `+L` and `+2L`.
    scalar_base: usize,
}

impl<B: Backend> Range<'_, B> {
    fn len(&self) -> usize {
        self.com.len()
    }

    fn bits(&self) -> core::ops::Range<usize> {
        self.scalar_base..self.scalar_base + self.len()
    }

    fn blindings(&self) -> core::ops::Range<usize> {
        self.scalar_base + self.len()..self.scalar_base + 2 * self.len()
    }

    fn products(&self) -> core::ops::Range<usize> {
        self.scalar_base + 2 * self.len()..self.scalar_base + 3 * self.len()
    }
}

/// How the remainder `c - s` is committed to: bitwise when `s > 0`, so
/// that it is shown to be nonnegative, or in one commitment when `s = 0`.
enum Remainder<'a, B: Backend> {
    Bits(Range<'a, B>),
    Single(&'a B::Point),
}

/// The `Spend` relation.
pub(crate) struct Spend<'a, B: Backend> {
    gens: &'a Generators<B>,
    a_prime: &'a B::Point,
    b_bar: &'a B::Point,
    a_bar: &'a B::Point,
    h1_prime: &'a B::Point,
    k_n: &'a B::Point,
    remainder: Remainder<'a, B>,
    /// The topped-up balance `c + a`, present exactly when `a > 0`.
    top_up: Option<Range<'a, B>>,
}

impl<'a, B: Backend> Spend<'a, B> {
    /// Builds the statement, rejecting a shape that does not match `s` and
    /// `a` or the balance width `l`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        gens: &'a Generators<B>,
        l: usize,
        a_prime: &'a B::Point,
        b_bar: &'a B::Point,
        a_bar: &'a B::Point,
        h1_prime: &'a B::Point,
        k_n: &'a B::Point,
        s: u64,
        a: u64,
        com1: &'a [B::Point],
        com_c: Option<&'a B::Point>,
        com2: &'a [B::Point],
    ) -> Result<Self, Error> {
        let expected1 = if s > 0 { l } else { 0 };
        let expected2 = if a > 0 { l } else { 0 };
        if com1.len() != expected1 || com2.len() != expected2 || com_c.is_some() != (s == 0) {
            return Err(Error::Verify);
        }
        // Indices of the elements and scalars after the fixed ones.
        let (remainder, element_base, scalar_base) = match com_c {
            None => {
                let range = Range {
                    com: com1,
                    sum: horner_points(com1),
                    offset: coefficient(s),
                    offset_scalar: B::Scalar::from(s),
                    element_base: FIXED_ELEMENTS,
                    scalar_base: FIXED_SCALARS,
                };
                (
                    Remainder::Bits(range),
                    FIXED_ELEMENTS + l,
                    FIXED_SCALARS + 3 * l,
                )
            }
            Some(com_c) => (
                Remainder::Single(com_c),
                FIXED_ELEMENTS + 1,
                FIXED_SCALARS + 1,
            ),
        };
        let top_up = (a > 0).then(|| Range {
            com: com2,
            sum: horner_points(com2),
            offset: order_minus(a),
            offset_scalar: -B::Scalar::from(a),
            element_base,
            scalar_base,
        });
        Ok(Self {
            gens,
            a_prime,
            b_bar,
            a_bar,
            h1_prime,
            k_n,
            remainder,
            top_up,
        })
    }

    /// The range blocks present, in equation order.
    fn ranges(&self) -> impl Iterator<Item = &Range<'a, B>> {
        let remainder = match &self.remainder {
            Remainder::Bits(range) => Some(range),
            Remainder::Single(_) => None,
        };
        remainder.into_iter().chain(&self.top_up)
    }

    fn serialize_range(&self, w: &mut RelationWriter<'_>, range: &Range<'_, B>) {
        let l = range.len();
        for j in 0..l {
            let com = range.element_base + j;
            w.image(&[(com, &ONE)]);
            w.terms(&[
                (range.scalar_base + j, EL_H1, &ONE),
                (range.scalar_base + l + j, EL_H3, &ONE),
            ]);
            w.image(&[(com, &ONE)]);
            w.terms(&[
                (range.scalar_base + j, com, &ONE),
                (range.scalar_base + 2 * l + j, EL_H3, &ONE),
            ]);
        }
        w.begin(1 + l);
        w.image_term(EL_H1, &range.offset);
        for j in 0..l {
            w.image_term(range.element_base + j, &coefficient(1 << j));
        }
        w.begin(1 + l);
        w.term(C, EL_H1, &ONE);
        for j in 0..l {
            w.term(range.scalar_base + l + j, EL_H3, &coefficient(1 << j));
        }
    }

    fn commit_range(&self, range: &Range<'_, B>, n: &[B::Scalar], out: &mut Vec<B::Point>) {
        let (h1, h3) = (&self.gens.h1, &self.gens.h3);
        let bits = &n[range.bits()];
        let blindings = &n[range.blindings()];
        let products = &n[range.products()];
        for j in 0..range.len() {
            out.push(fixed::<B, 2>([(h1, &bits[j]), (h3, &blindings[j])]));
            out.push(range.com[j].mul(&bits[j]).add(&h3.mul(&products[j])));
        }
        // Same-base terms merge: sum 2^j s[j] * H3 = (sum 2^j s[j]) * H3.
        out.push(fixed::<B, 2>([
            (h1, &n[C]),
            (h3, &horner_scalars(blindings)),
        ]));
    }

    fn simulate_range(
        &self,
        range: &Range<'_, B>,
        c: &B::Scalar,
        z: &[B::Scalar],
        out: &mut Vec<B::Point>,
    ) {
        let (h1, h3) = (&self.gens.h1, &self.gens.h3);
        let minus_c = -*c;
        let bits = &z[range.bits()];
        let blindings = &z[range.blindings()];
        let products = &z[range.products()];
        for j in 0..range.len() {
            let com = &range.com[j];
            let generators = fixed::<B, 2>([(h1, &bits[j]), (h3, &blindings[j])]);
            out.push(generators.add(&com.mul(&minus_c)));
            // -c * Com[j] folds into the term that Com[j] already carries.
            out.push(com.mul(&(bits[j] - *c)).add(&h3.mul(&products[j])));
        }
        // image = offset * H1 + sum 2^j Com[j]; the sum is precomputed.
        let generators = fixed::<B, 2>([
            (h1, &(z[C] - *c * range.offset_scalar)),
            (h3, &horner_scalars(blindings)),
        ]);
        out.push(generators.add(&range.sum.mul(&minus_c)));
    }
}

impl<B: Backend> Statement<B> for Spend<'_, B> {
    fn num_scalars(&self) -> usize {
        let single = matches!(self.remainder, Remainder::Single(_)) as usize;
        FIXED_SCALARS + single + self.ranges().map(|r| 3 * r.len()).sum::<usize>()
    }

    fn num_equations(&self) -> usize {
        let single = matches!(self.remainder, Remainder::Single(_)) as usize;
        3 + single + self.ranges().map(|r| 2 * r.len() + 1).sum::<usize>()
    }

    fn validate(&self) -> Result<(), Error> {
        // Check 8: no statement element is the identity. The generators are
        // fixed and the commitments were deserialized; `A_bar` and
        // `H1_prime` are computed.
        for point in [
            self.a_prime,
            self.b_bar,
            self.a_bar,
            self.h1_prime,
            self.k_n,
        ] {
            nonidentity(point)?;
        }
        for range in self.ranges() {
            for com in range.com {
                nonidentity(com)?;
            }
            // Check 9: the image of the sum equation, offset * H1 + sum.
            nonidentity(&self.gens.h1.mul(&range.offset_scalar).add(&range.sum))?;
        }
        if let Remainder::Single(com_c) = self.remainder {
            nonidentity(com_c)?;
        }
        // Check 10 holds structurally: every witness scalar multiplies a
        // fixed generator or a deserialized element with coefficient 1, -1,
        // or 2^j, none of which is zero modulo the order.
        Ok(())
    }

    fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = RelationWriter::new(out);
        w.equations(self.num_equations());

        w.image(&[(EL_A_BAR, &ONE)]);
        w.terms(&[(E, EL_A_PRIME, &MINUS_ONE), (R2, EL_B_BAR, &ONE)]);
        w.image(&[(EL_H1_PRIME, &ONE)]);
        w.terms(&[
            (R3, EL_B_BAR, &ONE),
            (C, EL_H1, &MINUS_ONE),
            (R, EL_H3, &MINUS_ONE),
        ]);
        w.image(&[(EL_K_N, &ONE)]);
        w.terms(&[(KSTAR, EL_H2, &ONE), (RN, EL_H3, &ONE)]);
        match &self.remainder {
            Remainder::Bits(range) => self.serialize_range(&mut w, range),
            Remainder::Single(_) => {
                w.image(&[(FIXED_ELEMENTS, &ONE)]);
                w.terms(&[(C, EL_H1, &ONE), (FIXED_SCALARS, EL_H3, &ONE)]);
            }
        }
        if let Some(range) = &self.top_up {
            self.serialize_range(&mut w, range);
        }

        for base in [&self.gens.h1, &self.gens.h2, &self.gens.h3] {
            w.element(base.point())?;
        }
        for point in [
            self.a_prime,
            self.b_bar,
            self.a_bar,
            self.h1_prime,
            self.k_n,
        ] {
            w.element(point)?;
        }
        match &self.remainder {
            Remainder::Bits(range) => range.com.iter().try_for_each(|com| w.element(com))?,
            Remainder::Single(com_c) => w.element(*com_c)?,
        }
        if let Some(range) = &self.top_up {
            range.com.iter().try_for_each(|com| w.element(com))?;
        }
        Ok(())
    }

    fn commit(&self, n: &[B::Scalar], out: &mut Vec<B::Point>) {
        let gens = self.gens;
        out.push(B::Point::lincomb([
            (self.a_prime, &-n[E]),
            (self.b_bar, &n[R2]),
        ]));
        let generators = fixed::<B, 2>([(&gens.h1, &-n[C]), (&gens.h3, &-n[R])]);
        out.push(self.b_bar.mul(&n[R3]).add(&generators));
        out.push(fixed::<B, 2>([(&gens.h2, &n[KSTAR]), (&gens.h3, &n[RN])]));
        match &self.remainder {
            Remainder::Bits(range) => self.commit_range(range, n, out),
            Remainder::Single(_) => {
                out.push(fixed::<B, 2>([
                    (&gens.h1, &n[C]),
                    (&gens.h3, &n[FIXED_SCALARS]),
                ]));
            }
        }
        if let Some(range) = &self.top_up {
            self.commit_range(range, n, out);
        }
    }

    fn simulate(&self, c: &B::Scalar, z: &[B::Scalar], out: &mut Vec<B::Point>) {
        let gens = self.gens;
        let minus_c = -*c;
        out.push(B::Point::lincomb([
            (self.a_prime, &-z[E]),
            (self.b_bar, &z[R2]),
            (self.a_bar, &minus_c),
        ]));
        let generators = fixed::<B, 2>([(&gens.h1, &-z[C]), (&gens.h3, &-z[R])]);
        out.push(
            B::Point::lincomb([(self.b_bar, &z[R3]), (self.h1_prime, &minus_c)]).add(&generators),
        );
        let generators = fixed::<B, 2>([(&gens.h2, &z[KSTAR]), (&gens.h3, &z[RN])]);
        out.push(generators.add(&self.k_n.mul(&minus_c)));
        match &self.remainder {
            Remainder::Bits(range) => self.simulate_range(range, c, z, out),
            Remainder::Single(com_c) => {
                let generators = fixed::<B, 2>([(&gens.h1, &z[C]), (&gens.h3, &z[FIXED_SCALARS])]);
                out.push(generators.add(&com_c.mul(&minus_c)));
            }
        }
        if let Some(range) = &self.top_up {
            self.simulate_range(range, c, z, out);
        }
    }
}
