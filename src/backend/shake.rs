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

//! SHAKE128 from the RustCrypto `shake` crate.
//!
//! The RustCrypto backend uses this natively. The BoringSSL backend uses it
//! as a stand-in: BoringSSL implements Keccak in `crypto/keccak/` but only
//! behind an internal C++ header, so `bssl-sys` cannot bind it. When
//! BoringSSL exports SHAKE128, that backend should switch its
//! `Backend::Shake128` to a binding and this module becomes RustCrypto-only.
//! The sponge only ever absorbs public data.

use shake::{ExtendableOutput, Update, XofReader};

/// SHAKE128 as implemented by the `shake` crate.
#[derive(Clone, Default)]
pub struct RustCryptoShake128(shake::Shake128);

impl super::Shake128 for RustCryptoShake128 {
    type Reader = RustCryptoShake128Reader;

    fn new() -> Self {
        Self::default()
    }

    fn absorb(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data);
    }

    fn finalize(self) -> Self::Reader {
        RustCryptoShake128Reader(self.0.finalize_xof())
    }
}

/// The output stream of [`RustCryptoShake128`].
pub struct RustCryptoShake128Reader(shake::Shake128Reader);

impl super::Shake128Reader for RustCryptoShake128Reader {
    fn read(&mut self, out: &mut [u8]) {
        XofReader::read(&mut self.0, out);
    }
}
