use std::fmt::Formatter;

use hex::ToHex as _;
use openmls_basic_credential::SignatureKeyPair;

use crate::{Obfuscate, compute_hash};

impl Obfuscate for SignatureKeyPair {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("signature_scheme", &self.signature_scheme())
            .field("public", &self.public().encode_hex::<String>())
            .field("private", &compute_hash(self.private()))
            .finish()
    }
}
