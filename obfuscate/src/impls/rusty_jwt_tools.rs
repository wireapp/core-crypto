use std::fmt::Formatter;

use rusty_jwt_tools::prelude::Pem;

use crate::{Obfuscate, compute_hash};

impl Obfuscate for Pem {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Pem({})", hex::encode(compute_hash(self.as_bytes())))
    }
}
