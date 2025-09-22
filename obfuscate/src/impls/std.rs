use std::fmt::Formatter;

use crate::{Obfuscate, compute_hash};

impl Obfuscate for Vec<u8> {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(hex::encode(compute_hash(self)).as_str())
    }
}

impl<T: Obfuscate> Obfuscate for Vec<T> {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("[")?;
        for item in self.iter() {
            item.obfuscate(f)?;
        }
        f.write_str("]")
    }
}

impl<T: Obfuscate> Obfuscate for Option<T> {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Some(item) => {
                f.write_str("Some(")?;
                item.obfuscate(f)?;
                f.write_str(")")
            }
            None => f.write_str("None"),
        }
    }
}
