use std::{fmt, ops::Deref};

use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoKeystoreError;

/// The key used to encrypt the database.
#[derive(Clone, Zeroize, ZeroizeOnDrop, derive_more::From, PartialEq, Eq)]
pub struct DatabaseKey([u8; Self::LEN]);

impl DatabaseKey {
    pub const LEN: usize = 32;

    pub fn generate() -> DatabaseKey {
        DatabaseKey(rand::random::<[u8; Self::LEN]>())
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("DatabaseKey(hash=")?;
        for x in Sha256::digest(self).as_slice().iter().take(10) {
            fmt::LowerHex::fmt(x, f)?
        }
        f.write_str("...)")
    }
}

impl AsRef<[u8]> for DatabaseKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for DatabaseKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for DatabaseKey {
    type Error = CryptoKeystoreError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() != Self::LEN {
            Err(CryptoKeystoreError::InvalidDbKeySize {
                expected: Self::LEN,
                actual: buf.len(),
            })
        } else {
            Ok(Self(buf.try_into().unwrap()))
        }
    }
}
