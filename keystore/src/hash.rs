use std::fmt;

use sha2::{Digest, Sha256};

use crate::{
    CryptoKeystoreResult,
    traits::{KeyType, OwnedKeyType},
};

/// Used to calculate ID hashes for some MlsEntities' SQLite tables (not used on wasm).
/// We only use sha256 on platforms where we use SQLite.
/// On wasm, we use IndexedDB, a key-value store, via the idb crate.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn sha256(data: &[u8]) -> String {
    Sha256Hash::hash_from(data).to_string()
}

/// A Sha256 hash.
///
/// Certain entities use this kind of hash as a key. It's a small value which lives on the stack,
/// as opposed to the longer, heap-allocated values which it replaces.
///
/// This type enables this use case with the new entity traits.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    derive_more::Deref,
    derive_more::AsRef,
    derive_more::From,
    derive_more::Into,
    serde::Serialize,
    serde::Deserialize,
)]
#[as_ref(forward)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    /// Create an instance by hashing a single input value.
    pub fn hash_from(input: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(input);
        Self(hasher.finalize().into())
    }

    /// Convert an existing hash into an instance of this type.
    ///
    /// Only basic length checking is performed!
    pub fn from_existing_hash(hash: impl AsRef<[u8]>) -> CryptoKeystoreResult<Self> {
        let array = hash.as_ref().try_into()?;
        Ok(Self(array))
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut hex_bytes = [0; 64];
        hex::encode_to_slice(self.0, hex_bytes.as_mut_slice())
            .expect("infallible given inputs and outputs of fixed correct length");
        let hex_str = str::from_utf8(&hex_bytes).expect("hex crate always produces valid utf8 data");
        write!(f, "{hex_str}")
    }
}

impl KeyType for Sha256Hash {
    fn bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        (&self.0).into()
    }
}

impl OwnedKeyType for Sha256Hash {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
}

#[cfg(not(target_family = "wasm"))]
impl rusqlite::ToSql for Sha256Hash {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.as_ref().to_sql()
    }
}
