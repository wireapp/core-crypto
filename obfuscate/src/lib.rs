use std::{fmt::Formatter, ops::Deref, sync::LazyLock};

use derive_more::From;
use log::kv::{ToValue, Value};
use sha2::{Digest, Sha256};

pub mod impls;

pub trait Obfuscate {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result;
}

pub fn compute_hash(bytes: &[u8]) -> [u8; 10] {
    /// Store a per-instantiation salt, so that obfuscated values cannot turn into pseudo-ids.
    ///
    /// This will be regenerated each time the library is instantiated. This will be approximately
    /// once per client instantiation.
    static SALT: LazyLock<[u8; 32]> = LazyLock::new(|| {
        use rand::Rng as _;
        let mut salt = [0; _];
        rand::thread_rng().fill(&mut salt);
        salt
    });

    let mut hasher = Sha256::new();
    hasher.update(*SALT);
    hasher.update(bytes);

    let mut output = [0; 10];
    output.copy_from_slice(&hasher.finalize().as_slice()[0..10]);
    output
}

/// We often want logging for some values that we shouldn't know the real value of, for privacy reasons.
///
/// `ConversationId` is a canonical example of such an item.
///
/// This wrapper lets us log a partial hash of the sensitive item, so we have deterministic loggable non-sensitive
/// aliases for all our sensitive values.
#[derive(From)]
pub struct Obfuscated<'a, T: Obfuscate + ?Sized>(&'a T);
impl<'a, T: Obfuscate + ?Sized> core::fmt::Debug for Obfuscated<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.obfuscate(f)
    }
}

impl<'a, T: Obfuscate> ToValue for Obfuscated<'a, T> {
    fn to_value(&self) -> Value<'_> {
        Value::from_debug(self)
    }
}

impl<T> Obfuscate for zeroize::Zeroizing<T>
where
    T: Obfuscate + zeroize::Zeroize,
{
    fn obfuscate(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.deref().obfuscate(f)
    }
}
