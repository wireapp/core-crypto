// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub type CryptoboxMigrationError = super::WrappedContextualError<CryptoboxMigrationErrorKind>;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
/// Wrapper for errors that can happen during a Cryptobox migration
pub enum CryptoboxMigrationErrorKind {
    #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))]
    #[error(transparent)]
    /// Rexie Error
    RexieError(rexie::Error),
    #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))]
    #[error(transparent)]
    /// IndexedDB Error
    IdbError(idb::Error),
    #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))]
    #[error(transparent)]
    /// Error when parsing/serializing JSON payloads from the WASM boundary
    JsonParseError(#[from] serde_wasm_bindgen::Error),
    #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))]
    #[error(transparent)]
    /// Error when decoding base64
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("The targeted value does not possess the targeted key ({0})")]
    /// Error when trying to fetch a certain key from a structured value
    MissingKeyInValue(String),
    #[error("The value cannot be coerced to the {0} type")]
    /// Error when trying to coerce a certain value to a certain type
    WrongValueType(String),
    #[cfg_attr(target_family = "wasm", error("The provided path [{0}] could not be found."))]
    #[cfg_attr(
        not(target_family = "wasm"),
        error("The provided path store [{0}] is either non-existent or has an incorrect shape.")
    )]
    /// Error when trying to open a Cryptobox store that doesn't exist
    ProvidedPathDoesNotExist(String),
    #[error("The Cryptobox identity at path [{0}] could not be found.")]
    /// Error when inspecting a Cryptobox store that doesn't contain an Identity
    IdentityNotFound(String),
    #[cfg(all(feature = "cryptobox-migrate", not(target_family = "wasm")))]
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(feature = "cryptobox-migrate")]
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
}

#[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))]
impl From<rexie::Error> for CryptoboxMigrationErrorKind {
    fn from(e: rexie::Error) -> Self {
        match e {
            rexie::Error::IdbError(e) => Self::IdbError(e),
            _ => Self::RexieError(e),
        }
    }
}
