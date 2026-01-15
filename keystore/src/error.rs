/// Error type to represent various errors that can happen in the KeyStore
#[derive(Debug, thiserror::Error)]
pub enum CryptoKeystoreError {
    #[error("The given key doesn't contain valid utf-8")]
    KeyReprError(#[from] std::str::Utf8Error),
    #[error("A transaction must be in progress to perform this operation.")]
    MutatingOperationWithoutTransaction,
    #[error("Cannot perform the operation \"{attempted_operation:?}\" while a transaction is in progress.")]
    TransactionInProgress { attempted_operation: String },
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("One of the Keystore locks has been poisoned")]
    LockPoisonError,
    #[error("The keystore has run out of keypackage bundles!")]
    OutOfKeyPackageBundles,
    #[error("Incorrect API usage: {0}")]
    IncorrectApiUsage(&'static str),
    #[error("The credential tied to this signature keypair is different from the provided one")]
    SignatureKeyPairDoesNotBelongToCredential,
    #[error("The uniqueness constraint has been violated for {0}")]
    AlreadyExists(&'static str),
    #[error("The provided buffer is too big to be persisted in the store")]
    BlobTooBig,
    #[error("This database connection has been closed")]
    Closed,
    #[error(transparent)]
    KeyStoreValueTransformError(#[from] postcard::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    TimeError(#[from] std::time::SystemTimeError),
    #[cfg(target_family = "wasm")]
    #[error(transparent)]
    ChannelError(#[from] std::sync::mpsc::TryRecvError),
    #[cfg(target_family = "wasm")]
    #[error("The task has been canceled")]
    WasmExecutorError,
    #[error("aead::Error")]
    AesGcmError,
    #[cfg(target_family = "wasm")]
    #[error("{0}")]
    SerdeWasmBindgenError(String),
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    DbError(#[from] rusqlite::Error),
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    DbMigrationError(#[from] Box<refinery::Error>),
    #[cfg(test)]
    #[error(transparent)]
    MlsKeyPackageIdError(#[from] openmls::prelude::KeyPackageIdError),
    #[cfg(test)]
    #[error(transparent)]
    MlsExtensionError(#[from] openmls::prelude::ExtensionError),
    #[error("Invalid database key size, expected {expected}, got {actual}")]
    InvalidDbKeySize { expected: usize, actual: usize },
    #[cfg(feature = "proteus-keystore")]
    #[error("Invalid key [{key}] size, expected {expected}, got {actual}")]
    InvalidKeySize {
        expected: usize,
        actual: usize,
        key: &'static str,
    },
    #[cfg(feature = "proteus-keystore")]
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[cfg(feature = "proteus-keystore")]
    #[error("Could not find a free prekey id")]
    NoFreePrekeyId,
    #[error("{0}")]
    MlsKeyStoreError(String),
    #[error(transparent)]
    HexDecodeError(#[from] hex::FromHexError),
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[cfg(target_os = "ios")]
    #[error(transparent)]
    HexSaltDecodeError(hex::FromHexError),
    #[cfg(target_os = "ios")]
    #[error(transparent)]
    SecurityFrameworkError(#[from] security_framework::base::Error),
    #[cfg(target_family = "wasm")]
    #[error("{0}")]
    JsError(String),
    #[error("Not implemented (and probably never will)")]
    NotImplemented,
    #[error("Failed getting current timestamp")]
    TimestampError,
    #[error("Could not find {0} in keystore with value {1}")]
    NotFound(&'static str, String),
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[cfg(target_family = "wasm")]
    #[error(transparent)]
    IdbError(#[from] idb::Error),
    #[cfg(target_family = "wasm")]
    #[error(transparent)]
    IdbErrorCryptoKeystoreV1_0_0(idb::Error),
    #[cfg(target_family = "wasm")]
    #[error("Migration from version {0} is not supported")]
    MigrationNotSupported(u32),
    #[error("The migration failed: {0}")]
    MigrationFailed(String),
    #[error("the provided bytes could not be interpreted as the primary key of {0}")]
    InvalidPrimaryKeyBytes(&'static str),
    #[error("the collection name {0} is unknown and could not be found")]
    UnknownCollectionName(&'static str),
}

#[cfg(target_family = "wasm")]
impl From<wasm_bindgen::JsValue> for CryptoKeystoreError {
    fn from(jsv: wasm_bindgen::JsValue) -> Self {
        Self::JsError(jsv.as_string().unwrap())
    }
}

#[cfg(target_family = "wasm")]
#[allow(clippy::from_over_into)]
impl Into<wasm_bindgen::JsValue> for CryptoKeystoreError {
    fn into(self) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&self.to_string())
    }
}

#[cfg(target_family = "wasm")]
impl From<serde_wasm_bindgen::Error> for CryptoKeystoreError {
    fn from(jsv: serde_wasm_bindgen::Error) -> Self {
        Self::SerdeWasmBindgenError(jsv.to_string())
    }
}

#[cfg(feature = "proteus-keystore")]
impl proteus_traits::ProteusErrorCode for CryptoKeystoreError {
    fn code(&self) -> proteus_traits::ProteusErrorKind {
        use proteus_traits::ProteusErrorKind;
        match self {
            CryptoKeystoreError::KeyReprError(_) => ProteusErrorKind::DecodeError,
            CryptoKeystoreError::TryFromSliceError(_) => ProteusErrorKind::DecodeError,
            CryptoKeystoreError::LockPoisonError => ProteusErrorKind::OtherSystemError,
            CryptoKeystoreError::BlobTooBig => ProteusErrorKind::IoError,
            CryptoKeystoreError::KeyStoreValueTransformError(_) => ProteusErrorKind::DecodeError,
            CryptoKeystoreError::IoError(_) => ProteusErrorKind::IoError,
            #[cfg(not(target_family = "wasm"))]
            CryptoKeystoreError::DbError(_) => ProteusErrorKind::IoError,
            #[cfg(not(target_family = "wasm"))]
            CryptoKeystoreError::DbMigrationError(_) => ProteusErrorKind::IoError,
            CryptoKeystoreError::InvalidKeySize { .. } => ProteusErrorKind::InvalidArrayLen,
            CryptoKeystoreError::ParseIntError(_) => ProteusErrorKind::DecodeError,
            CryptoKeystoreError::HexDecodeError(_) => ProteusErrorKind::DecodeError,
            CryptoKeystoreError::FromUtf8Error(_) => ProteusErrorKind::DecodeError,
            _ => unreachable!(),
        }
    }
}

/// A specialized Result for the KeyStore functions
pub type CryptoKeystoreResult<T> = Result<T, CryptoKeystoreError>;
