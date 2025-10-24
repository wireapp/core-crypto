#[cfg(not(target_family = "wasm"))]
use std::sync::Arc;

use core_crypto::{Ciphersuite as CryptoCiphersuite, Credential as CryptoCredential};
use mls_crypto_provider::RustCrypto;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Ciphersuite, CoreCryptoResult, CredentialRef, CredentialType,
    client_id::ClientIdMaybeArc,
    database::{DatabaseMaybeArc, ToCc as _},
};

/// A cryptographic credential.
///
/// This is tied to a particular client via either its client id or certificate bundle,
/// depending on its credential type, but is independent of any client instance or storage.
///
/// To attach to a particular client instance and store, see [`CoreCryptoFfi::add_credential`][crate::CoreCryptoFfi::add_credential].
#[derive(Debug, Clone, derive_more::From, derive_more::Into)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct Credential(CryptoCredential);

impl Credential {
    fn basic_impl(ciphersuite: Ciphersuite, client_id: ClientIdMaybeArc) -> CoreCryptoResult<Self> {
        let crypto = RustCrypto::default();
        CryptoCredential::basic(
            CryptoCiphersuite::from(ciphersuite).signature_algorithm(),
            client_id.as_cc(),
            crypto,
        )
        .map(Into::into)
        .map_err(Into::into)
    }
}

/// Generate a basic credential.
///
/// The result is independent of any client instance and the database; it lives in memory only.
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub fn credential_basic(ciphersuite: Ciphersuite, client_id: ClientIdMaybeArc) -> CoreCryptoResult<Credential> {
    Credential::basic_impl(ciphersuite, client_id)
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl Credential {
    /// Generate a basic credential.
    ///
    /// The result is independent of any client instance and the database; it lives in memory only.
    pub fn basic(ciphersuite: Ciphersuite, client_id: ClientIdMaybeArc) -> CoreCryptoResult<Self> {
        Credential::basic_impl(ciphersuite, client_id)
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl Credential {
    /// Get the type of this credential.
    pub fn r#type(&self) -> CoreCryptoResult<CredentialType> {
        self.0.mls_credential().credential_type().try_into()
    }

    /// Get the earliest possible validity of this credential, expressed as seconds after the unix epoch.
    ///
    /// Basic credentials have no defined earliest validity and will always return 0.
    pub fn earliest_validity(&self) -> u64 {
        self.0.earliest_validity()
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl Credential {
    /// Save this credential in a [`Database`][crate::Database].
    ///
    /// Of course, in order to use this credential in a particular [`CoreCryptoFfi`][crate::CoreCryptoFfi] instance,
    /// the database provided must be the same that the instance was instantiated with.
    ///
    /// Produces a [`CredentialRef`], which can later be used to add this credential to a [`CoreCryptoFfi`][crate::CoreCryptoFfi] instance.
    pub async fn save(&mut self, database: &DatabaseMaybeArc) -> CoreCryptoResult<CredentialRef> {
        let database = database.as_cc();
        self.0.save(database).await.map(Into::into).map_err(Into::into)
    }
}

#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
impl Credential {
    /// Save this credential in a [`Database`][crate::Database].
    ///
    /// Of course, in order to use this credential in a particular [`CoreCryptoFfi`][crate::CoreCryptoFfi] instance,
    /// the database provided must be the same that the instance was instantiated with.
    ///
    /// Produces a [`CredentialRef`], which can later be used to add this credential to a [`CoreCryptoFfi`][crate::CoreCryptoFfi] instance.
    pub async fn save(self: Arc<Self>, database: &DatabaseMaybeArc) -> CoreCryptoResult<CredentialRef> {
        let database = database.as_cc();
        let mut this = Arc::unwrap_or_clone(self);
        this.0.save(database).await.map(Into::into).map_err(Into::into)
    }
}
