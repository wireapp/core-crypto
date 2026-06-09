//! This entire module is temporary until our system decouples client identities from a client's public signature key.
//! See <https://wearezeta.atlassian.net/wiki/x/RABtrQ>.

use std::sync::Arc;

use async_lock::Mutex;
use core_crypto::RecursiveError;

use crate::{
    CoreCryptoError, CoreCryptoResult, CredentialRef, Database, PkiEnvironment, X509CredentialAcquisition,
    X509CredentialAcquisitionConfiguration, e2ei::AcquisitionState,
};

#[cfg_attr(any(feature = "wasm", feature = "napi"), uniffi::export)]
impl X509CredentialAcquisition {
    /// Create a new credential acquisition from an existing credential. This API is temporary until our system
    /// decouples client identities from a client's public signature key.
    /// See <https://wearezeta.atlassian.net/wiki/x/RABtrQ>.
    ///
    /// Provide `core_crypto_database` if you're using distinct DB instances for `PkiEnvironment` and `CoreCrypto`.
    /// Otherwise, the `PkiEnvironment`'s DB will be used to load the full credential.
    #[cfg_attr(any(feature = "wasm", feature = "napi"), uniffi::constructor)]
    pub async fn new_from_credential_ref(
        pki_environment: Arc<PkiEnvironment>,
        config: X509CredentialAcquisitionConfiguration,
        credential_ref: &CredentialRef,
        core_crypto_database: Option<Arc<Database>>,
    ) -> CoreCryptoResult<Self> {
        let cipher_suite = config.cipher_suite;
        if cipher_suite != credential_ref.cipher_suite() {
            return Err(CoreCryptoError::ad_hoc(
                "config cipher suite doesn't match credential cipher suite",
            ));
        }

        let ffi_database = core_crypto_database
            .map(|db| db.as_ref().clone())
            .unwrap_or(pki_environment.database());
        let database = Arc::<core_crypto_keystore::Database>::from(ffi_database);
        let credential = credential_ref
            .0
            .load(&*database)
            .await
            .map_err(RecursiveError::mls_credential_ref("loading credential from ref"))?;

        let key_bytes = credential.signature_key_bytes();
        let algorithm = cipher_suite.try_into()?;
        let pem = wire_e2e_identity::utils::pem_from_bytes(key_bytes, algorithm)?;

        let inner = wire_e2e_identity::X509CredentialAcquisition::try_new_from_pem(
            pki_environment.clone_inner(),
            config.try_into_core()?,
            pem,
        )?;

        Ok(Self {
            state: Mutex::new(AcquisitionState::Initialized(inner.into())),
            cipher_suite,
        })
    }
}

// Note: free function when not using ubrn.

/// Create a new credential acquisition from an existing credential. This API is temporary until our system
/// decouples client identities from a client's public signature key.
/// See <https://wearezeta.atlassian.net/wiki/x/RABtrQ>.
///
/// Provide `core_crypto_database` if you're using distinct DB instances for `PkiEnvironment` and `CoreCrypto`.
/// Otherwise, the `PkiEnvironment`'s DB will be used to load the full credential.
#[cfg(not(any(feature = "wasm", feature = "napi", target_os = "unknown")))]
#[uniffi::export(default(core_crypto_database = None))]
pub async fn x509_credential_acquisition_new_from_credential_ref(
    pki_environment: Arc<PkiEnvironment>,
    config: X509CredentialAcquisitionConfiguration,
    credential_ref: &CredentialRef,
    core_crypto_database: Option<Arc<Database>>,
) -> CoreCryptoResult<X509CredentialAcquisition> {
    X509CredentialAcquisition::new_from_credential_ref(pki_environment, config, credential_ref, core_crypto_database)
        .await
}
