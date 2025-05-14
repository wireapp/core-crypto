use core_crypto::RecursiveError;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Ciphersuite, CoreCrypto, CoreCryptoResult};

pub(crate) mod identities;

#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
/// Dump of the PKI environemnt as PEM
pub struct E2eiDumpedPkiEnv {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    /// Root CA in use (i.e. Trust Anchor)
    pub root_ca: String,
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    /// Intermediate CAs that are loaded
    pub intermediates: Vec<String>,
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    /// CRLs registered in the PKI env
    pub crls: Vec<String>,
}

impl From<core_crypto::e2e_identity::E2eiDumpedPkiEnv> for E2eiDumpedPkiEnv {
    fn from(value: core_crypto::e2e_identity::E2eiDumpedPkiEnv) -> Self {
        Self {
            root_ca: value.root_ca,
            intermediates: value.intermediates,
            crls: value.crls,
        }
    }
}

// End-to-end identity methods
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCrypto {
    pub async fn e2ei_dump_pki_env(&self) -> CoreCryptoResult<Option<E2eiDumpedPkiEnv>> {
        let dumped_pki_env = self
            .inner
            .e2ei_dump_pki_env()
            .await
            .map_err(RecursiveError::mls_client("dumping pki env"))?;
        Ok(dumped_pki_env.map(Into::into))
    }

    /// See [core_crypto::prelude::Session::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.inner.e2ei_is_pki_env_setup().await
    }

    /// See [core_crypto::prelude::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let signature_scheme =
            core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
                .signature_algorithm();
        self.inner
            .e2ei_is_enabled(signature_scheme)
            .await
            .map_err(RecursiveError::mls_client("checking if e2ei is enabled"))
            .map_err(Into::into)
    }
}
