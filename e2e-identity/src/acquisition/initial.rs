use std::sync::Arc;

use obfuscate::Obfuscated;

use super::{X509CredentialAcquisition, X509CredentialConfiguration, states};
use crate::{
    error::E2eIdentityResult,
    pki_env::PkiEnvironment,
    utils::{generate_key, public_jwk_from_pem_keypair},
};

impl X509CredentialAcquisition<states::Initialized> {
    /// Create the acquisition object.
    ///
    /// Generates the signing and ACME keypairs, but does not perform
    /// any network I/O.
    pub fn try_new(pki_env: Arc<PkiEnvironment>, config: X509CredentialConfiguration) -> E2eIdentityResult<Self> {
        let sign_kp = generate_key(config.sign_alg)?;
        let acme_kp = generate_key(config.sign_alg)?;
        let acme_jwk = public_jwk_from_pem_keypair(config.sign_alg, &acme_kp)?;

        log::info!(
            "created acquisition({:?}), sign_alg = {}, acme_url = {}",
            Obfuscated::from(&sign_kp),
            config.sign_alg,
            config.acme_url
        );
        Ok(Self {
            pki_env,
            config,
            sign_kp,
            acme_kp,
            acme_jwk,
            data: states::Initialized,
        })
    }
}
