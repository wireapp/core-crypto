use std::sync::Arc;

use obfuscate::Obfuscated;
use rusty_jwt_tools::prelude::Pem;

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
            config.acme_directory_url
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

    /// Create the acquisition object using an existing sign keypair.
    /// This API is temporary until our system decouples client identities from a client's public signature key.
    /// See <https://wearezeta.atlassian.net/wiki/x/RABtrQ>.
    //
    // We're intentionally not factoring this into `try_new()`, so that this can be removed more cleanly.
    pub fn try_new_from_pem(
        pki_env: Arc<PkiEnvironment>,
        config: X509CredentialConfiguration,
        sign_kp: Pem,
    ) -> E2eIdentityResult<Self> {
        let acme_kp = generate_key(config.sign_alg)?;
        let acme_jwk = public_jwk_from_pem_keypair(config.sign_alg, &acme_kp)?;
        log::info!(
            "created acquisition from existing {:?}, sign_alg = {}, acme_url = {}",
            Obfuscated::from(&sign_kp),
            config.sign_alg,
            config.acme_directory_url
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
