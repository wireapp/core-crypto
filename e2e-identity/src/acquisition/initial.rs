use std::sync::Arc;

use obfuscate::Obfuscated;
use rusty_jwt_tools::prelude::Pem;

use super::{CiphersuiteExt as _, X509CredentialAcquisition, X509CredentialConfiguration, states};
use crate::{
    error::{E2eIdentityError, E2eIdentityResult},
    pki_env::PkiEnvironment,
    utils::{generate_key, public_jwk_from_pem_keypair},
};

impl X509CredentialAcquisition<states::Initialized> {
    /// Create the acquisition object.
    ///
    /// Generates the signing and ACME keypairs, but does not perform
    /// any network I/O.
    pub fn try_new(pki_env: Arc<PkiEnvironment>, config: X509CredentialConfiguration) -> E2eIdentityResult<Self> {
        let sign_alg = config
            .cipher_suite
            .jws_algorithm()
            .ok_or(E2eIdentityError::UnsupportedCipherSuite(config.cipher_suite))?;
        let sign_kp = generate_key(sign_alg)?;
        let acme_kp = generate_key(sign_alg)?;
        let acme_jwk = public_jwk_from_pem_keypair(sign_alg, &acme_kp)?;

        log::info!(
            "created acquisition({:?}), cipher_suite = {:?}, acme_url = {}",
            Obfuscated::from(&sign_kp),
            config.cipher_suite,
            config.acme_directory_url
        );
        Ok(Self {
            pki_env,
            config,
            sign_alg,
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
        let sign_alg = config
            .cipher_suite
            .jws_algorithm()
            .ok_or(E2eIdentityError::UnsupportedCipherSuite(config.cipher_suite))?;
        let acme_kp = generate_key(sign_alg)?;
        let acme_jwk = public_jwk_from_pem_keypair(sign_alg, &acme_kp)?;
        log::info!(
            "created acquisition from existing {:?}, cipher_suite = {:?}, acme_url = {}",
            Obfuscated::from(&sign_kp),
            config.cipher_suite,
            config.acme_directory_url
        );

        Ok(Self {
            pki_env,
            config,
            sign_alg,
            sign_kp,
            acme_kp,
            acme_jwk,
            data: states::Initialized,
        })
    }
}
