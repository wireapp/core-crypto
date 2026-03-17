use std::sync::Arc;

use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, ES512KeyPair, Ed25519KeyPair, Jwk};
use rusty_jwt_tools::{
    jwk::TryIntoJwk,
    prelude::{JwsAlgorithm, Pem},
};

use super::{X509CredentialAcquisition, X509CredentialConfiguration, states};
use crate::{error::E2eIdentityResult, pki_env::PkiEnvironment};

impl X509CredentialAcquisition<states::Initialized> {
    /// Create the acquisition object.
    ///
    /// Generates the signing and ACME keypairs, but does not perform
    /// any network I/O.
    pub fn try_new(pki_env: Arc<PkiEnvironment>, config: X509CredentialConfiguration) -> E2eIdentityResult<Self> {
        let (sign_kp, acme_kp, acme_jwk) = Self::generate_keys(config.sign_alg)?;

        Ok(Self {
            pki_env,
            config,
            sign_kp,
            acme_kp,
            acme_jwk,
            data: states::Initialized,
        })
    }

    fn generate_keys(sign_alg: JwsAlgorithm) -> E2eIdentityResult<(Pem, Pem, Jwk)> {
        let (sign_kp, acme_kp, acme_jwk) = match sign_alg {
            JwsAlgorithm::Ed25519 => {
                let sign_kp = Ed25519KeyPair::generate();
                let acme_kp = Ed25519KeyPair::generate();
                (
                    sign_kp.to_pem().into(),
                    acme_kp.to_pem().into(),
                    acme_kp.public_key().try_into_jwk()?,
                )
            }
            JwsAlgorithm::P256 => {
                let sign_kp = ES256KeyPair::generate();
                let acme_kp = ES256KeyPair::generate();
                (
                    sign_kp.to_pem()?.into(),
                    acme_kp.to_pem()?.into(),
                    acme_kp.public_key().try_into_jwk()?,
                )
            }
            JwsAlgorithm::P384 => {
                let sign_kp = ES384KeyPair::generate();
                let acme_kp = ES384KeyPair::generate();
                (
                    sign_kp.to_pem()?.into(),
                    acme_kp.to_pem()?.into(),
                    acme_kp.public_key().try_into_jwk()?,
                )
            }
            JwsAlgorithm::P521 => {
                let sign_kp = ES512KeyPair::generate();
                let acme_kp = ES512KeyPair::generate();
                (
                    sign_kp.to_pem()?.into(),
                    acme_kp.to_pem()?.into(),
                    acme_kp.public_key().try_into_jwk()?,
                )
            }
        };
        Ok((sign_kp, acme_kp, acme_jwk))
    }
}
