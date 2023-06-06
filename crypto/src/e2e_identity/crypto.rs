use super::error::*;
use crate::prelude::MlsCiphersuite;
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsCryptoProvider};
use wire_e2e_identity::prelude::JwsAlgorithm;

impl super::WireE2eIdentity {
    /// Length for all signature keys since there's not method to retrieve it from openmls
    const SIGN_KEY_LENGTH: usize = 32;

    pub(super) fn new_sign_key(ciphersuite: MlsCiphersuite, backend: &MlsCryptoProvider) -> E2eIdentityResult<Vec<u8>> {
        let crypto = backend.crypto();
        let cs = openmls_traits::types::Ciphersuite::from(ciphersuite);
        let (sk, pk) = crypto.signature_key_gen(cs.signature_algorithm())?;
        Ok(Self::into_e2ei_sign_key(sk, pk))
    }

    fn into_e2ei_sign_key(sk: Vec<u8>, pk: Vec<u8>) -> Vec<u8> {
        [sk, pk].concat()
    }

    pub(super) fn get_sign_key_for_mls(&self) -> E2eIdentityResult<Vec<u8>> {
        if self.sign_sk.len() != Self::SIGN_KEY_LENGTH * 2 {
            return Err(E2eIdentityError::ImplementationError);
        }
        Ok(self.sign_sk[..Self::SIGN_KEY_LENGTH].to_vec())
    }
}

impl TryFrom<MlsCiphersuite> for JwsAlgorithm {
    type Error = E2eIdentityError;

    fn try_from(cs: MlsCiphersuite) -> E2eIdentityResult<Self> {
        let cs = openmls_traits::types::Ciphersuite::from(cs);
        Ok(match cs {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => JwsAlgorithm::Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => JwsAlgorithm::P256,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => JwsAlgorithm::P384,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                return Err(E2eIdentityError::NotYetSupported)
            }
        })
    }
}
