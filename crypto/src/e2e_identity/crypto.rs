use super::error::*;
use crate::prelude::MlsCiphersuite;
use crate::{CryptoError, CryptoResult, MlsError};
use mls_crypto_provider::MlsCryptoProvider;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsCryptoProvider};
use wire_e2e_identity::prelude::JwsAlgorithm;
use zeroize::Zeroize;

/// Length for all signature keys since there's not method to retrieve it from openmls
const SIGN_KEY_LENGTH: usize = 32;
const SIGN_KEYPAIR_LENGTH: usize = SIGN_KEY_LENGTH * 2;

impl super::E2eiEnrollment {
    pub(super) fn new_sign_key(
        ciphersuite: MlsCiphersuite,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<E2eiSignatureKeypair> {
        let crypto = backend.crypto();
        let cs = openmls_traits::types::Ciphersuite::from(ciphersuite);
        let (sk, pk) = crypto
            .signature_key_gen(cs.signature_algorithm())
            .map_err(MlsError::from)?;
        Ok((sk, pk).into())
    }

    pub(super) fn get_sign_key_for_mls(&self) -> CryptoResult<Vec<u8>> {
        let sk = match self.sign_sk.len() {
            SIGN_KEYPAIR_LENGTH => &self.sign_sk[..SIGN_KEY_LENGTH],
            SIGN_KEY_LENGTH => &self.sign_sk,
            _ => return Err(E2eIdentityError::InvalidSignatureKey.into()),
        };
        Ok(sk.to_vec())
    }
}

impl TryFrom<MlsCiphersuite> for JwsAlgorithm {
    type Error = E2eIdentityError;

    fn try_from(cs: MlsCiphersuite) -> E2eIdentityResult<Self> {
        let cs = openmls_traits::types::Ciphersuite::from(cs);
        Ok(match cs {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_X25519KYBER768DRAFT00_AES128GCM_SHA256_Ed25519 => JwsAlgorithm::Ed25519,
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

#[derive(Debug, serde::Serialize, serde::Deserialize, Zeroize, derive_more::From, derive_more::Deref)]
#[zeroize(drop)]
pub struct E2eiSignatureKeypair(Vec<u8>);

impl From<(Vec<u8>, Vec<u8>)> for E2eiSignatureKeypair {
    fn from((sk, pk): (Vec<u8>, Vec<u8>)) -> Self {
        Self([sk, pk].concat())
    }
}

impl TryFrom<SignatureKeyPair> for E2eiSignatureKeypair {
    type Error = CryptoError;

    fn try_from(kp: SignatureKeyPair) -> CryptoResult<Self> {
        let sk = kp.private();
        let sk = match sk.len() {
            SIGN_KEY_LENGTH => sk,
            SIGN_KEYPAIR_LENGTH => &sk[..SIGN_KEY_LENGTH],
            _ => return Err(E2eIdentityError::InvalidSignatureKey.into()),
        };
        Ok((sk.to_vec(), kp.to_public_vec()).into())
    }
}
