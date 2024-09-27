use super::error::*;
use crate::{prelude::MlsCiphersuite, CryptoError, CryptoResult, MlsError};
use mls_crypto_provider::{PkiKeypair, RustCrypto, TransactionalCryptoProvider};
use openmls_basic_credential::SignatureKeyPair as OpenMlsSignatureKeyPair;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, SignatureScheme},
    OpenMlsCryptoProvider,
};
use wire_e2e_identity::prelude::JwsAlgorithm;
use zeroize::Zeroize;

impl super::E2eiEnrollment {
    pub(super) fn new_sign_key(
        ciphersuite: MlsCiphersuite,
        backend: &TransactionalCryptoProvider,
    ) -> CryptoResult<E2eiSignatureKeypair> {
        let (sk, _) = backend
            .crypto()
            .signature_key_gen(ciphersuite.signature_algorithm())
            .map_err(MlsError::from)?;
        E2eiSignatureKeypair::try_new(ciphersuite.signature_algorithm(), sk)
    }

    pub(super) fn get_sign_key_for_mls(&self) -> CryptoResult<Vec<u8>> {
        let sk = match self.ciphersuite.signature_algorithm() {
            SignatureScheme::ECDSA_SECP256R1_SHA256 | SignatureScheme::ECDSA_SECP384R1_SHA384 => self.sign_sk.to_vec(),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => RustCrypto::normalize_p521_secret_key(&self.sign_sk).to_vec(),
            SignatureScheme::ED25519 => RustCrypto::normalize_ed25519_key(self.sign_sk.as_slice())
                .map_err(MlsError::from)?
                .to_bytes()
                .to_vec(),
            SignatureScheme::ED448 => return Err(E2eIdentityError::NotYetSupported.into()),
        };
        Ok(sk)
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
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => JwsAlgorithm::P521,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                return Err(E2eIdentityError::NotYetSupported)
            }
        })
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Zeroize, derive_more::From, derive_more::Deref)]
#[zeroize(drop)]
pub struct E2eiSignatureKeypair(Vec<u8>);

impl E2eiSignatureKeypair {
    pub fn try_new(sc: SignatureScheme, sk: Vec<u8>) -> CryptoResult<Self> {
        let keypair = PkiKeypair::new(sc, sk)?;
        Ok(Self(keypair.signing_key_bytes()))
    }
}

impl TryFrom<&OpenMlsSignatureKeyPair> for E2eiSignatureKeypair {
    type Error = CryptoError;

    fn try_from(kp: &OpenMlsSignatureKeyPair) -> CryptoResult<Self> {
        Self::try_new(kp.signature_scheme(), kp.private().to_vec())
    }
}
