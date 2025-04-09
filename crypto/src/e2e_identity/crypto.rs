use super::error::*;
use crate::{MlsError, prelude::MlsCiphersuite};
use mls_crypto_provider::PkiKeypair;
use openmls_basic_credential::SignatureKeyPair as OpenMlsSignatureKeyPair;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use wire_e2e_identity::prelude::JwsAlgorithm;
use zeroize::Zeroize;

impl TryFrom<MlsCiphersuite> for JwsAlgorithm {
    type Error = Error;

    fn try_from(cs: MlsCiphersuite) -> Result<Self> {
        let cs = openmls_traits::types::Ciphersuite::from(cs);
        Ok(match cs {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => JwsAlgorithm::Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => JwsAlgorithm::P256,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => JwsAlgorithm::P384,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => JwsAlgorithm::P521,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => return Err(Error::NotYetSupported),
        })
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Zeroize, derive_more::From, derive_more::Deref)]
#[zeroize(drop)]
pub struct E2eiSignatureKeypair(Vec<u8>);

impl E2eiSignatureKeypair {
    pub fn try_new(sc: SignatureScheme, sk: Vec<u8>) -> Result<Self> {
        let keypair = PkiKeypair::new(sc, sk).map_err(MlsError::wrap("creating new pki keypair"))?;
        Ok(Self(keypair.signing_key_bytes()))
    }
}

impl TryFrom<&OpenMlsSignatureKeyPair> for E2eiSignatureKeypair {
    type Error = Error;

    fn try_from(kp: &OpenMlsSignatureKeyPair) -> Result<Self> {
        Self::try_new(kp.signature_scheme(), kp.private().to_vec())
    }
}
