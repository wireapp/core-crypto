use openmls_traits::types::{Ciphersuite, SignatureScheme};
use zeroize::Zeroize;

use crate::{
    JwsAlgorithm,
    error::{E2eIdentityError, E2eIdentityResult},
    pki::PkiKeypair,
};

pub(crate) fn ciphersuite_to_jws_algo(cs: Ciphersuite) -> E2eIdentityResult<JwsAlgorithm> {
    match cs {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => Ok(JwsAlgorithm::Ed25519),
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(JwsAlgorithm::P256),
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => Ok(JwsAlgorithm::P384),
        Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => Ok(JwsAlgorithm::P521),
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => Err(E2eIdentityError::NotSupported),
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Zeroize, derive_more::From, derive_more::Deref)]
#[zeroize(drop)]
pub struct E2eiSignatureKeypair(Vec<u8>);

impl E2eiSignatureKeypair {
    pub fn try_new(sc: SignatureScheme, sk: Vec<u8>) -> E2eIdentityResult<Self> {
        let keypair = PkiKeypair::new(sc, sk)?;
        Ok(Self(keypair.signing_key_bytes()))
    }
}
