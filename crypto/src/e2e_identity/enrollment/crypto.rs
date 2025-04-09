use mls_crypto_provider::{MlsCryptoProvider, RustCrypto};
use openmls::prelude::SignatureScheme;
use openmls_traits::{OpenMlsCryptoProvider as _, crypto::OpenMlsCrypto as _};

use super::{Error, Result};
use crate::{MlsError, e2e_identity::crypto::E2eiSignatureKeypair, prelude::MlsCiphersuite};

impl super::E2eiEnrollment {
    pub(crate) fn new_sign_key(
        ciphersuite: MlsCiphersuite,
        backend: &MlsCryptoProvider,
    ) -> Result<E2eiSignatureKeypair> {
        let (sk, _) = backend
            .crypto()
            .signature_key_gen(ciphersuite.signature_algorithm())
            .map_err(MlsError::wrap("performing signature keygen"))?;
        E2eiSignatureKeypair::try_new(ciphersuite.signature_algorithm(), sk)
    }

    pub(crate) fn get_sign_key_for_mls(&self) -> Result<Vec<u8>> {
        let sk = match self.ciphersuite.signature_algorithm() {
            SignatureScheme::ECDSA_SECP256R1_SHA256 | SignatureScheme::ECDSA_SECP384R1_SHA384 => self.sign_sk.to_vec(),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => RustCrypto::normalize_p521_secret_key(&self.sign_sk).to_vec(),
            SignatureScheme::ED25519 => RustCrypto::normalize_ed25519_key(self.sign_sk.as_slice())
                .map_err(MlsError::wrap("normalizing ed25519 key"))?
                .to_bytes()
                .to_vec(),
            SignatureScheme::ED448 => return Err(Error::NotYetSupported),
        };
        Ok(sk)
    }
}
