use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{
    crypto::OpenMlsCrypto as _,
    signatures::{DefaultSigner as _, Signer},
    types::Error,
};

use crate::mls_provider::CRYPTO;

/// Signs through our crypto provider, so that signing uses the same backend as everything else.
///
/// `SignatureKeyPair` is itself a [`Signer`], through openmls' blanket implementation for
/// `DefaultSigner`, but that one signs with RustCrypto unconditionally. Pass this to openmls
/// instead, wherever it asks for a signer.
pub(crate) struct ProviderSigner<'a>(pub(super) &'a SignatureKeyPair);

impl Signer for ProviderSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let scheme = self.0.signature_scheme();
        CRYPTO
            .sign(scheme, payload, self.0.private_key())
            // Report errors as openmls' own signer did.
            .map_err(|err| match scheme {
                SignatureScheme::MLDSA44 | SignatureScheme::MLDSA65 | SignatureScheme::MLDSA87 => {
                    Error::CryptoError(err)
                }
                _ => Error::SigningError,
            })
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.0.signature_scheme()
    }
}
