//! It can be desirable to export a credential as a PEM file.
//!
//! For basic credentials, this is a simple PEM-encoding of the credential's public key.
//!
//! For x509 credentials, this exports the full certificate chain in a composite file.

use std::debug_assert_matches;

use openmls::prelude::MlsCredentialType;
use pem::{self, Pem};

use crate::{Credential, CredentialType};

impl Credential {
    /// A basic credential is nothing but a signing key, so wrap that up in PEM format and call it a day.
    fn export_basic_pem(&self) -> String {
        debug_assert_matches!(self.credential_type, CredentialType::Basic);
        debug_assert_matches!(
            self.mls_credential.mls_credential(),
            MlsCredentialType::Basic(_),
            "coding error: attempted to export basic pem given x509 credential"
        );

        let public_key = self.signature_key_pair.public();
        let pem = Pem::new("PUBLIC KEY", public_key);
        pem::encode(&pem)
    }

    /// Encode a composite PEM document containing the certificate chain for this credential.
    fn export_x509_pem(&self) -> String {
        debug_assert_matches!(self.credential_type, CredentialType::X509);
        let MlsCredentialType::X509(credential) = self.mls_credential.mls_credential() else {
            panic!("coding error: attempted to export x509 pem given basic credential");
        };

        let mut pem_document = String::new();

        // It's not documented, but OpenMLS stores the certificates in its `Certificate` type
        // leaf-first. One presumes that each subsequent certificate in the chain signs the previous.
        // https://github.com/wireapp/openmls/blob/c9cde17076508968c9cbead5728454f0a1f60c4f/openmls/src/credentials/mod.rs#L189-L190
        // This seems to be the conventional ordering for a composite PEM document as well.
        //
        // We encode manually instead of using `pem::encode_many` in order to reduce the amount of
        // unnecessary allocation; we still have to allocate for all the certificates' bytes and also
        // their output string, but at least we're not also allocating a new vector.
        for certificate in &credential.certificates {
            let pem = Pem::new("CERTIFICATE", certificate.as_slice());
            pem_document.push_str(&pem::encode(&pem));
        }

        pem_document
    }

    /// Export a PEM string containing the public portion of this credential.
    ///
    /// - Basic credentials export their public key.
    /// - x509 credentials export the full certificate chain. This enables external tools such as `openssl` to validate
    ///   the certificate chain.
    pub fn export_pem(&self) -> String {
        match self.credential_type {
            CredentialType::Basic => self.export_basic_pem(),
            CredentialType::X509 => self.export_x509_pem(),
        }
    }
}
