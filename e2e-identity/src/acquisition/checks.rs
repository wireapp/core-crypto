use rusty_jwt_tools::prelude::{ClientId, Handle};
use x509_cert::{Certificate, anchor::TrustAnchorChoice};

use super::{X509CredentialAcquisition, states};
use crate::{
    acquisition::{error::CertificateError, identity::WireIdentityReader as _},
    validation::{prepare_environment, validate_cert},
};

impl X509CredentialAcquisition<states::DpopChallengeCompleted> {
    pub(crate) async fn verify_cert_chain(&self, certs: &[Certificate]) -> Result<(), CertificateError> {
        // We can be sure there is at least one certificate because the ACME server
        // response was checked prior to calling this function.
        let (leaf, intermediates) = certs.split_first().expect("at least one certificate");

        let trust_anchors: Vec<TrustAnchorChoice> = self
            .pki_env
            .get_trust_anchors()
            .await
            .into_iter()
            .map(TrustAnchorChoice::Certificate)
            .collect();

        let env = prepare_environment(&trust_anchors, intermediates, &[])?;
        self.verify_leaf_certificate(&env, leaf).await?;

        // see https://datatracker.ietf.org/doc/html/rfc8555#section-11.4
        crate::utils::extract_ski_aki_from_cert(leaf)?;

        Ok(())
    }

    /// Ensure that the generated certificate matches our expectations, i.e. that the fields in the
    /// certificate match configuration values.
    async fn verify_leaf_certificate(
        &self,
        env: &certval::environment::PkiEnvironment,
        cert: &Certificate,
    ) -> Result<(), CertificateError> {
        validate_cert(env, cert, false)?;

        // Make sure that the algorithm specified by the certificate matches the one of the signing
        // keypair.
        let alg = crate::utils::jws_alg_to_x509_identifier(self.sign_alg);
        if cert.tbs_certificate().subject_public_key_info().algorithm != alg {
            return Err(CertificateError::AlgorithmMismatch);
        }

        // Make sure that the public key in the certificate matches the one from the signing keypair.
        let sign_kp_bytes = crate::utils::public_key_bytes(self.sign_alg, &self.sign_kp)
            .map_err(|_| CertificateError::InvalidSigningKeypair)?;
        let cert_pubkey_bytes = cert
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes();
        if sign_kp_bytes != cert_pubkey_bytes {
            return Err(CertificateError::KeyMismatch);
        }

        let config = &self.config;
        let cert_identity = cert.extract_identity(&self.pki_env).await?;

        let cert_id =
            ClientId::try_from_qualified(&cert_identity.client_id).map_err(|_| CertificateError::InvalidClientId)?;
        if cert_id != config.client_id {
            return Err(CertificateError::ClientIdMismatch);
        }

        if cert_identity.display_name != config.display_name {
            return Err(CertificateError::DisplayNameMismatch);
        }

        let handle = Handle::from(config.handle.as_ref())
            .try_to_qualified(&config.domain)
            .expect("X509 configuration handle and domain must be valid");
        if cert_identity.handle != handle {
            return Err(CertificateError::HandleMismatch);
        }

        if cert_identity.domain != config.domain {
            return Err(CertificateError::DomainMismatch);
        }
        Ok(())
    }
}
