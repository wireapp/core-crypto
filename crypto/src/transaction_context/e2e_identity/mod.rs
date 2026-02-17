//! This module contains all behaviour of a transaction context connected to end-to-end identity.

pub(crate) mod conversation_state;
pub mod enabled;
mod error;
mod init_certificates;

use std::{collections::HashSet, sync::Arc};

pub use error::{Error, Result};
use openmls_traits::types::SignatureScheme;
use wire_e2e_identity::{NewCrlDistributionPoints, x509_check::extract_crl_uris};

use super::TransactionContext;
use crate::{
    CertificateBundle, Ciphersuite, ClientId, Credential, CredentialRef, E2eiEnrollment, MlsTransport, RecursiveError,
    RustCrypto,
    mls::credential::{crl::get_new_crl_distribution_points, x509::CertificatePrivateKey},
};

impl TransactionContext {
    /// Creates an enrollment instance with private key material you can use in order to fetch
    /// a new x509 certificate from the acme server.
    ///
    /// # Parameters
    /// * `client_id` - client identifier e.g. `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry_sec` - generated x509 certificate expiry in seconds
    pub async fn e2ei_new_enrollment(
        &self,
        client_id: ClientId,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Result<E2eiEnrollment> {
        let client_id = wire_e2e_identity::legacy::id::ClientId::from(client_id.0);
        E2eiEnrollment::try_new::<RustCrypto>(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            ciphersuite.into(),
            false, // fresh install so no refresh token registered yet
            crate::mls_provider::CRYPTO.as_ref(),
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    /// Saves a new X509 credential. Requires first having enrolled a new X509 certificate
    /// with [TransactionContext::e2ei_new_enrollment].
    ///
    /// # Expected actions to perform after this function (in this order)
    /// 1. Set the credential to the return value of this function for each conversation via
    ///    [crate::mls::conversation::ConversationGuard::set_credential_by_ref]
    /// 2. Generate new key packages with [Self::generate_keypackage]
    /// 3. Use these to replace the stale ones the in the backend
    /// 4. Delete the old credentials and keypackages locally using [Self::remove_credential]
    pub async fn save_x509_credential(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
    ) -> Result<(CredentialRef, NewCrlDistributionPoints)> {
        let sk = get_sign_key_for_mls(enrollment)?;
        let ciphersuite = *enrollment.ciphersuite();
        let signature_scheme = ciphersuite.signature_algorithm();

        let pki_environment = self
            .pki_environment()
            .await
            .map_err(RecursiveError::transaction("getting pki environment"))?;
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                pki_environment
                    .mls_pki_env_provider()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("getting certificate response"))?;

        let private_key = CertificatePrivateKey::new(sk);

        let crl_new_distribution_points = self.extract_dp_on_init(&certificate_chain[..]).await?;

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
            signature_scheme,
        };

        let credential = Credential::x509(ciphersuite.into(), cert_bundle).map_err(RecursiveError::mls_credential(
            "creating new x509 credential from certificate bundle in save_x509_credential",
        ))?;

        let credential_ref = self
            .add_credential(credential)
            .await
            .map_err(RecursiveError::transaction(
                "saving and adding credential in save_x509_credential",
            ))?;

        Ok((credential_ref, crl_new_distribution_points))
    }
    /// Parses the ACME server response from the endpoint fetching x509 certificates and uses it
    /// to initialize the MLS client with a certificate
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
        transport: Arc<dyn MlsTransport>,
    ) -> Result<(CredentialRef, NewCrlDistributionPoints)> {
        let pki_environment = self
            .pki_environment()
            .await
            .map_err(RecursiveError::transaction("getting pki environment"))?;

        let sk = get_sign_key_for_mls(enrollment)?;
        let ciphersuite = *enrollment.ciphersuite();
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                pki_environment
                    .mls_pki_env_provider()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("getting certificate response"))?;

        let crl_new_distribution_points = self.extract_dp_on_init(&certificate_chain[..]).await?;

        let private_key = CertificatePrivateKey::new(sk);

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
            signature_scheme: ciphersuite.signature_algorithm(),
        };

        let mut credential = Credential::x509(ciphersuite.into(), cert_bundle.clone()).map_err(
            RecursiveError::mls_credential("creating credential from certificate bundle in e2ei_mls_init_only"),
        )?;
        let database = &self
            .database()
            .await
            .map_err(RecursiveError::transaction("Getting database from transaction context"))?;
        let credential_ref = credential.save(database).await.map_err(RecursiveError::mls_credential(
            "saving credential in e2ei_mls_init_only",
        ))?;
        let session_id = cert_bundle.get_client_id().map_err(RecursiveError::mls_credential(
            "Getting session id from certificate bundle",
        ))?;
        self.mls_init(session_id, transport)
            .await
            .map_err(RecursiveError::transaction("initializing mls"))?;
        Ok((credential_ref, crl_new_distribution_points))
    }

    /// When x509 new credentials are registered this extracts the new CRL Distribution Point from the end entity
    /// certificate and all the intermediates
    async fn extract_dp_on_init(&self, certificate_chain: &[Vec<u8>]) -> Result<NewCrlDistributionPoints> {
        use x509_cert::der::Decode as _;

        // Own intermediates are not provided by smallstep in the /federation endpoint so we got to intercept them here,
        // at issuance
        let size = certificate_chain.len();
        let mut crl_new_distribution_points = HashSet::new();
        if size > 1 {
            for int in certificate_chain.iter().skip(1).rev() {
                let mut crl_dp = self
                    .e2ei_register_intermediate_ca_der(int)
                    .await
                    .map_err(RecursiveError::transaction("registering intermediate ca der"))?;
                if let Some(crl_dp) = crl_dp.take() {
                    crl_new_distribution_points.extend(crl_dp);
                }
            }
        }

        let ee = certificate_chain.first().ok_or(Error::InvalidCertificateChain)?;
        let ee = x509_cert::Certificate::from_der(ee)
            .map_err(crate::mls::credential::Error::DecodeX509)
            .map_err(RecursiveError::mls_credential("decoding x509 credential"))?;
        let mut ee_crl_dp = extract_crl_uris(&ee).map_err(RecursiveError::e2e_identity("extracting crl urls"))?;
        if let Some(crl_dp) = ee_crl_dp.take() {
            crl_new_distribution_points.extend(crl_dp);
        }

        let database = self
            .database()
            .await
            .map_err(RecursiveError::transaction("getting database"))?;
        get_new_crl_distribution_points(&database, crl_new_distribution_points)
            .await
            .map_err(RecursiveError::mls_credential("getting new crl distribution points"))
            .map_err(Into::into)
    }
}
