use core_crypto_keystore::{
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
    traits::FetchFromDatabase,
};
use wire_e2e_identity::prelude::x509::{
    extract_crl_uris, extract_expiration_from_crl,
    revocation::{PkiEnvironment, PkiEnvironmentParams},
};
use x509_cert::der::Decode;

use super::{Error, Result};
use crate::{
    KeystoreError, RecursiveError,
    e2e_identity::{CrlRegistration, NewCrlDistributionPoints},
    transaction_context::TransactionContext,
};

impl TransactionContext {
    /// See [crate::mls::session::Session::e2ei_is_pki_env_setup].
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        let Ok(pki_env) = self.pki_environment().await else {
            return false;
        };

        pki_env.mls_pki_env_provider().is_env_setup().await
    }

    /// Registers a Root Trust Anchor CA for the use in E2EI processing.
    ///
    /// Please note that without a Root Trust Anchor, all validations *will* fail;
    /// So this is the first step to perform after initializing your E2EI client
    ///
    /// # Parameters
    /// * `trust_anchor_pem` - PEM certificate to anchor as a Trust Root
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> Result<()> {
        let pki_environment = self.pki_environment().await.map_err(RecursiveError::transaction(
            "Getting PKI environment from transaction context",
        ))?;

        let database = pki_environment.database();

        if matches!(database.get_unique::<E2eiAcmeCA>().await, Ok(Some(_))) {
            return Err(Error::TrustAnchorAlreadyRegistered);
        }

        let pki_env = PkiEnvironment::init(PkiEnvironmentParams {
            intermediates: Default::default(),
            trust_roots: Default::default(),
            crls: Default::default(),
            time_of_interest: Default::default(),
        })?;

        // Parse/decode PEM cert
        let root_cert = PkiEnvironment::decode_pem_cert(trust_anchor_pem)?;

        // Validate it (expiration & signature only)
        pki_env.validate_trust_anchor_cert(&root_cert)?;

        // Save DER repr in keystore
        let cert_der = PkiEnvironment::encode_cert_to_der(&root_cert)?;
        let acme_ca = E2eiAcmeCA { content: cert_der };
        database
            .save(acme_ca)
            .await
            .map_err(KeystoreError::wrap("saving acme ca"))?;

        // To do that, tear down and recreate the inner pki env
        pki_environment.update_pki_environment_provider().await?;
        Ok(())
    }

    /// Registers an Intermediate CA for the use in E2EI processing.
    ///
    /// Please note that a Root Trust Anchor CA is needed to validate Intermediate CAs;
    /// You **need** to have a Root CA registered before calling this
    ///
    /// # Parameters
    /// * `cert_pem` - PEM certificate to register as an Intermediate CA
    pub async fn e2ei_register_intermediate_ca_pem(&self, cert_pem: String) -> Result<NewCrlDistributionPoints> {
        // Parse/decode PEM cert
        let inter_ca = PkiEnvironment::decode_pem_cert(cert_pem)?;
        self.e2ei_register_intermediate_ca(inter_ca).await
    }

    pub(crate) async fn e2ei_register_intermediate_ca_der(&self, cert_der: &[u8]) -> Result<NewCrlDistributionPoints> {
        let inter_ca = x509_cert::Certificate::from_der(cert_der)?;
        self.e2ei_register_intermediate_ca(inter_ca).await
    }

    async fn e2ei_register_intermediate_ca(
        &self,
        inter_ca: x509_cert::Certificate,
    ) -> Result<NewCrlDistributionPoints> {
        let pki_environment = self.pki_environment().await.map_err(RecursiveError::transaction(
            "Getting PKI environment from transaction context",
        ))?;

        // TrustAnchor must have been registered at this point
        let database = pki_environment.database();

        let trust_anchor = database
            .get_unique::<E2eiAcmeCA>()
            .await
            .map_err(KeystoreError::wrap("finding acme ca"))?
            .ok_or(Error::NotFound("E2eiAcmeCA"))?;
        let trust_anchor = x509_cert::Certificate::from_der(&trust_anchor.content)?;

        // the `/federation` endpoint from smallstep repeats the root CA
        // so we filter it out here so that clients don't have to do it
        if inter_ca == trust_anchor {
            return Ok(None.into());
        }

        let intermediate_crl = extract_crl_uris(&inter_ca)?.map(|s| s.into_iter().collect());

        let (ski, aki) = PkiEnvironment::extract_ski_aki_from_cert(&inter_ca)?;

        let ski_aki_pair = format!("{ski}:{}", aki.unwrap_or_default());

        // Validate it
        {
            let provider = pki_environment.mls_pki_env_provider();
            let auth_service_arc = provider.borrow().await;
            let Some(pki_env) = auth_service_arc.as_ref() else {
                return Err(Error::PkiEnvironmentUnset);
            };
            pki_env.validate_cert_and_revocation(&inter_ca)?;
        }

        // Save DER repr in keystore
        let cert_der = PkiEnvironment::encode_cert_to_der(&inter_ca)?;
        let intermediate_ca = E2eiIntermediateCert {
            content: cert_der,
            ski_aki_pair,
        };
        database
            .save(intermediate_ca)
            .await
            .map_err(KeystoreError::wrap("saving intermediate ca"))?;

        pki_environment.update_pki_environment_provider().await?;

        Ok(intermediate_crl.into())
    }

    /// Registers a CRL for the use in E2EI processing.
    ///
    /// Please note that a Root Trust Anchor CA is needed to validate CRLs;
    /// You **need** to have a Root CA registered before calling this
    ///
    /// # Parameters
    /// * `crl_dp` - CRL Distribution Point; Basically the URL you fetched it from
    /// * `crl_der` - DER representation of the CRL
    ///
    /// # Returns
    /// A [CrlRegistration] with the dirty state of the new CRL (see struct) and its expiration timestamp
    pub async fn e2ei_register_crl(&self, crl_dp: String, crl_der: Vec<u8>) -> Result<CrlRegistration> {
        let pki_environment = self.pki_environment().await.map_err(RecursiveError::transaction(
            "Getting PKI environment from transaction context",
        ))?;
        // Parse & Validate CRL
        let crl = {
            let provider = pki_environment.mls_pki_env_provider();
            let auth_service_arc = provider.borrow().await;
            let Some(pki_env) = auth_service_arc.as_ref() else {
                return Err(Error::PkiEnvironmentUnset);
            };
            pki_env.validate_crl_with_raw(&crl_der)?
        };

        let expiration = extract_expiration_from_crl(&crl);

        let database = pki_environment.database();

        let dirty = database
            .get::<E2eiCrl>(&crl_dp)
            .await
            .ok()
            .flatten()
            .map(|existing_crl| {
                PkiEnvironment::decode_der_crl(existing_crl.content.clone())
                    .map(|old_crl| old_crl.tbs_cert_list.revoked_certificates != crl.tbs_cert_list.revoked_certificates)
            })
            .transpose()?
            .unwrap_or_default();

        // Save DER repr in keystore
        let crl_data = E2eiCrl {
            content: PkiEnvironment::encode_crl_to_der(&crl)?,
            distribution_point: crl_dp,
        };
        database
            .save(crl_data)
            .await
            .map_err(KeystoreError::wrap("saving crl"))?;

        pki_environment.update_pki_environment_provider().await?;
        Ok(CrlRegistration { expiration, dirty })
    }
}

#[cfg(test)]
mod tests {
    use x509_cert::der::EncodePem;

    use super::super::Error;
    use crate::test_utils::*;

    #[apply(all_cred_cipher)]
    async fn register_acme_ca_should_fail_when_already_set(case: TestContext) {
        use x509_cert::der::pem::LineEnding;

        if !case.is_x509() {
            return;
        }

        let [alice] = case.sessions().await;
        Box::pin(async move {
            let alice_test_chain = alice.x509_chain_unchecked();
            let alice_ta = alice_test_chain
                .trust_anchor
                .certificate
                .to_pem(LineEnding::CRLF)
                .unwrap();

            assert!(matches!(
                alice.transaction.e2ei_register_acme_ca(alice_ta).await.unwrap_err(),
                Error::TrustAnchorAlreadyRegistered
            ));
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    async fn x509_restore_should_not_happen_if_basic(case: TestContext) {
        if case.is_x509() {
            return;
        }

        let [alice_id] = case.basic_client_ids();
        let alice_id = ClientIdentifier::Basic(alice_id);
        let alice = SessionContext::new_with_identifier(&case, alice_id, None)
            .await
            .unwrap();

        Box::pin(async move {
            assert!(!alice.transaction.e2ei_is_pki_env_setup().await);

            // mls_central.restore_from_disk().await.unwrap();

            // assert!(!mls_central.mls_backend.is_pki_env_setup().await);
        })
        .await;
    }
}
