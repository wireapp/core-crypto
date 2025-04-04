use super::{Error, Result};
use crate::e2e_identity::E2eiDumpedPkiEnv;
use crate::{
    KeystoreError, MlsError, RecursiveError,
    e2e_identity::{CrlRegistration, NewCrlDistributionPoints, restore_pki_env},
    transaction_context::TransactionContext,
};
use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
};
use openmls_traits::OpenMlsCryptoProvider;
use wire_e2e_identity::prelude::x509::{
    extract_crl_uris, extract_expiration_from_crl,
    revocation::{PkiEnvironment, PkiEnvironmentParams},
};
use x509_cert::der::Decode;

impl TransactionContext {
    /// See [Client::e2ei_is_pki_env_setup].
    /// Unlike [Client::e2ei_is_pki_env_setup], this function returns a result.
    pub async fn e2ei_is_pki_env_setup(&self) -> Result<bool> {
        Ok(self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?
            .authentication_service()
            .is_env_setup()
            .await)
    }

    /// See [Client::e2ei_dump_pki_env].
    pub async fn e2ei_dump_pki_env(&self) -> Result<Option<E2eiDumpedPkiEnv>> {
        if !self.e2ei_is_pki_env_setup().await? {
            return Ok(None);
        }
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        let Some(pki_env) = &*mls_provider.authentication_service().borrow().await else {
            return Ok(None);
        };
        E2eiDumpedPkiEnv::from_pki_env(pki_env)
            .await
            .map_err(RecursiveError::e2e_identity("dumping pki env"))
            .map_err(Into::into)
    }

    /// Registers a Root Trust Anchor CA for the use in E2EI processing.
    ///
    /// Please note that without a Root Trust Anchor, all validations *will* fail;
    /// So this is the first step to perform after initializing your E2EI client
    ///
    /// # Parameters
    /// * `trust_anchor_pem` - PEM certificate to anchor as a Trust Root
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> Result<()> {
        {
            if self
                .mls_provider()
                .await
                .map_err(RecursiveError::transaction("getting mls provider"))?
                .keystore()
                .find_unique::<E2eiAcmeCA>()
                .await
                .is_ok()
            {
                return Err(Error::TrustAnchorAlreadyRegistered);
            }
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
        self.mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?
            .keystore()
            .save(acme_ca)
            .await
            .map_err(KeystoreError::wrap("saving acme ca"))?;

        // To do that, tear down and recreate the pki env
        self.init_pki_env().await?;

        Ok(())
    }

    pub(crate) async fn init_pki_env(&self) -> Result<()> {
        if let Some(pki_env) = restore_pki_env(
            &self
                .mls_provider()
                .await
                .map_err(RecursiveError::transaction("getting mls provider"))?
                .keystore(),
        )
        .await
        .map_err(RecursiveError::e2e_identity("restoring pki env"))?
        {
            let provider = self
                .mls_provider()
                .await
                .map_err(RecursiveError::transaction("getting mls provider"))?;
            provider
                .authentication_service()
                .update_env(pki_env)
                .await
                .map_err(MlsError::wrap("updating authentication service env"))?;
        }

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
        // TrustAnchor must have been registered at this point
        let keystore = self
            .keystore()
            .await
            .map_err(RecursiveError::transaction("getting keystore"))?;
        let trust_anchor = keystore
            .find_unique::<E2eiAcmeCA>()
            .await
            .map_err(KeystoreError::wrap("finding acme ca"))?;
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
            let provider = self
                .mls_provider()
                .await
                .map_err(RecursiveError::transaction("getting mls provider"))?;
            let auth_service_arc = provider.authentication_service().borrow().await;
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
        keystore
            .save(intermediate_ca)
            .await
            .map_err(KeystoreError::wrap("saving intermediate ca"))?;

        self.init_pki_env().await?;

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
        // Parse & Validate CRL
        let crl = {
            let provider = self
                .mls_provider()
                .await
                .map_err(RecursiveError::transaction("getting mls provider"))?;
            let auth_service_arc = provider.authentication_service().borrow().await;
            let Some(pki_env) = auth_service_arc.as_ref() else {
                return Err(Error::PkiEnvironmentUnset);
            };
            pki_env.validate_crl_with_raw(&crl_der)?
        };

        let expiration = extract_expiration_from_crl(&crl);

        let ks = self
            .keystore()
            .await
            .map_err(RecursiveError::transaction("getting keystore"))?;

        let dirty = ks
            .find::<E2eiCrl>(crl_dp.as_bytes())
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
        ks.save(crl_data).await.map_err(KeystoreError::wrap("saving crl"))?;

        self.init_pki_env().await?;

        Ok(CrlRegistration { expiration, dirty })
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;
    use x509_cert::der::EncodePem;

    use crate::test_utils::*;

    use super::super::Error;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn register_acme_ca_should_fail_when_already_set(case: TestCase) {
        use x509_cert::der::pem::LineEnding;

        if !case.is_x509() {
            return;
        }
        run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
            Box::pin(async move {
                let alice_test_chain = alice_central.x509_test_chain.as_ref().as_ref().unwrap();
                let alice_ta = alice_test_chain
                    .trust_anchor
                    .certificate
                    .to_pem(LineEnding::CRLF)
                    .unwrap();

                assert!(matches!(
                    alice_central.context.e2ei_register_acme_ca(alice_ta).await.unwrap_err(),
                    Error::TrustAnchorAlreadyRegistered
                ));
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn x509_restore_should_not_happen_if_basic(case: TestCase) {
        if case.is_x509() {
            return;
        }
        run_test_with_client_ids(case.clone(), ["alice"], move |[alice_ctx]| {
            Box::pin(async move {
                let SessionContext {
                    context,
                    x509_test_chain,
                    ..
                } = alice_ctx;

                assert!(x509_test_chain.is_none());
                assert!(!context.e2ei_is_pki_env_setup().await.unwrap());

                // mls_central.restore_from_disk().await.unwrap();

                assert!(x509_test_chain.is_none());
                // assert!(!mls_central.mls_backend.is_pki_env_setup().await);
            })
        })
        .await;
    }
}
