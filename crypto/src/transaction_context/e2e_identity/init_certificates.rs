use core_crypto_keystore::{
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
    traits::FetchFromDatabase,
};
use wire_e2e_identity::{
    NewCrlDistributionPoints,
    legacy::CrlRegistration,
    x509_check::{
        extract_crl_uris, extract_expiration_from_crl,
        revocation::{PkiEnvironment, PkiEnvironmentParams},
    },
};
use x509_cert::der::Decode;

use super::{Error, Result};
use crate::{KeystoreError, RecursiveError, transaction_context::TransactionContext};

impl TransactionContext {
    /// See [crate::mls::session::Session::e2ei_is_pki_env_setup].
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.pki_environment().await.ok().flatten().is_some()
    }

    /// Registers a Root Trust Anchor CA for the use in E2EI processing.
    ///
    /// Please note that without a Root Trust Anchor, all validations *will* fail;
    /// So this is the first step to perform after initializing your E2EI client
    ///
    /// # Parameters
    /// * `trust_anchor_pem` - PEM certificate to anchor as a Trust Root
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> Result<()> {
        let outer_pki_env = self
            .pki_environment()
            .await
            .map_err(RecursiveError::transaction(
                "Getting PKI environment from transaction context",
            ))?
            .ok_or(Error::PkiEnvironmentUnset)?;

        let database = outer_pki_env.database();

        if matches!(database.get_unique::<E2eiAcmeCA>().await, Ok(Some(_))) {
            return Err(Error::TrustAnchorAlreadyRegistered);
        }

        let pki_env = PkiEnvironment::init(PkiEnvironmentParams {
            intermediates: Default::default(),
            trust_roots: Default::default(),
            crls: Default::default(),
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
        outer_pki_env.update_pki_environment_provider().await?;
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

    async fn e2ei_register_intermediate_ca(
        &self,
        inter_ca: x509_cert::Certificate,
    ) -> Result<NewCrlDistributionPoints> {
        let outer_pki_env = self
            .pki_environment()
            .await
            .map_err(RecursiveError::transaction(
                "Getting PKI environment from transaction context",
            ))?
            .ok_or(Error::PkiEnvironmentUnset)?;

        // TrustAnchor must have been registered at this point
        let database = outer_pki_env.database();

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
        outer_pki_env
            .mls_pki_env_provider()
            .validate_cert_and_revocation(&inter_ca)?;

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

        outer_pki_env.update_pki_environment_provider().await?;

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
        let outer_pki_env = self
            .pki_environment()
            .await
            .map_err(RecursiveError::transaction(
                "Getting PKI environment from transaction context",
            ))?
            .ok_or(Error::PkiEnvironmentUnset)?;

        // Parse & Validate CRL
        let crl = outer_pki_env.mls_pki_env_provider().validate_crl_with_raw(&crl_der)?;
        let expiration = extract_expiration_from_crl(&crl);

        let database = outer_pki_env.database();

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

        outer_pki_env.update_pki_environment_provider().await?;
        Ok(CrlRegistration { expiration, dirty })
    }
}
