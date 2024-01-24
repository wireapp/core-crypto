use crate::{e2e_identity::CrlRegistration, prelude::MlsCentral, CryptoError, CryptoResult};
use core_crypto_keystore::entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, EntityBase, UniqueEntity};
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::OpenMlsCryptoProvider;
use std::ops::DerefMut;
use wire_e2e_identity::prelude::x509::{
    extract_expiration_from_crl,
    revocation::{PkiEnvironment, PkiEnvironmentParams},
};
use x509_cert::der::Decode;

impl MlsCentral {
    /// Registers a Root Trust Anchor CA for the use in E2EI processing.
    ///
    /// Please note that without a Root Trust Anchor, all validations *will* fail;
    /// So this is the first step to perform after initializing your E2EI client
    ///
    /// # Parameters
    /// * `trust_anchor_pem` - PEM certificate to anchor as a Trust Root
    pub async fn e2ei_register_acme_ca(&mut self, trust_anchor_pem: String) -> CryptoResult<()> {
        let pki_env = PkiEnvironment::init(PkiEnvironmentParams {
            intermediates: Default::default(),
            trust_roots: Default::default(),
            crls: Default::default(),
            time_of_interest: Default::default(),
        })
        .map_err(|e| CryptoError::E2eiError(e.into()))?;

        // Parse/decode PEM cert
        let root_cert =
            PkiEnvironment::decode_pem_cert(trust_anchor_pem).map_err(|e| CryptoError::E2eiError(e.into()))?;

        // Validate it (expiration & signature only)
        pki_env
            .validate_trust_anchor_cert(&root_cert)
            .map_err(|e| CryptoError::E2eiError(e.into()))?;

        // Save DER repr in keystore
        let cert_der = PkiEnvironment::encode_cert_to_der(&root_cert).map_err(|e| CryptoError::E2eiError(e.into()))?;
        let acme_ca = E2eiAcmeCA { content: cert_der };
        let mut conn = self.mls_backend.key_store().borrow_conn().await?;
        acme_ca.replace(&mut conn).await?;
        drop(conn);

        // To do that, tear down and recreate the pki env
        self.init_pki_env().await?;

        Ok(())
    }

    /// Registers an Intermediate CA for the use in E2EI processing.
    ///
    /// Please note that a Root Trust Anchor CA is needed to validate Intermediate CAs;
    /// You **need** to have a Root CA registered before calling this
    ///
    /// # Parameters
    /// * `cert_pem` - PEM certificate to register as an Intermediate CA
    pub async fn e2ei_register_intermediate_ca(&mut self, cert_pem: String) -> CryptoResult<()> {
        let Some(pki_env) = self.e2ei_pki_env.as_ref() else {
            return Err(CryptoError::ConsumerError);
        };

        // TrustAnchor must have been registered at this point
        let ta = E2eiAcmeCA::find_unique(self.mls_backend.key_store().borrow_conn().await?.deref_mut()).await?;
        let ta = x509_cert::Certificate::from_der(&ta.content)?;

        // Parse/decode PEM cert
        let inter_ca = PkiEnvironment::decode_pem_cert(cert_pem).map_err(|e| CryptoError::E2eiError(e.into()))?;

        // the `/federation` endpoint from smallstep repeats the root CA
        // so we filter it out here so that clients don't have to do it
        if inter_ca == ta {
            return Ok(());
        }

        let (ski, aki) =
            PkiEnvironment::extract_ski_aki_from_cert(&inter_ca).map_err(|e| CryptoError::E2eiError(e.into()))?;

        let ski_aki_pair = format!("{ski}:{}", aki.unwrap_or_default());

        // Validate it
        pki_env
            .validate_cert_and_revocation(&inter_ca)
            .map_err(|e| CryptoError::E2eiError(e.into()))?;

        // Save DER repr in keystore
        let cert_der = PkiEnvironment::encode_cert_to_der(&inter_ca).map_err(|e| CryptoError::E2eiError(e.into()))?;
        let intermediate_ca = E2eiIntermediateCert {
            content: cert_der,
            ski_aki_pair,
        };
        self.mls_backend.key_store().save(intermediate_ca).await?;

        self.init_pki_env().await?;

        Ok(())
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
    pub async fn e2ei_register_crl(&mut self, crl_dp: String, crl_der: Vec<u8>) -> CryptoResult<CrlRegistration> {
        let Some(pki_env) = self.e2ei_pki_env.as_ref() else {
            return Err(CryptoError::ConsumerError);
        };

        // Parse/decode DER CRL
        let crl = PkiEnvironment::decode_der_crl(crl_der).map_err(|e| CryptoError::E2eiError(e.into()))?;

        // Validate CRL
        pki_env
            .validate_crl(&crl)
            .map_err(|e| CryptoError::E2eiError(e.into()))?;

        let expiration = extract_expiration_from_crl(&crl);

        let ks = self.mls_backend.key_store();

        let dirty = if let Some(existing_crl) = ks.find::<E2eiCrl>(&crl_dp).await.ok().flatten() {
            let old_crl = PkiEnvironment::decode_der_crl(existing_crl.content.clone())
                .map_err(|e| CryptoError::E2eiError(e.into()))?;

            old_crl.tbs_cert_list.revoked_certificates != crl.tbs_cert_list.revoked_certificates
        } else {
            false
        };

        // Save DER repr in keystore
        let crl_data = E2eiCrl {
            content: PkiEnvironment::encode_crl_to_der(&crl).map_err(|e| CryptoError::E2eiError(e.into()))?,
            distribution_point: crl_dp,
        };
        ks.save(crl_data).await?;

        self.init_pki_env().await?;

        Ok(CrlRegistration { expiration, dirty })
    }

    pub(crate) async fn init_pki_env(&mut self) -> CryptoResult<()> {
        self.e2ei_pki_env
            .replace(Self::restore_pki_env(&self.mls_backend).await?);
        Ok(())
    }

    pub(crate) async fn restore_pki_env(backend: &MlsCryptoProvider) -> CryptoResult<PkiEnvironment> {
        let keystore = backend.key_store();
        let mut conn = keystore.borrow_conn().await?;

        let mut trust_roots = vec![];
        if let Ok(ta_raw) = E2eiAcmeCA::find_unique(&mut conn).await {
            trust_roots.push(
                x509_cert::Certificate::from_der(&ta_raw.content)
                    .map(x509_cert::anchor::TrustAnchorChoice::Certificate)?,
            );
        }

        let intermediates = E2eiIntermediateCert::find_all(&mut conn, Default::default())
            .await?
            .into_iter()
            .try_fold(vec![], |mut acc, inter| {
                acc.push(x509_cert::Certificate::from_der(&inter.content)?);
                CryptoResult::Ok(acc)
            })?;

        let crls = E2eiCrl::find_all(&mut conn, Default::default())
            .await?
            .into_iter()
            .try_fold(vec![], |mut acc, crl| {
                acc.push(x509_cert::crl::CertificateList::from_der(&crl.content)?);
                CryptoResult::Ok(acc)
            })?;

        let params = PkiEnvironmentParams {
            trust_roots: &trust_roots,
            intermediates: &intermediates,
            crls: &crls,
            time_of_interest: None,
        };

        PkiEnvironment::init(params).map_err(|e| CryptoError::E2eiError(e.into()))
    }
}
