use super::{Error, Result};
use crate::{context::CentralContext, e2e_identity::CrlRegistration, prelude::MlsCentral, RecursiveError};
use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
};
use openmls_traits::OpenMlsCryptoProvider;
use std::collections::HashSet;
use wire_e2e_identity::prelude::x509::{
    extract_crl_uris, extract_expiration_from_crl,
    revocation::{PkiEnvironment, PkiEnvironmentParams},
};
use x509_cert::der::{pem::LineEnding, Decode, EncodePem};

#[derive(Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, derive_more::DerefMut)]
pub struct NewCrlDistributionPoint(Option<HashSet<String>>);

impl From<NewCrlDistributionPoint> for Option<Vec<String>> {
    fn from(mut dp: NewCrlDistributionPoint) -> Self {
        dp.take().map(|d| d.into_iter().collect())
    }
}

#[derive(Debug, Clone)]
/// Dump of the PKI environemnt as PEM
pub struct E2eiDumpedPkiEnv {
    /// Root CA in use (i.e. Trust Anchor)
    pub root_ca: String,
    /// Intermediate CAs that are loaded
    pub intermediates: Vec<String>,
    /// CRLs registered in the PKI env
    pub crls: Vec<String>,
}

impl CentralContext {
    /// See [MlsCentral::e2ei_is_pki_env_setup].
    /// Unlike [MlsCentral::e2ei_is_pki_env_setup], this function returns a result.
    pub async fn e2ei_is_pki_env_setup(&self) -> Result<bool> {
        Ok(self
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))?
            .authentication_service()
            .is_env_setup()
            .await)
    }

    /// See [MlsCentral::e2ei_dump_pki_env].
    pub async fn e2ei_dump_pki_env(&self) -> Result<Option<E2eiDumpedPkiEnv>> {
        if !self.e2ei_is_pki_env_setup().await? {
            return Ok(None);
        }
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))?;
        let Some(pki_env) = &*mls_provider.authentication_service().borrow().await else {
            return Ok(None);
        };
        E2eiDumpedPkiEnv::from_pki_env(pki_env).await
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
                .map_err(RecursiveError::root("getting mls provider"))?
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
            .map_err(RecursiveError::root("getting mls provider"))?
            .keystore()
            .save(acme_ca)
            .await?;

        // To do that, tear down and recreate the pki env
        self.init_pki_env().await?;

        Ok(())
    }

    pub(crate) async fn init_pki_env(&self) -> Result<()> {
        if let Some(pki_env) = restore_pki_env(
            &self
                .mls_provider()
                .await
                .map_err(RecursiveError::root("getting mls provider"))?
                .keystore(),
        )
        .await?
        {
            let provider = self
                .mls_provider()
                .await
                .map_err(RecursiveError::root("getting mls provider"))?;
            provider.authentication_service().update_env(pki_env).await?;
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
    pub async fn e2ei_register_intermediate_ca_pem(&self, cert_pem: String) -> Result<NewCrlDistributionPoint> {
        // Parse/decode PEM cert
        let inter_ca = PkiEnvironment::decode_pem_cert(cert_pem)?;
        self.e2ei_register_intermediate_ca(inter_ca).await
    }

    pub(crate) async fn e2ei_register_intermediate_ca_der(&self, cert_der: &[u8]) -> Result<NewCrlDistributionPoint> {
        let inter_ca = x509_cert::Certificate::from_der(cert_der)?;
        self.e2ei_register_intermediate_ca(inter_ca).await
    }

    async fn e2ei_register_intermediate_ca(&self, inter_ca: x509_cert::Certificate) -> Result<NewCrlDistributionPoint> {
        // TrustAnchor must have been registered at this point
        let keystore = self
            .keystore()
            .await
            .map_err(RecursiveError::root("getting keystore"))?;
        let trust_anchor = keystore.find_unique::<E2eiAcmeCA>().await?;
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
                .map_err(RecursiveError::root("getting mls provider"))?;
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
        keystore.save(intermediate_ca).await?;

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
                .map_err(RecursiveError::root("getting mls provider"))?;
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
            .map_err(RecursiveError::root("getting keystore"))?;

        let dirty = if let Some(existing_crl) = ks.find::<E2eiCrl>(crl_dp.as_bytes()).await.ok().flatten() {
            let old_crl = PkiEnvironment::decode_der_crl(existing_crl.content.clone())?;

            old_crl.tbs_cert_list.revoked_certificates != crl.tbs_cert_list.revoked_certificates
        } else {
            false
        };

        // Save DER repr in keystore
        let crl_data = E2eiCrl {
            content: PkiEnvironment::encode_crl_to_der(&crl)?,
            distribution_point: crl_dp,
        };
        ks.save(crl_data).await?;

        self.init_pki_env().await?;

        Ok(CrlRegistration { expiration, dirty })
    }
}

impl MlsCentral {
    /// Returns whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs)
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.mls_backend.is_pki_env_setup().await
    }

    /// Dumps the PKI environment as PEM
    pub async fn e2ei_dump_pki_env(&self) -> Result<Option<E2eiDumpedPkiEnv>> {
        if !self.e2ei_is_pki_env_setup().await {
            return Ok(None);
        }
        let pki_env_lock = self.mls_backend.authentication_service().borrow().await;
        let Some(pki_env) = &*pki_env_lock else {
            return Ok(None);
        };
        E2eiDumpedPkiEnv::from_pki_env(pki_env).await
    }
}

impl E2eiDumpedPkiEnv {
    async fn from_pki_env(pki_env: &PkiEnvironment) -> Result<Option<E2eiDumpedPkiEnv>> {
        let Some(root) = pki_env
            .get_trust_anchors()
            .map_err(Error::certificate_validation("getting pki trust anchors"))?
            .pop()
        else {
            return Ok(None);
        };

        let x509_cert::anchor::TrustAnchorChoice::Certificate(root) = &root.decoded_ta else {
            return Ok(None);
        };

        let root_ca = root.to_pem(LineEnding::LF)?;

        let inner_intermediates = pki_env
            .get_intermediates()
            .map_err(Error::certificate_validation("getting pki intermediates"))?;

        let mut intermediates = Vec::with_capacity(inner_intermediates.len());

        for inter in inner_intermediates {
            let pem_inter = inter.decoded_cert.to_pem(LineEnding::LF)?;
            intermediates.push(pem_inter);
        }

        let inner_crls: Vec<Vec<u8>> = pki_env
            .get_all_crls()
            .map_err(Error::certificate_validation("getting all crls"))?;

        let mut crls = Vec::with_capacity(inner_crls.len());
        for crl in inner_crls.into_iter() {
            let crl_pem = x509_cert::der::pem::encode_string("X509 CRL", LineEnding::LF, &crl)
                .map_err(Error::certificate_validation("encoding crl title to pem"))?;
            crls.push(crl_pem);
        }

        Ok(Some(E2eiDumpedPkiEnv {
            root_ca,
            intermediates,
            crls,
        }))
    }
}

pub(crate) async fn restore_pki_env(data_provider: &impl FetchFromDatabase) -> Result<Option<PkiEnvironment>> {
    let mut trust_roots = vec![];
    let Ok(ta_raw) = data_provider.find_unique::<E2eiAcmeCA>().await else {
        return Ok(None);
    };

    trust_roots.push(
        x509_cert::Certificate::from_der(&ta_raw.content).map(x509_cert::anchor::TrustAnchorChoice::Certificate)?,
    );

    let intermediates = data_provider
        .find_all::<E2eiIntermediateCert>(Default::default())
        .await?
        .into_iter()
        .map(|inter| x509_cert::Certificate::from_der(&inter.content))
        .collect::<Result<Vec<_>, _>>()?;

    let crls = data_provider
        .find_all::<E2eiCrl>(Default::default())
        .await?
        .into_iter()
        .map(|crl| x509_cert::crl::CertificateList::from_der(&crl.content))
        .collect::<Result<Vec<_>, _>>()?;

    let params = PkiEnvironmentParams {
        trust_roots: &trust_roots,
        intermediates: &intermediates,
        crls: &crls,
        time_of_interest: None,
    };

    Ok(Some(PkiEnvironment::init(params)?))
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;
    use x509_cert::der::pem::LineEnding;
    use x509_cert::der::EncodePem;

    use crate::test_utils::*;

    use super::super::Error;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn register_acme_ca_should_fail_when_already_set(case: TestCase) {
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
                let ClientContext {
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
