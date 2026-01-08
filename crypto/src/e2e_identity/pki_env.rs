//! PKI Environment API

use std::{collections::HashSet, sync::Arc};

use core_crypto_keystore::{
    connection::Database,
    entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert},
    traits::FetchFromDatabase,
};
use mls_crypto_provider::PkiEnvironmentProvider;
use wire_e2e_identity::prelude::x509::revocation::{PkiEnvironment as RjtPkiEnvironment, PkiEnvironmentParams};
use x509_cert::der::Decode;

use super::Result;
use crate::{KeystoreError, RecursiveError};

/// New Certificate Revocation List distribution points.
#[derive(Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, derive_more::DerefMut)]
pub struct NewCrlDistributionPoints(Option<HashSet<String>>);

impl From<NewCrlDistributionPoints> for Option<Vec<String>> {
    fn from(mut dp: NewCrlDistributionPoints) -> Self {
        dp.take().map(|d| d.into_iter().collect())
    }
}

impl IntoIterator for NewCrlDistributionPoints {
    type Item = String;

    type IntoIter = std::collections::hash_set::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        let items = self.0.unwrap_or_default();
        items.into_iter()
    }
}

pub(crate) async fn restore_pki_env(data_provider: &impl FetchFromDatabase) -> Result<Option<RjtPkiEnvironment>> {
    let mut trust_roots = vec![];
    let Ok(Some(ta_raw)) = data_provider.get_unique::<E2eiAcmeCA>().await else {
        return Ok(None);
    };

    trust_roots.push(
        x509_cert::Certificate::from_der(&ta_raw.content).map(x509_cert::anchor::TrustAnchorChoice::Certificate)?,
    );

    let intermediates = data_provider
        .load_all::<E2eiIntermediateCert>()
        .await
        .map_err(KeystoreError::wrap("finding intermediate certificates"))?
        .into_iter()
        .map(|inter| x509_cert::Certificate::from_der(&inter.content))
        .collect::<Result<Vec<_>, _>>()?;

    let crls = data_provider
        .load_all::<E2eiCrl>()
        .await
        .map_err(KeystoreError::wrap("finding crls"))?
        .into_iter()
        .map(|crl| x509_cert::crl::CertificateList::from_der(&crl.content))
        .collect::<Result<Vec<_>, _>>()?;

    let params = PkiEnvironmentParams {
        trust_roots: &trust_roots,
        intermediates: &intermediates,
        crls: &crls,
        time_of_interest: None,
    };

    Ok(Some(RjtPkiEnvironment::init(params)?))
}

/// The PKI environment which can be initialized independently from a CoreCrypto session.
#[derive(Debug, Clone)]
pub struct PkiEnvironment {
    /// Implemented by the clients and used by us to make external calls during e2e flow
    // TODO: remove this config with further implementation of RFC CC2, as soon as hooks are actually used
    #[allow(dead_code)]
    hooks: Arc<dyn PkiEnvironmentHooks>,
    /// The database in which X509 Credentials are stored. It is unrelated to the CoreCrypto session data base but can
    /// be the same.
    database: Database,
    /// The PkiEnvironmentProvider is the provider used by the MlsCryptoProvider which has to implement
    /// openmls_traits::OpenMlsCryptoProvideropenMls. It therefore has to be shared with the MlsCryptoProvider but
    /// we consider this struct to be the place where it actually belongs to.
    mls_pki_env_provider: PkiEnvironmentProvider,
}

impl PkiEnvironment {
    /// Create a new PKI Environment
    pub async fn new(hooks: Arc<dyn PkiEnvironmentHooks>, database: Database) -> Result<PkiEnvironment> {
        let mls_pki_env_provider = restore_pki_env(&database)
            .await
            .map_err(RecursiveError::e2e_identity("restoring pki env"))?
            .map(PkiEnvironmentProvider::from)
            .unwrap_or_default();
        Ok(Self {
            hooks,
            database,
            mls_pki_env_provider,
        })
    }

    pub fn mls_pki_env_provider(&self) -> PkiEnvironmentProvider {
        self.mls_pki_env_provider.clone()
    }
}

/// An http method
pub enum HttpMethod {
    /// GET
    Get,
    /// POST
    Post,
    /// PUT
    Put,
    /// DELETE
    Delete,
    /// PATCH
    Patch,
    /// HEAD
    Head,
}

/// An http header
pub struct HttpHeader {
    /// header name
    pub name: String,
    /// header value
    pub value: String,
}

/// An HTTP Response
pub struct HttpResponse {
    /// Response status code
    pub status: u16,
    /// Response Header
    pub headers: Vec<HttpHeader>,
    /// Response Body
    pub body: Vec<u8>,
}

/// An OAuthResponse
pub struct OAuthResponse {
    /// OAuth Access Token
    pub access_token: String,
    /// OAuth Id Token
    pub id_token: Option<String>,
    /// The Token Type
    pub token_type: Option<String>,
    /// Expiration
    pub expires_in: Option<u64>,
    /// OAuth Scope
    pub scope: Option<String>,
    /// OAuth Refresh Token
    pub refresh_token: Option<String>,
}

/// The PKI Environment Hooks used for external calls during e2e enrollment flow.
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait PkiEnvironmentHooks: std::fmt::Debug + Send + Sync {
    /// Used for making HTTP requests to ACME servers, CRL distributors etc.
    async fn http_request(
        &self,
        method: HttpMethod,
        url: String,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> HttpResponse;

    /// Only used to authenticate with the user's identity provider
    async fn authenticate(&self, idp: String, key_auth: String, acme_aud: String) -> OAuthResponse;

    /// Only used for DPoP challenge
    async fn fetch_backend_access_token(&self, dpop: String) -> String;
}
