use std::{fmt, sync::Arc};

use crate::{CoreCryptoFfi, CoreCryptoResult, Database};

/// HttpMethod used for pki hooks
#[derive(uniffi::Enum)]
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

impl From<core_crypto::e2e_identity::pki_env::HttpMethod> for HttpMethod {
    fn from(inner: core_crypto::e2e_identity::pki_env::HttpMethod) -> Self {
        match inner {
            core_crypto::e2e_identity::pki_env::HttpMethod::Get => Self::Get,
            core_crypto::e2e_identity::pki_env::HttpMethod::Post => Self::Post,
            core_crypto::e2e_identity::pki_env::HttpMethod::Put => Self::Put,
            core_crypto::e2e_identity::pki_env::HttpMethod::Delete => Self::Delete,
            core_crypto::e2e_identity::pki_env::HttpMethod::Patch => Self::Patch,
            core_crypto::e2e_identity::pki_env::HttpMethod::Head => Self::Head,
        }
    }
}

/// An HttpHeader used for pki hooks
#[derive(uniffi::Record)]
pub struct HttpHeader {
    /// header name
    pub name: String,
    /// header value
    pub value: String,
}

impl From<core_crypto::e2e_identity::pki_env::HttpHeader> for HttpHeader {
    fn from(inner: core_crypto::e2e_identity::pki_env::HttpHeader) -> Self {
        Self {
            name: inner.name,
            value: inner.value,
        }
    }
}

impl From<HttpHeader> for core_crypto::e2e_identity::pki_env::HttpHeader {
    fn from(ffi: HttpHeader) -> Self {
        Self {
            name: ffi.name,
            value: ffi.value,
        }
    }
}

/// An HttpResponse used for pki hooks
#[derive(uniffi::Record)]
pub struct HttpResponse {
    /// http status code
    pub status: u16,
    /// List of header fields
    pub headers: Vec<HttpHeader>,
    /// http body
    pub body: Vec<u8>,
}

impl From<HttpResponse> for core_crypto::e2e_identity::pki_env::HttpResponse {
    fn from(ffi: HttpResponse) -> Self {
        Self {
            status: ffi.status,
            headers: ffi.headers.into_iter().map(Into::into).collect(),
            body: ffi.body,
        }
    }
}

/// An OAuthResponse used for pki hooks
#[derive(uniffi::Record)]
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

impl From<OAuthResponse> for core_crypto::e2e_identity::pki_env::OAuthResponse {
    fn from(ffi: OAuthResponse) -> Self {
        Self {
            access_token: ffi.access_token,
            id_token: ffi.id_token,
            token_type: ffi.token_type,
            expires_in: ffi.expires_in,
            scope: ffi.scope,
            refresh_token: ffi.refresh_token,
        }
    }
}

/// Callbacks that CoreCrypto uses during E2e flow.
#[uniffi::export(with_foreign)]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait PkiEnvironmentHooks: Send + Sync {
    /// Used for making HTTP requests to ACME servers, CRL distributors etc.
    async fn http_request(
        &self,
        method: HttpMethod,
        url: String,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> HttpResponse;

    /// only used to authenticate with the user's identity provider
    async fn authenticate(&self, idp: String, key_auth: String, acme_aud: String) -> OAuthResponse;

    /// this one is only used for DPoP challenge
    async fn fetch_backend_access_token(&self, dpop: String) -> String;
}

#[derive(derive_more::Constructor)]
struct PkiEnvironmentHooksShim(Arc<dyn PkiEnvironmentHooks>);

impl std::fmt::Debug for PkiEnvironmentHooksShim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PkiEnvironmentHooksShim")
            .field(&"Arc<dyn PkiEnvironmentHooks>")
            .finish()
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl core_crypto::e2e_identity::pki_env::PkiEnvironmentHooks for PkiEnvironmentHooksShim {
    async fn http_request(
        &self,
        method: core_crypto::e2e_identity::pki_env::HttpMethod,
        url: String,
        headers: Vec<core_crypto::e2e_identity::pki_env::HttpHeader>,
        body: Vec<u8>,
    ) -> core_crypto::e2e_identity::pki_env::HttpResponse {
        let headers = headers.into_iter().map(Into::into).collect();
        self.0.http_request(method.into(), url, headers, body).await.into()
    }

    async fn authenticate(
        &self,
        idp: String,
        key_auth: String,
        acme_aud: String,
    ) -> core_crypto::e2e_identity::pki_env::OAuthResponse {
        self.0.authenticate(idp, key_auth, acme_aud).await.into()
    }

    async fn fetch_backend_access_token(&self, dpop: String) -> String {
        self.0.fetch_backend_access_token(dpop).await
    }
}

#[derive(derive_more::Into, Clone, uniffi::Object)]
pub struct PkiEnvironment(core_crypto::e2e_identity::pki_env::PkiEnvironment);

#[uniffi::export]
impl CoreCryptoFfi {
    /// Set the Pki Environment of the CoreCrypto instance
    pub async fn set_pki_environment(&self, pki_environment: &Arc<PkiEnvironment>) -> CoreCryptoResult<()> {
        self.inner
            .set_pki_environment(pki_environment.as_ref().clone().into())
            .await
            .map_err(Into::into)
    }

    /// Get the Pki Environment of the CoreCrypto instance
    /// Returns null if it is not set.
    pub async fn get_pki_environment(&self) -> Option<Arc<PkiEnvironment>> {
        self.inner.get_pki_environment().await.map(PkiEnvironment).map(Arc::new)
    }
}
