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

impl From<core_crypto::e2e_identity::pki_env_hooks::HttpMethod> for HttpMethod {
    fn from(inner: core_crypto::e2e_identity::pki_env_hooks::HttpMethod) -> Self {
        match inner {
            core_crypto::e2e_identity::pki_env_hooks::HttpMethod::Get => Self::Get,
            core_crypto::e2e_identity::pki_env_hooks::HttpMethod::Post => Self::Post,
            core_crypto::e2e_identity::pki_env_hooks::HttpMethod::Put => Self::Put,
            core_crypto::e2e_identity::pki_env_hooks::HttpMethod::Delete => Self::Delete,
            core_crypto::e2e_identity::pki_env_hooks::HttpMethod::Patch => Self::Patch,
            core_crypto::e2e_identity::pki_env_hooks::HttpMethod::Head => Self::Head,
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

impl From<core_crypto::e2e_identity::pki_env_hooks::HttpHeader> for HttpHeader {
    fn from(inner: core_crypto::e2e_identity::pki_env_hooks::HttpHeader) -> Self {
        Self {
            name: inner.name,
            value: inner.value,
        }
    }
}

impl From<HttpHeader> for core_crypto::e2e_identity::pki_env_hooks::HttpHeader {
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

impl From<HttpResponse> for core_crypto::e2e_identity::pki_env_hooks::HttpResponse {
    fn from(ffi: HttpResponse) -> Self {
        Self {
            status: ffi.status,
            headers: ffi.headers.into_iter().map(Into::into).collect(),
            body: ffi.body,
        }
    }
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum PkiEnvironmentHooksError {
    #[error("reason: {reason}")]
    Error { reason: String },
}

// Convert to a "flat" struct in another module
impl From<PkiEnvironmentHooksError> for core_crypto::e2e_identity::pki_env_hooks::PkiEnvironmentHooksError {
    fn from(err: PkiEnvironmentHooksError) -> Self {
        match err {
            PkiEnvironmentHooksError::Error { reason } => {
                core_crypto::e2e_identity::pki_env_hooks::PkiEnvironmentHooksError { reason }
            }
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PkiEnvironmentHooksError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        PkiEnvironmentHooksError::Error { reason: value.reason }
    }
}

/// The PKI Environment Hooks used for external calls during e2e enrollment flow.
/// When communicating with the Identity Provider (IDP)  and Wire server,
/// CoreCrypto delegates to the client app by calling the relevant methods.
///
/// Client App                 CoreCrypto                     Acme                     IDP
///    |                           |                          |                        |
///    | X509CredentialAcquisition().finalize()               |                        |
///    |-------------------------->|                          |                        |
///    |                           | GET acme/root.pem        |                        |
///    |                           |------------------------> |                        |
///    |                           | 200 OK                   |                        |
///    |                           |<------------------------ |                        |
///    | authenticate()            |                          |                        |
///    |<--------------------------|                          |                        |
///    |                           | Authentication flow      |                        |
///    | ----------------------------------------------------------------------------> |
///    |<----------------------------------------------------------------------------- |
///    | return Success [PKiEnvironmentHooks.authenticate()]  |                        |
///    |<--------------------------|                          |                        |
///    |                           |  (excluded several calls for brevity)             |
///    | return Success(Credential) [X509CredentialAcquisition().finalize()]           |
///    |<--------------------------|                          |                        |
#[uniffi::export(with_foreign)]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait PkiEnvironmentHooks: Send + Sync {
    /// Make an HTTP request
    /// Used for requests to ACME servers, CRL distributors etc.
    async fn http_request(
        &self,
        method: HttpMethod,
        url: String,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> HttpResponse;

    /// Authenticate with the user's identity provider (IdP)
    ///
    /// The implementation should perform an [authentication using the authorization code flow]
    /// (<https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth>) with the PKCE
    /// (<https://www.rfc-editor.org/rfc/rfc7636>) extension. As part of the authorization
    /// request, the implementation should specify `key_auth` and `acme_aud` claims, along with
    /// their values, in the `claims` parameter. This is to instruct the IdP to add the `key_auth`
    /// and `acme_aud` claims to the ID token that will be returned as part of the access token.
    ///
    /// Once the authentication is completed successfully, the implementation should request
    /// an access token from the IdP, extract the ID token from it and return it to the caller.
    async fn authenticate(
        &self,
        idp: String,
        key_auth: String,
        acme_aud: String,
    ) -> Result<String, PkiEnvironmentHooksError>;

    /// Get a nonce from the backend
    async fn get_backend_nonce(&self) -> Result<String, PkiEnvironmentHooksError>;

    /// Fetch an access token to be used for the DPoP challenge (`wire-dpop-01`)
    ///
    /// The implementation should take the provided DPoP token (`dpop`) and make a request to the
    /// backend to obtain an access token, which should be returned to the caller.
    async fn fetch_backend_access_token(&self, dpop: String) -> Result<String, PkiEnvironmentHooksError>;
}

#[derive(derive_more::Constructor)]
struct PkiEnvironmentHooksShim(Arc<dyn PkiEnvironmentHooks>);

impl std::fmt::Debug for PkiEnvironmentHooksShim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PkiEnvironmentHooksShim")
            .field(&fmt::from_fn(|f| write!(f, "{:p}", Arc::as_ptr(&self.0))))
            .finish()
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl core_crypto::e2e_identity::pki_env_hooks::PkiEnvironmentHooks for PkiEnvironmentHooksShim {
    async fn http_request(
        &self,
        method: core_crypto::e2e_identity::pki_env_hooks::HttpMethod,
        url: String,
        headers: Vec<core_crypto::e2e_identity::pki_env_hooks::HttpHeader>,
        body: Vec<u8>,
    ) -> core_crypto::e2e_identity::pki_env_hooks::HttpResponse {
        let headers = headers.into_iter().map(Into::into).collect();
        self.0.http_request(method.into(), url, headers, body).await.into()
    }

    async fn authenticate(
        &self,
        idp: String,
        key_auth: String,
        acme_aud: String,
    ) -> Result<String, core_crypto::e2e_identity::pki_env_hooks::PkiEnvironmentHooksError> {
        self.0.authenticate(idp, key_auth, acme_aud).await.map_err(Into::into)
    }

    async fn get_backend_nonce(
        &self,
    ) -> Result<String, core_crypto::e2e_identity::pki_env_hooks::PkiEnvironmentHooksError> {
        self.0.get_backend_nonce().await.map_err(Into::into)
    }

    async fn fetch_backend_access_token(
        &self,
        dpop: String,
    ) -> Result<String, core_crypto::e2e_identity::pki_env_hooks::PkiEnvironmentHooksError> {
        self.0.fetch_backend_access_token(dpop).await.map_err(Into::into)
    }
}

/// A PkiEnvironment
#[derive(derive_more::From, derive_more::Into, Clone, uniffi::Object)]
pub struct PkiEnvironment(core_crypto::e2e_identity::pki_env::PkiEnvironment);

impl PkiEnvironment {
    async fn new(hooks: Arc<dyn PkiEnvironmentHooks>, database: Arc<Database>) -> CoreCryptoResult<Self> {
        let shim = Arc::new(PkiEnvironmentHooksShim::new(hooks));
        let pki_env =
            core_crypto::e2e_identity::pki_env::PkiEnvironment::new(shim, database.as_ref().clone().into()).await?;
        Ok(pki_env.into())
    }
}

/// Create a new PKI environment
#[uniffi::export]
pub async fn create_pki_environment(
    hooks: Arc<dyn PkiEnvironmentHooks>,
    database: Arc<Database>,
) -> CoreCryptoResult<PkiEnvironment> {
    PkiEnvironment::new(hooks, database).await
}

#[uniffi::export]
impl CoreCryptoFfi {
    /// Set the Pki Environment of the CoreCrypto instance
    pub async fn set_pki_environment(&self, pki_environment: Option<Arc<PkiEnvironment>>) -> CoreCryptoResult<()> {
        let pki_environment = pki_environment.as_ref().map(|p| p.as_ref().clone()).map(Into::into);
        self.inner
            .set_pki_environment(pki_environment)
            .await
            .map_err(Into::into)
    }

    /// Get the PKI environment of the CoreCrypto instance
    /// Returns null if it is not set.
    pub async fn get_pki_environment(&self) -> Option<Arc<PkiEnvironment>> {
        self.inner.get_pki_environment().await.map(PkiEnvironment).map(Arc::new)
    }
}
