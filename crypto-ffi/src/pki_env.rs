use std::{fmt, sync::Arc};

use wire_e2e_identity::pki_env;

use crate::{CoreCryptoFfi, CoreCryptoResult, Database};

/// HttpMethod used for PKI hooks.
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

impl From<pki_env::hooks::HttpMethod> for HttpMethod {
    fn from(inner: pki_env::hooks::HttpMethod) -> Self {
        match inner {
            pki_env::hooks::HttpMethod::Get => Self::Get,
            pki_env::hooks::HttpMethod::Post => Self::Post,
            pki_env::hooks::HttpMethod::Put => Self::Put,
            pki_env::hooks::HttpMethod::Delete => Self::Delete,
            pki_env::hooks::HttpMethod::Patch => Self::Patch,
            pki_env::hooks::HttpMethod::Head => Self::Head,
        }
    }
}

/// An HttpHeader used for PKI hooks.
#[derive(uniffi::Record)]
pub struct HttpHeader {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
}

impl From<pki_env::hooks::HttpHeader> for HttpHeader {
    fn from(inner: pki_env::hooks::HttpHeader) -> Self {
        Self {
            name: inner.name,
            value: inner.value,
        }
    }
}

impl From<HttpHeader> for pki_env::hooks::HttpHeader {
    fn from(ffi: HttpHeader) -> Self {
        Self {
            name: ffi.name,
            value: ffi.value,
        }
    }
}

/// An HttpResponse used for PKI hooks.
#[derive(uniffi::Record)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: u16,
    /// List of header fields
    pub headers: Vec<HttpHeader>,
    /// HTTP body
    pub body: Vec<u8>,
}

impl From<HttpResponse> for pki_env::hooks::HttpResponse {
    fn from(ffi: HttpResponse) -> Self {
        Self {
            status: ffi.status,
            headers: ffi.headers.into_iter().map(Into::into).collect(),
            body: ffi.body,
        }
    }
}

/// An error returned by a `PkiEnvironmentHooks` callback implementation.
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum PkiEnvironmentHooksError {
    /// An error with the given reason string.
    #[error("reason: {reason}")]
    Error { reason: String },
}

// Convert to a "flat" struct in another module
impl From<PkiEnvironmentHooksError> for pki_env::hooks::PkiEnvironmentHooksError {
    fn from(err: PkiEnvironmentHooksError) -> Self {
        match err {
            PkiEnvironmentHooksError::Error { reason } => pki_env::hooks::PkiEnvironmentHooksError { reason },
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PkiEnvironmentHooksError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        PkiEnvironmentHooksError::Error { reason: value.reason }
    }
}

/// Callbacks for external calls made by CoreCrypto during X509 credential acquisition.
///
/// When communicating with the Identity Provider (IDP) and Wire server,
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
#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
pub trait PkiEnvironmentHooks: Send + Sync {
    /// Make an HTTP request.
    ///
    /// Used for requests to ACME servers, CRL distributors, etc.
    async fn http_request(
        &self,
        method: HttpMethod,
        url: String,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> Result<HttpResponse, PkiEnvironmentHooksError>;

    /// Authenticate with the user's identity provider (IdP)
    ///
    /// The implementation should perform authentication using the authorization code flow
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

    /// Get a nonce from the backend.
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

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl pki_env::hooks::PkiEnvironmentHooks for PkiEnvironmentHooksShim {
    async fn http_request(
        &self,
        method: pki_env::hooks::HttpMethod,
        url: String,
        headers: Vec<pki_env::hooks::HttpHeader>,
        body: Vec<u8>,
    ) -> Result<pki_env::hooks::HttpResponse, pki_env::hooks::PkiEnvironmentHooksError> {
        let headers = headers.into_iter().map(Into::into).collect();
        self.0
            .http_request(method.into(), url, headers, body)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    async fn authenticate(
        &self,
        idp: String,
        key_auth: String,
        acme_aud: String,
    ) -> Result<String, pki_env::hooks::PkiEnvironmentHooksError> {
        self.0.authenticate(idp, key_auth, acme_aud).await.map_err(Into::into)
    }

    async fn get_backend_nonce(&self) -> Result<String, pki_env::hooks::PkiEnvironmentHooksError> {
        self.0.get_backend_nonce().await.map_err(Into::into)
    }

    async fn fetch_backend_access_token(
        &self,
        dpop: String,
    ) -> Result<String, pki_env::hooks::PkiEnvironmentHooksError> {
        self.0.fetch_backend_access_token(dpop).await.map_err(Into::into)
    }
}

/// The PKI environment used for certificate management during X509 credential acquisition.
#[derive(derive_more::Into, uniffi::Object)]
pub struct PkiEnvironment(Arc<wire_e2e_identity::pki_env::PkiEnvironment>);

#[cfg_attr(feature = "wasm", uniffi::export)]
impl PkiEnvironment {
    /// Create a new PKI environment.
    #[cfg_attr(feature = "wasm", uniffi::constructor)]
    pub async fn new(hooks: Arc<dyn PkiEnvironmentHooks>, database: Arc<Database>) -> CoreCryptoResult<Self> {
        let shim = Arc::new(PkiEnvironmentHooksShim::new(hooks));
        let pki_env = wire_e2e_identity::pki_env::PkiEnvironment::new(shim, database.as_ref().clone().into()).await?;
        Ok(Self(Arc::new(pki_env)))
    }
}

/// Create a new PKI environment.
#[cfg(not(any(feature = "wasm", target_os = "unknown")))]
#[uniffi::export]
pub async fn create_pki_environment(
    hooks: Arc<dyn PkiEnvironmentHooks>,
    database: Arc<Database>,
) -> CoreCryptoResult<PkiEnvironment> {
    PkiEnvironment::new(hooks, database).await
}

#[uniffi::export]
impl CoreCryptoFfi {
    /// Set the PKI environment of the CoreCrypto instance.
    pub async fn set_pki_environment(&self, pki_environment: Option<Arc<PkiEnvironment>>) {
        self.inner
            .set_pki_environment(pki_environment.map(|env| env.0.clone()))
            .await;
    }

    /// Get the PKI environment of the CoreCrypto instance.
    ///
    /// Returns null if it is not set.
    pub async fn get_pki_environment(&self) -> Option<Arc<PkiEnvironment>> {
        let pki_env = self.inner.get_pki_environment();
        (*pki_env.read().await)
            .as_ref()
            .map(|env| Arc::new(PkiEnvironment(env.clone())))
    }
}
