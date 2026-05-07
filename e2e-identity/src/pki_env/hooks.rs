//! PKI Environment API Hooks
use std::fmt;

/// An http method
#[derive(Debug)]
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
#[derive(Debug)]
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

impl HttpResponse {
    /// Deserialize the body of the response into a JSON value.
    pub fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Return the value of the first header with the given name.
    pub fn first_header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find_map(|h| (h.name == name).then(|| h.value.clone()))
    }
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            writeln!(f, "BEGIN HttpResponse")?;
            writeln!(f, "Status: {}", self.status)?;
            for header in &self.headers {
                writeln!(f, "{}: {}", header.name, header.value)?;
            }
            writeln!(f)?;
            match std::str::from_utf8(&self.body) {
                Ok(body) => match serde_json::from_str::<serde_json::Value>(body) {
                    Ok(body) => writeln!(f, "{body:#}")?,
                    Err(_) => writeln!(f, "{body}")?,
                },
                Err(_) => writeln!(f, "{:#?}", self.body)?,
            }
            writeln!(f, "END HttpResponse")
        } else {
            f.debug_struct("HttpResponse")
                .field("status", &self.status)
                .field("headers", &self.headers)
                .field("body", &self.body)
                .finish()
        }
    }
}

/// Error type for PKI environment hooks
#[derive(Debug, thiserror::Error, derive_more::From)]
#[error("reason: {reason}")]
pub struct PkiEnvironmentHooksError {
    /// the error reason
    pub reason: String,
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
///    | return Success [PkiEnvironmentHooks.authenticate()]  |                        |
///    |<--------------------------|                          |                        |
///    |                           |  (excluded several calls for brevity)             |
///    | return Success(Credential) [X509CredentialAcquisition().finalize()]           |
///    |<--------------------------|                          |                        |
#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
pub trait PkiEnvironmentHooks: std::fmt::Debug + Send + Sync {
    /// Make an HTTP request
    /// Used for requests to ACME servers, CRL distributors etc.
    async fn http_request(
        &self,
        method: HttpMethod,
        url: String,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> Result<HttpResponse, PkiEnvironmentHooksError>;

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
        acquisition_snapshot: Vec<u8>,
    ) -> Result<String, PkiEnvironmentHooksError>;

    /// Get a nonce from the backend
    async fn get_backend_nonce(&self) -> Result<String, PkiEnvironmentHooksError>;

    /// Fetch an access token to be used for the DPoP challenge (`wire-dpop-01`)
    ///
    /// The implementation should take the provided DPoP token (`dpop`) and make a request to the
    /// backend to obtain an access token, which should be returned to the caller.
    async fn fetch_backend_access_token(&self, dpop: String) -> Result<String, PkiEnvironmentHooksError>;
}
