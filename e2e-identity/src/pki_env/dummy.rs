use std::sync::Arc;

use core_crypto_keystore::Database;

use super::{
    PkiEnvironment,
    hooks::{HttpHeader, HttpMethod, HttpResponse, PkiEnvironmentHooks, PkiEnvironmentHooksError},
};

#[derive(Debug, Default)]
struct DummyPkiEnvironmentHooks;

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl PkiEnvironmentHooks for DummyPkiEnvironmentHooks {
    async fn http_request(
        &self,
        _method: HttpMethod,
        _url: String,
        _headers: Vec<HttpHeader>,
        _body: Vec<u8>,
    ) -> Result<HttpResponse, PkiEnvironmentHooksError> {
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        })
    }

    async fn authenticate(
        &self,
        _idp: String,
        _key_auth: String,
        _acme_aud: String,
        _acquisition_snapshot: Vec<u8>,
    ) -> Result<String, PkiEnvironmentHooksError> {
        Ok("dummy-id-token".to_string())
    }

    async fn get_backend_nonce(&self) -> Result<String, PkiEnvironmentHooksError> {
        Ok("dummy-backend-nonce".to_string())
    }

    async fn fetch_backend_access_token(&self, _dpop: String) -> Result<String, PkiEnvironmentHooksError> {
        Ok("dummy-backend-token".to_string())
    }
}

impl PkiEnvironment {
    pub async fn with_dummy_hooks(database: Database) -> Result<PkiEnvironment, super::Error> {
        Self::new(Arc::new(DummyPkiEnvironmentHooks), database).await
    }
}
