use std::collections::HashMap;

use base64::Engine as _;
use wire_e2e_identity::pki_env::hooks::{
    HttpHeader, HttpMethod, HttpResponse, PkiEnvironmentHooks, PkiEnvironmentHooksError,
};

use crate::utils::{
    OauthCfg, WireServer,
    ctx::ctx_get_http_client_builder,
    idp::{IdpServer, OidcProvider, fetch_id_token},
    stepca::AcmeServer,
};

#[derive(Debug)]
pub(crate) struct TestPkiEnvironmentHooks {
    pub acme: AcmeServer,
    pub wire_server: WireServer,
    pub idp_server: IdpServer,
    pub device_id: String,
    pub wire_server_context: serde_json::Value,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl PkiEnvironmentHooks for TestPkiEnvironmentHooks {
    async fn http_request(
        &self,
        method: HttpMethod,
        url: String,
        mut headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> Result<HttpResponse, PkiEnvironmentHooksError> {
        let cert = reqwest::tls::Certificate::from_pem(self.acme.ca_cert.to_string().as_ref()).unwrap();
        let client = ctx_get_http_client_builder()
            .add_root_certificate(cert)
            .build()
            .unwrap();
        let headers: HashMap<String, String> = HashMap::from_iter(headers.drain(..).map(|h| (h.name, h.value)));
        let headers = reqwest::header::HeaderMap::try_from(&headers).unwrap();
        let req = match method {
            HttpMethod::Get => client.get(url).headers(headers),
            HttpMethod::Head => client.head(url).headers(headers),
            HttpMethod::Patch => client.patch(url).headers(headers),
            HttpMethod::Post => client.post(url).headers(headers),
            HttpMethod::Put => client.put(url).headers(headers),
            HttpMethod::Delete => client.delete(url).headers(headers),
        };

        let req = req.body(body);
        log::debug!("HTTP request:\n{:#?}", &req);

        let resp = req.send().await.map_err(|err| err.to_string())?;
        let status = resp.status();
        let headers = resp
            .headers()
            .into_iter()
            .map(|(name, value)| HttpHeader {
                name: name.as_str().to_owned(),
                value: value.to_str().unwrap().to_owned(),
            })
            .collect();
        let body = resp.bytes().await.map_err(|err| err.to_string())?.to_vec();

        let response = HttpResponse {
            status: status.into(),
            headers,
            body,
        };

        log::debug!("HTTP response:\n{:#?}", &response);
        Ok(response)
    }

    async fn authenticate(
        &self,
        idp: String,
        key_auth: String,
        acme_aud: String,
    ) -> Result<String, PkiEnvironmentHooksError> {
        let oauth_cfg = OauthCfg {
            client_id: "wireapp".to_string(),
            redirect_uri: self.wire_server.oauth_redirect_uri(),
        };
        let mut oidc_target = idp.clone();

        // TODO: this is a temporary workaround to make sure this works with both Keycloak
        // and Authelia. See the comment about the issuer URL in authelia::fetch_id_token.
        if self.idp_server.provider == OidcProvider::Authelia && !oidc_target.ends_with("/") {
            oidc_target.push('/');
        }
        let oidc_target = url::Url::parse(&oidc_target).unwrap();
        let id_token = fetch_id_token(&self.idp_server, &oauth_cfg, &oidc_target, &key_auth, &acme_aud).await;
        Ok(id_token)
    }

    async fn get_backend_nonce(&self) -> Result<String, PkiEnvironmentHooksError> {
        let url = format!("{}/clients/{}/nonce", self.wire_server.uri(), self.device_id);
        let response = self.http_request(HttpMethod::Get, url, vec![], vec![]).await?;
        Ok(String::from_utf8(response.body).unwrap())
    }

    async fn fetch_backend_access_token(&self, dpop: String) -> Result<String, PkiEnvironmentHooksError> {
        let url = format!("{}/clients/{}/access-token", self.wire_server.uri(), self.device_id);
        let dpop = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&dpop);
        let headers = vec![HttpHeader {
            name: "dpop".into(),
            value: dpop,
        }];
        let body = serde_json::to_vec(&self.wire_server_context).unwrap();
        let response = self.http_request(HttpMethod::Post, url, headers, body).await?;
        let json = String::from_utf8(response.body).unwrap();

        // The real access token is actually the value of the `token` field.
        let access_token = serde_json::from_slice::<serde_json::Value>(json.as_ref()).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        Ok(access_token)
    }
}
