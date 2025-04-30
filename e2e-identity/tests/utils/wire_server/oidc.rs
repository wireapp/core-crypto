use crate::utils::{ctx::*, wire_server::OauthCfg};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use openidconnect::{
    ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use scraper::Html;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct Oidc {
    name: String,
    handle: String,
    keyauth: String,
}

pub async fn handle_login(_req: Request<Incoming>) -> http::Result<Response<Full<Bytes>>> {
    let OauthCfg {
        issuer_uri,
        client_id,
        client_secret,
        redirect_uri,
    } = OauthCfg::cxt_get();

    let issuer_url = IssuerUrl::new(issuer_uri.clone()).unwrap();
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), move |r| {
        custom_oauth_client("discovery", ctx_get_http_client(), r)
    })
    .await
    .unwrap();

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        openidconnect::ClientId::new(client_id.clone()),
        Some(ClientSecret::new(client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.clone()).unwrap());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    ctx_store("pkce-verifier", pkce_verifier.secret());
    ctx_store("pkce-challenge", pkce_challenge.as_str());

    let (auth_url, ..) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header("location", auth_url.as_str())
        .body(Default::default())
}

pub fn scrap_login(html: String) -> String {
    let html = Html::parse_document(&html);
    let selector = scraper::Selector::parse("form").unwrap();
    let form = html.select(&selector).find(|_| true).unwrap();
    form.value().attr("action").unwrap().to_string()
}

pub fn scrap_grant(html: String) -> String {
    let html = Html::parse_document(&html);
    let selector = scraper::Selector::parse("form").unwrap();
    let form = html.select(&selector).find(|_| true).unwrap();
    form.children()
        .filter_map(|c| c.value().as_element())
        .filter(|c| c.attr("name") == Some("req"))
        .find_map(|e| e.attr("value"))
        .unwrap()
        .to_string()
}

pub async fn handle_callback(req: Request<Incoming>) -> http::Result<Response<Full<Bytes>>> {
    let req_uri = req.uri().clone();
    let req_uri: url::Url = format!("http://localhost{}", req_uri).parse().unwrap();
    let authorization_code = req_uri
        .query_pairs()
        .find_map(|(k, v)| match k.as_ref() {
            "code" => Some(v.to_string()),
            _ => None,
        })
        .unwrap();
    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(authorization_code.into())
        .unwrap();
    Ok(resp)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OidcCfg {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: String,
    pub issuer_uri: Option<String>,
}

impl OidcCfg {
    pub fn set_issuer_uri(&mut self, base: &str) {
        let issuer_uri = url::Url::parse(&self.issuer).unwrap();
        let issuer_uri = format!("{base}{}", issuer_uri.path());
        self.issuer_uri = Some(issuer_uri)
    }
}
