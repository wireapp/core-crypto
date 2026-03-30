use std::net::SocketAddr;

use scraper::Html;

use crate::utils::idp::IdpServer;

pub(crate) fn scrap_login(html: String) -> String {
    let html = Html::parse_document(&html);
    let selector = scraper::Selector::parse("form").unwrap();
    let form = html.select(&selector).find(|_| true).unwrap();
    form.value().attr("action").unwrap().to_string()
}

#[derive(Debug, Clone)]
pub(crate) struct OauthCfg {
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct OidcCfg {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: String,
    pub issuer_uri: Option<String>,
}

impl OidcCfg {
    pub(crate) fn set_issuer_uri(&mut self, base: &str) {
        let issuer_uri = url::Url::parse(&self.issuer).unwrap();
        let issuer_uri = format!("{base}{}", issuer_uri.path());
        self.issuer_uri = Some(issuer_uri)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WireServer {
    pub hostname: String,
    pub addr: SocketAddr,
}

impl WireServer {
    pub(crate) fn uri(&self) -> String {
        format!("http://{}:{}", self.hostname, self.addr.port())
    }

    /// Returns the Wire server-owned URI which the IdP server is supposed to redirect
    /// the user to after successful authentication.
    pub(crate) fn oauth_redirect_uri(&self) -> String {
        format!("http://{}:{}/callback", self.hostname, self.addr.port())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TestEnvironment {
    pub wire_server: WireServer,
    pub idp_server: IdpServer,
}

pub(crate) fn default_http_client() -> reqwest::ClientBuilder {
    let timeout = core::time::Duration::from_secs(5);
    reqwest::ClientBuilder::new()
        .timeout(timeout)
        .connect_timeout(timeout)
        .connection_verbose(true)
        .danger_accept_invalid_certs(true)
}
