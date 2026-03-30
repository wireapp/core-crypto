#![allow(dead_code)]
use std::net::SocketAddr;

use rusty_jwt_tools::prelude::ClientId;
use scraper::Html;

use crate::utils::idp::IdpServer;

#[cfg(not(target_os = "unknown"))]
pub(crate) mod ctx;
#[cfg(not(target_os = "unknown"))]
pub(crate) mod hooks;
#[cfg(not(target_os = "unknown"))]
pub(crate) mod idp;
#[cfg(not(target_os = "unknown"))]
pub(crate) mod stepca;

/// Container network name.
pub(crate) const NETWORK: &str = "wire";

/// Container shared memory size in bytes. By default Docker allocates 64MB.
pub(crate) const SHM: u64 = 8 * 1000 * 1000; // 8MB

pub(crate) fn rand_str(size: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), size)
}

pub(crate) fn rand_base64_str(size: usize) -> String {
    use base64::Engine as _;
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(rand_str(size))
}

pub(crate) fn rand_client_id(device_id: Option<u64>) -> ClientId {
    let device_id = device_id.unwrap_or_else(rand::random::<u64>);
    ClientId::try_from_raw_parts(
        uuid::Uuid::new_v4().as_ref(),
        device_id,
        format!("{}.com", rand_str(6)).as_bytes(),
    )
    .unwrap()
}

pub(crate) fn scrap_login(html: String) -> String {
    let html = Html::parse_document(&html);
    let selector = scraper::Selector::parse("form").unwrap();
    let form = html.select(&selector).find(|_| true).unwrap();
    form.value().attr("action").unwrap().to_string()
}

pub(crate) fn default_http_client() -> reqwest::ClientBuilder {
    let timeout = core::time::Duration::from_secs(5);
    reqwest::ClientBuilder::new()
        .timeout(timeout)
        .connect_timeout(timeout)
        .connection_verbose(true)
        .danger_accept_invalid_certs(true)
}

#[derive(Debug, Clone)]
pub(crate) struct OauthCfg {
    pub client_id: String,
    pub redirect_uri: String,
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
