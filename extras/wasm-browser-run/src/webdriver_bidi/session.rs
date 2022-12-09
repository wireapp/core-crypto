use crate::webdriver_bidi::browsing_context::BrowsingContext;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum ProxyCapabilityType {
    Pac,
    Direct,
    AutoDetect,
    System,
    Manual,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyCapability {
    pub proxy_type: Option<ProxyCapabilityType>,
    pub proxy_autoconfig_url: Option<String>,
    pub ftp_proxy: Option<String>,
    pub http_proxy: Option<String>,
    pub ssl_proxy: Option<String>,
    pub socks_proxy: Option<String>,
    pub socks_version: Option<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct SessionCapabilityRequest {
    pub accept_insecure_certs: Option<bool>,
    pub browser_name: Option<String>,
    pub browser_version: Option<String>,
    pub platform_name: Option<String>,
    pub proxy: Option<ProxyCapability>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionCapabilitiesRequest {
    pub always_match: Option<SessionCapabilityRequest>,
    pub first_match: Option<Vec<SessionCapabilityRequest>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionSubscriptionRequest {
    pub events: Vec<String>,
    pub contexts: Option<Vec<BrowsingContext>>,
}

pub mod commands {
    // pub fn session_status() ->
}
