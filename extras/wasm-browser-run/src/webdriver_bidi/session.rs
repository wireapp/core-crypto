use crate::webdriver_bidi::browsing_context::BrowsingContext;

#[derive(Debug, Clone, Copy)]
pub enum ProxyCapabilityType {
    Pac,
    Direct,
    AutoDetect,
    System,
    Manual,
}

#[derive(Debug, Clone)]
pub struct ProxyCapability {
    proxy_type: Option<ProxyCapabilityType>,
    proxy_autoconfig_url: Option<String>,
    ftp_proxy: Option<String>,
    http_proxy: Option<String>,
    ssl_proxy: Option<String>,
    socks_proxy: Option<String>,
    socks_version: Option<u8>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionCapabilityRequest {
    accept_insecure_certs: Option<bool>,
    browser_name: Option<String>,
    browser_version: Option<String>,
    platform_name: Option<String>,
    proxy: Option<ProxyCapability>,
}

#[derive(Debug, Clone)]
pub struct SessionCapabilitiesRequest {
    always_match: Option<SessionCapabilityRequest>,
    first_match: Option<Vec<SessionCapabilityRequest>>,
}

#[derive(Debug, Clone)]
pub struct SessionSubscriptionRequest {
    events: Vec<String>,
    contexts: Option<Vec<BrowsingContext>>,
}
