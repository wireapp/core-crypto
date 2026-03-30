//! Test helper for sharing data between the resource server (wire-server) and the client which
//! is responsible for displaying them.

use std::{
    collections::HashMap,
    net::SocketAddr,
    str::FromStr,
    sync::{LazyLock, Mutex},
};

use base64::Engine;
use http::Method;
use itertools::Itertools;

use crate::utils::cfg::default_http_client;

// ugly but openidconnect::Client has too many generics and it's a hell to store in a context
// to pass between endpoints
pub(crate) static CONTEXT: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) async fn custom_oauth_client(
    key: &'static str,
    client: reqwest::Client,
    request: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, oauth2::reqwest::Error> {
    ctx_store_request(key, &request);
    let resp = proxy_http_client(client, request).await;
    if let Ok(resp) = resp.as_ref() {
        ctx_store(format!("{key}-response-status"), resp.status().as_str());
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| format!("{}|{}", k.as_str(), v.to_str().unwrap()))
            .join(";");
        ctx_store(format!("{key}-response-headers"), headers);
        let b64_body = base64::prelude::BASE64_STANDARD.encode(resp.body().clone());
        ctx_store(format!("{key}-response-body"), b64_body);
    }
    resp
}

pub(crate) async fn proxy_http_client(
    client: reqwest::Client,
    req: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, oauth2::reqwest::Error> {
    // Now use the reqwest client
    let request = client
        .request(Method::from_str(req.method().as_str()).unwrap(), req.uri().to_string())
        .headers(req.headers().clone())
        .body(req.body().clone());
    let response = request.send().await.unwrap();

    let mut builder = http::Response::builder().status(response.status());

    for (k, v) in response.headers() {
        builder = builder.header(k, v);
    }

    Ok(builder.body(response.bytes().await?.to_vec()).unwrap())
}

// store args for callback endpoint because openidconnect::Client is a mess to handle
pub(crate) fn ctx_store(key: impl AsRef<str>, value: impl AsRef<str>) {
    CONTEXT
        .lock()
        .unwrap()
        .insert(key.as_ref().to_string(), value.as_ref().to_string());
}

pub(crate) fn ctx_store_request(key: &'static str, req: &oauth2::HttpRequest) {
    ctx_store(format!("{key}-request-method"), req.method().as_str());
    ctx_store(format!("{key}-request-uri"), req.uri().to_string());
    let headers = req
        .headers()
        .iter()
        .map(|(k, v)| format!("{}|{}", k.as_str(), v.to_str().unwrap()))
        .join(";");
    ctx_store(format!("{key}-request-headers"), headers);
    let body = base64::prelude::BASE64_STANDARD.encode(req.body());
    ctx_store(format!("{key}-request-body"), body);
}

pub(crate) fn ctx_get(key: impl AsRef<str>) -> Option<String> {
    CONTEXT.lock().unwrap().get(key.as_ref()).map(|v| v.to_string())
}

const DNS_MAPPING_PREFIX: &str = "dns-mapping-";

pub(crate) fn ctx_store_http_client(mappings: &HashMap<String, SocketAddr>) {
    for (host, socket) in mappings {
        ctx_store(format!("{DNS_MAPPING_PREFIX}{host}"), socket.to_string())
    }
}

pub(crate) fn ctx_get_http_client_builder() -> reqwest::ClientBuilder {
    let ctx = CONTEXT.lock().unwrap();
    let mappings = ctx
        .iter()
        .filter_map(|(k, v)| {
            if k.starts_with(DNS_MAPPING_PREFIX) {
                Some(k.clone()).zip(SocketAddr::from_str(v).ok())
            } else {
                None
            }
        })
        .collect::<Vec<(String, SocketAddr)>>();

    let mut builder = default_http_client();
    for (host, socket) in mappings {
        let host = host.strip_prefix(DNS_MAPPING_PREFIX).unwrap();
        builder = builder.resolve_to_addrs(host, &vec![socket][..]);
    }
    builder
}

pub(crate) fn ctx_get_http_client() -> reqwest::Client {
    ctx_get_http_client_builder().build().unwrap()
}
