//! Test helper for sharing data between the resource server (wire-server) and the client which
//! is responsible for displaying them.

use std::net::SocketAddr;
use std::{
    collections::{HashMap, hash_map::RandomState},
    str::FromStr,
};

use base64::Engine;
use http::{Method, Request};
use hyper::body::Incoming;
use itertools::Itertools;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::utils::cfg::default_http_client;

lazy_static::lazy_static! {
    // ugly but openidconnect::Client has too many generics and it's a hell to store in a context
    // to pass between endpoints
    pub static ref CONTEXT: std::sync::Mutex<HashMap<String, String>> = std::sync::Mutex::new(HashMap::new());
}

pub async fn custom_oauth_client(
    key: &'static str,
    client: reqwest::Client,
    request: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, oauth2::reqwest::Error<reqwest::Error>> {
    ctx_store_request(key, &request);
    let resp = proxy_http_client(client, request).await;
    if let Ok(resp) = resp.as_ref() {
        ctx_store(format!("{key}-response-status"), resp.status_code.as_str());
        let headers = resp
            .headers
            .iter()
            .map(|(k, v)| format!("{}|{}", k.as_str(), v.to_str().unwrap()))
            .join(";");
        ctx_store(format!("{key}-response-headers"), headers);
        let b64_body = base64::prelude::BASE64_STANDARD.encode(resp.body.clone());
        ctx_store(format!("{key}-response-body"), b64_body);
    }
    resp
}

pub async fn proxy_http_client(
    client: reqwest::Client,
    req: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, oauth2::reqwest::Error<reqwest::Error>> {
    // Map oauth http headers to reqwest headers
    let request_headers = req
        .headers
        .iter()
        .map(|(k, v)| {
            (
                HeaderName::from_str(k.as_str()).unwrap(),
                HeaderValue::from_str(v.to_str().unwrap()).unwrap(),
            )
        })
        .collect();

    // Now use the reqwest client
    let request = client
        .request(Method::from_str(req.method.as_str()).unwrap(), req.url.as_str())
        .headers(request_headers)
        .body(req.body);
    let response = request.send().await.unwrap();

    // Map the reqwest headers back to oauth headers
    let response_headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                oauth2::http::header::HeaderName::from_str(k.as_str()).unwrap(),
                oauth2::http::header::HeaderValue::from_str(v.to_str().unwrap()).unwrap(),
            )
        })
        .collect();
    Ok(oauth2::HttpResponse {
        status_code: oauth2::http::StatusCode::from_u16(response.status().as_u16()).unwrap(),
        headers: response_headers,
        body: response.bytes().await.unwrap().to_vec(),
    })
}

// store args for callback endpoint because openidconnect::Client is a mess to handle
pub fn ctx_store(key: impl AsRef<str>, value: impl AsRef<str>) {
    CONTEXT
        .lock()
        .unwrap()
        .insert(key.as_ref().to_string(), value.as_ref().to_string());
}

pub fn ctx_store_request(key: &'static str, req: &oauth2::HttpRequest) {
    ctx_store(format!("{key}-request-method"), req.method.as_str());
    ctx_store(format!("{key}-request-uri"), req.url.as_str());
    let headers = req
        .headers
        .iter()
        .map(|(k, v)| format!("{}|{}", k.as_str(), v.to_str().unwrap()))
        .join(";");
    ctx_store(format!("{key}-request-headers"), headers);
    let body = base64::prelude::BASE64_STANDARD.encode(&req.body);
    ctx_store(format!("{key}-request-body"), body);
}

pub fn ctx_store_reqwest_request(key: &'static str, req: &reqwest::Request) {
    ctx_store(format!("{key}-request-method"), req.method().as_str());
    ctx_store(format!("{key}-request-uri"), req.url().as_str());
    let headers = req
        .headers()
        .iter()
        .map(|(k, v)| format!("{}|{}", k.as_str(), v.to_str().unwrap()))
        .join(";");
    ctx_store(format!("{key}-request-headers"), headers);
    if let Some(body) = req.body().and_then(|b| b.as_bytes()) {
        let body = base64::prelude::BASE64_STANDARD.encode(body);
        ctx_store(format!("{key}-request-body"), body);
    }
}

pub fn ctx_store_http_request(key: &'static str, req: &Request<Incoming>) {
    ctx_store(format!("{key}-request-method"), req.method().as_str());
    ctx_store(format!("{key}-request-uri"), req.uri().to_string());
    let headers = req
        .headers()
        .iter()
        .map(|(k, v)| format!("{}|{}", k.as_str(), v.to_str().unwrap()))
        .join(";");
    ctx_store(format!("{key}-request-headers"), headers);
}

pub async fn ctx_store_reqwest_response(key: &'static str, resp: reqwest::Response) -> Option<Vec<u8>> {
    ctx_store(format!("{key}-response-status"), resp.status().as_str());
    ctx_store(format!("{key}-response-uri"), resp.url().as_str());
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| format!("{}|{}", k.as_str(), v.to_str().unwrap()))
        .join(";");
    ctx_store(format!("{key}-response-headers"), headers);

    if let Ok(body) = resp.bytes().await {
        let body = body.to_vec();
        let b64_body = base64::prelude::BASE64_STANDARD.encode(body.clone());
        ctx_store(format!("{key}-response-body"), b64_body);
        return Some(body);
    }
    None
}

pub fn ctx_get(key: impl AsRef<str>) -> Option<String> {
    CONTEXT.lock().unwrap().get(key.as_ref()).map(|v| v.to_string())
}

pub fn ctx_get_request(key: &'static str) -> reqwest::Request {
    let method = ctx_get(format!("{key}-request-method")).unwrap();
    let method = reqwest::Method::from_str(&method).unwrap();
    let uri: url::Url = ctx_get(format!("{key}-request-uri")).unwrap().parse().unwrap();
    let headers = ctx_get(format!("{key}-request-headers"))
        .unwrap()
        .split(';')
        .filter_map(|kv| {
            let mut kv = kv.split('|');
            kv.next().zip(kv.next())
        })
        .filter_map(|(k, v)| k.parse().ok().zip(v.parse().ok()))
        .collect::<Vec<(HeaderName, HeaderValue)>>();
    let body = ctx_get(format!("{key}-request-body"))
        .map(|body| base64::prelude::BASE64_STANDARD.decode(body).unwrap())
        .map(reqwest::Body::from);

    // sadly this is currently the only way to build a RequestBuilder
    let mut req = reqwest::Client::new()
        .request(method, uri)
        .headers(HeaderMap::from_iter(headers));
    if let Some(body) = body {
        req = req.body(body)
    }
    req.build().unwrap()
}

pub fn ctx_get_resp(key: &'static str, as_html: bool) -> String {
    let status = ctx_get(format!("{key}-response-status"))
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let uri = ctx_get(format!("{key}-response-uri")).unwrap_or_default();
    let headers = ctx_get(format!("{key}-response-headers"));
    let headers = headers
        .as_ref()
        .unwrap()
        .split(';')
        .filter_map(|kv| {
            let mut kv = kv.split('|');
            kv.next().zip(kv.next())
        })
        .collect::<Vec<(&str, &str)>>();
    let headers = HashMap::<&str, &str, RandomState>::from_iter(headers);
    let body = ctx_get(format!("{key}-response-body"))
        .map(|body| base64::prelude::BASE64_STANDARD.decode(body).unwrap())
        .map(|body| String::from_utf8(body).unwrap());
    if as_html {
        format!(
            r#"
```text
{status} {uri}
{headers:#?}
```

<details>
<summary>Html</summary>

```html
{}
```

</details>

"#,
            body.unwrap_or_default()
        )
    } else {
        body.unwrap_or_default()
    }
}

const DNS_MAPPING_PREFIX: &str = "dns-mapping-";

pub fn ctx_store_http_client(mappings: &HashMap<String, SocketAddr>) {
    for (host, socket) in mappings {
        ctx_store(format!("{DNS_MAPPING_PREFIX}{}", host), socket.to_string())
    }
}

pub fn ctx_get_http_client() -> reqwest::Client {
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
    builder.build().unwrap()
}
