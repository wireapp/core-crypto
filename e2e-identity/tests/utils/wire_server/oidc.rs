use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use scraper::Html;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct Oidc {
    name: String,
    handle: String,
    keyauth: String,
}

pub fn scrap_login(html: String) -> String {
    let html = Html::parse_document(&html);
    let selector = scraper::Selector::parse("form").unwrap();
    let form = html.select(&selector).find(|_| true).unwrap();
    form.value().attr("action").unwrap().to_string()
}

pub async fn handle_callback(req: Request<Incoming>) -> http::Result<Response<Full<Bytes>>> {
    let req_uri = req.uri().clone();
    let req_uri: url::Url = format!("http://localhost{req_uri}").parse().unwrap();
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
