use crate::utils::TestResult;
use http::header::AsHeaderName;
use http::{HeaderName, HeaderValue, header};
use itertools::Itertools;

pub trait ClientHelper {
    fn acme_req<T: serde::Serialize>(&self, url: &url::Url, body: &T) -> TestResult<reqwest::Request>;
}

impl ClientHelper for reqwest::Client {
    fn acme_req<T: serde::Serialize>(&self, url: &url::Url, body: &T) -> TestResult<reqwest::Request> {
        let body = serde_json::to_vec(body)?;
        Ok(self.post(url.as_str()).body(body).content_type_jose().build()?)
    }
}

pub trait RespHelper {
    fn replay_nonce(&self) -> String;
    fn location_url(&self) -> url::Url;
}

impl RespHelper for reqwest::Response {
    fn replay_nonce(&self) -> String {
        self.headers()
            .get("replay-nonce")
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .to_string()
    }

    fn location_url(&self) -> url::Url {
        self.headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .and_then(|u| url::Url::parse(u).ok())
            .unwrap()
    }
}

pub trait ReqHelper {
    fn content_type_jose(self) -> Self;
}

impl ReqHelper for reqwest::RequestBuilder {
    fn content_type_jose(self) -> Self {
        self.header("content-type", "application/jose+json")
    }
}

pub trait AcmeAsserter {
    fn expect_status(&mut self, status: http::status::StatusCode) -> &mut Self;
    fn expect_status_success(&mut self) -> &mut Self;
    fn expect_header_present(&mut self, name: impl AsHeaderName) -> &mut Self;
    fn expect_header_absent(&mut self, name: impl AsHeaderName) -> &mut Self;
    fn expect_header_value(&mut self, name: impl AsHeaderName, value: &'static str) -> &mut Self;
    fn expect_content_type_json(&mut self) -> &mut Self;
    fn has_replay_nonce(&mut self) -> &mut Self;
    fn has_location(&mut self) -> &mut Self;
}

impl AcmeAsserter for reqwest::Response {
    fn expect_status(&mut self, status: http::status::StatusCode) -> &mut Self {
        assert_eq!(self.status(), status);
        self
    }
    fn expect_status_success(&mut self) -> &mut Self {
        assert!(self.status().is_success());
        self
    }

    fn expect_header_present(&mut self, name: impl AsHeaderName) -> &mut Self {
        assert!(self.headers().contains_key(name));
        self
    }

    fn expect_header_absent(&mut self, name: impl AsHeaderName) -> &mut Self {
        assert!(!self.headers().contains_key(name));
        self
    }

    fn expect_header_value(&mut self, name: impl AsHeaderName, value: &'static str) -> &mut Self {
        let header_value = self.headers().get(name).unwrap().to_str().unwrap();
        assert_eq!(value, header_value);
        self
    }
    fn expect_content_type_json(&mut self) -> &mut Self {
        assert!(
            self.headers()
                .iter()
                .contains(&(&header::CONTENT_TYPE, &HeaderValue::from_static("application/json")))
        );
        self
    }
    fn has_replay_nonce(&mut self) -> &mut Self {
        assert!(self.headers().contains_key(HeaderName::from_static("replay-nonce")));
        let replay_nonce = self.headers().get(HeaderName::from_static("replay-nonce")).unwrap();
        assert!(!replay_nonce.is_empty());
        self
    }

    fn has_location(&mut self) -> &mut Self {
        assert!(self.headers().contains_key(header::LOCATION));
        let location = self.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(url::Url::try_from(location).is_ok());
        self
    }
}
