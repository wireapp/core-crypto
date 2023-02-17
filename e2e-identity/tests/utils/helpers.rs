use crate::utils::TestResult;

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

asserhttp::asserhttp_customize!(AcmeAsserter);

pub trait AcmeAsserter<T>: asserhttp::Asserhttp<T> {
    fn has_replay_nonce(&mut self) -> &mut T {
        self.expect_header("replay-nonce", |n: &str| assert!(!n.is_empty()))
    }

    fn has_location(&mut self) -> &mut T {
        self.expect_header("location", |location: &str| {
            assert!(url::Url::try_from(location).is_ok());
        })
    }
}
