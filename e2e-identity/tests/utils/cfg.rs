use std::{collections::HashMap, net::SocketAddr};

use jwt_simple::prelude::*;
use rand::random;
use rusty_acme::prelude::{AcmeAccount, AcmeAuthz, AcmeChallenge, AcmeDirectory, AcmeFinalize, AcmeOrder};
use rusty_jwt_tools::{jwk::TryIntoJwk, prelude::*};
use scraper::Html;

use crate::utils::{
    TestResult,
    ctx::ctx_store_http_client,
    display::TestDisplay,
    idp::IdpServer,
    rand_str, stepca,
    stepca::{AcmeServer, CaCfg},
};

pub fn scrap_login(html: String) -> String {
    let html = Html::parse_document(&html);
    let selector = scraper::Selector::parse("form").unwrap();
    let form = html.select(&selector).find(|_| true).unwrap();
    form.value().attr("action").unwrap().to_string()
}

#[derive(Debug, Clone)]
pub struct OauthCfg {
    pub client_id: String,
    pub redirect_uri: String,
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

pub struct E2eTest {
    pub display_name: String,
    pub domain: String,
    pub team: Option<String>,
    pub device_id: u64,
    pub sub: ClientId,
    pub handle: String,
    pub ca_cfg: CaCfg,
    pub oauth_cfg: OauthCfg,
    pub backend_kp: Pem,
    pub alg: JwsAlgorithm,
    pub hash_alg: HashAlgorithm,
    pub acme_kp: Pem,
    pub client_kp: Pem,
    pub acme_jwk: Jwk,
    pub is_demo: bool,
    pub display: TestDisplay,
    pub env: TestEnvironment,
    pub acme_server: Option<AcmeServer>,
    pub oidc_cfg: Option<OidcCfg>,
    pub client: reqwest::Client,
    pub oidc_provider: OidcProvider,
}

#[derive(Debug, Clone)]
pub struct WireServer {
    pub hostname: String,
    pub addr: SocketAddr,
}

impl WireServer {
    pub fn uri(&self) -> String {
        format!("http://{}:{}", self.hostname, self.addr.port())
    }

    /// Returns the Wire server-owned URI which the IdP server is supposed to redirect
    /// the user to after successful authentication.
    pub fn oauth_redirect_uri(&self) -> String {
        format!("http://{}:{}/callback", self.hostname, self.addr.port())
    }
}

#[derive(Debug, Clone)]
pub struct TestEnvironment {
    pub wire_server: WireServer,
    pub idp_server: IdpServer,
}

impl std::fmt::Debug for E2eTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OidcProvider {
    Keycloak,
}

impl E2eTest {
    const STEPCA_HOST: &'static str = "stepca";

    pub fn new(env: TestEnvironment) -> Self {
        Self::new_internal(false, JwsAlgorithm::Ed25519, env)
    }

    pub fn new_demo(env: TestEnvironment) -> Self {
        Self::new_internal(true, JwsAlgorithm::Ed25519, env)
    }

    pub fn new_internal(is_demo: bool, alg: JwsAlgorithm, env: TestEnvironment) -> Self {
        let oidc_provider = OidcProvider::Keycloak;
        let ca_host = if is_demo {
            Self::STEPCA_HOST.to_string()
        } else {
            format!("{}.{}", rand_str(6).to_lowercase(), Self::STEPCA_HOST)
        };
        let domain = env.wire_server.hostname.clone();
        let (firstname, lastname) = ("Alice", "Smith");
        let display_name = format!("{firstname} {lastname}");
        let wire_user_id = uuid::Uuid::new_v4();
        let wire_client_id = random::<u64>();
        let sub = ClientId::try_new(wire_user_id.to_string(), wire_client_id, &domain).unwrap();
        let (handle, team) = ("alice_wire", "wire");
        let audience = "wireapp";

        let (client_kp, sign_key, backend_kp, acme_kp, acme_jwk) = match alg {
            JwsAlgorithm::Ed25519 => {
                let client_kp = Ed25519KeyPair::generate();
                let backend_kp = Ed25519KeyPair::generate();
                let acme_kp = Ed25519KeyPair::generate();
                (
                    Pem::from(client_kp.to_pem()),
                    backend_kp.public_key().to_pem(),
                    Pem::from(backend_kp.to_pem()),
                    Pem::from(acme_kp.to_pem()),
                    acme_kp.public_key().try_into_jwk().unwrap(),
                )
            }
            JwsAlgorithm::P256 => {
                let client_kp = ES256KeyPair::generate();
                let backend_kp = ES256KeyPair::generate();
                let acme_kp = ES256KeyPair::generate();
                (
                    Pem::from(client_kp.to_pem().unwrap()),
                    backend_kp.public_key().to_pem().unwrap(),
                    Pem::from(backend_kp.to_pem().unwrap()),
                    Pem::from(acme_kp.to_pem().unwrap()),
                    acme_kp.public_key().try_into_jwk().unwrap(),
                )
            }
            JwsAlgorithm::P384 => {
                let client_kp = ES384KeyPair::generate();
                let backend_kp = ES384KeyPair::generate();
                let acme_kp = ES384KeyPair::generate();
                (
                    Pem::from(client_kp.to_pem().unwrap()),
                    backend_kp.public_key().to_pem().unwrap(),
                    Pem::from(backend_kp.to_pem().unwrap()),
                    Pem::from(acme_kp.to_pem().unwrap()),
                    acme_kp.public_key().try_into_jwk().unwrap(),
                )
            }
            JwsAlgorithm::P521 => {
                let client_kp = ES512KeyPair::generate();
                let backend_kp = ES512KeyPair::generate();
                let acme_kp = ES512KeyPair::generate();
                (
                    Pem::from(client_kp.to_pem().unwrap()),
                    backend_kp.public_key().to_pem().unwrap(),
                    Pem::from(backend_kp.to_pem().unwrap()),
                    Pem::from(acme_kp.to_pem().unwrap()),
                    acme_kp.public_key().try_into_jwk().unwrap(),
                )
            }
        };

        let hash_alg = HashAlgorithm::SHA256;
        let display = TestDisplay::new(format!("{alg:?} - {hash_alg:?}"), false);
        let issuer = env.idp_server.issuer.clone();
        let discovery_base_url = env.idp_server.discovery_base_url.clone();
        let oauth_redirect_uri = env.wire_server.oauth_redirect_uri();

        Self {
            env,
            domain: domain.to_string(),
            display_name: display_name.to_string(),
            device_id: wire_client_id,
            sub: sub.clone(),
            handle: handle.to_string(),
            team: Some(team.to_string()),
            ca_cfg: CaCfg {
                sign_key,
                issuer,
                audience: audience.to_string(),
                discovery_base_url,
                dpop_target_uri: None,
                domain: domain.to_string(),
                host: ca_host,
            },
            oauth_cfg: OauthCfg {
                client_id: audience.to_string(),
                redirect_uri: oauth_redirect_uri,
            },
            alg,
            hash_alg,
            client_kp,
            acme_kp,
            acme_jwk,
            backend_kp,
            display,
            acme_server: None,
            oidc_cfg: None,
            is_demo,
            client: reqwest::Client::new(),
            oidc_provider,
        }
    }

    pub async fn start(mut self) -> E2eTest {
        if self.is_demo {
            TestDisplay::clear();
            self.display.set_active();
        }

        let wire_server_uri = self.env.wire_server.uri();

        // start ACME server
        let template = r#"{{.DeviceID}}"#;
        let dpop_target_uri = format!("{wire_server_uri}/clients/{template}/access-token");
        self.ca_cfg.dpop_target_uri = Some(dpop_target_uri);
        let acme_server = stepca::start_acme_server(&self.ca_cfg).await;

        // configure http client custom dns resolution for this test
        // this helps having domain names in request URIs instead of 'localhost:{port}'
        let mut dns_mappings = HashMap::<String, SocketAddr>::new();
        dns_mappings.insert(self.ca_cfg.host.clone(), acme_server.socket);
        dns_mappings.insert(self.env.wire_server.hostname.clone(), self.env.wire_server.addr);
        dns_mappings.insert(self.env.idp_server.hostname.clone(), self.env.idp_server.addr);

        ctx_store_http_client(&dns_mappings);

        // configure the http client for our tests
        let mut client_builder = default_http_client()
            // to get mTLS connection accepted by acme server
            .add_root_certificate(acme_server.ca_cert.clone());

        // add DNS mapping
        for (host, socket) in &dns_mappings {
            client_builder = client_builder.resolve_to_addrs(host, &vec![*socket][..]);
        }

        self.client = client_builder.build().unwrap();

        let oidc_cfg = self.fetch_oidc_cfg().await;
        self.ca_cfg.issuer = oidc_cfg.issuer.clone();
        self.oidc_cfg = Some(oidc_cfg);
        self.acme_server = Some(acme_server);
        self
    }

    pub async fn fetch_oidc_cfg(&self) -> OidcCfg {
        let hostname = &self.env.idp_server.hostname;
        let realm = &self.env.idp_server.realm;
        let port = self.env.idp_server.addr.port();
        let uri = format!("http://{hostname}:{port}/realms/{realm}/.well-known/openid-configuration");
        let response = self.client.get(&uri).send().await.unwrap();
        let status = response.status();
        let response_text = response.text().await.unwrap();
        let cfg_deserialized = serde_json::from_str::<OidcCfg>(&response_text);
        match cfg_deserialized {
            Ok(mut cfg) => {
                cfg.set_issuer_uri(hostname);
                cfg
            }
            Err(e) => {
                panic!(
                    "Error deserializing OIDC config from response: {e}. Actual response ({status}): {response_text}."
                )
            }
        }
    }

    pub fn issuer_uri(&self) -> String {
        self.oidc_cfg
            .as_ref()
            .and_then(|c| c.issuer_uri.as_ref())
            .unwrap()
            .to_string()
    }

    pub async fn fetch_acme_root_ca(&self) -> String {
        #[derive(serde::Deserialize)]
        struct SmallStepRootsResponse {
            crts: Vec<String>,
        }

        let base_url = &self.acme_server.as_ref().unwrap().uri;
        let url = format!("{base_url}/roots");
        let resp = self.client.get(&url).send().await.unwrap();
        let certs = resp.json::<SmallStepRootsResponse>().await.unwrap();
        certs.crts.first().unwrap().to_string()
    }
}

impl std::ops::Deref for E2eTest {
    type Target = TestDisplay;

    fn deref(&self) -> &Self::Target {
        &self.display
    }
}

impl std::ops::DerefMut for E2eTest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.display
    }
}

pub fn default_http_client() -> reqwest::ClientBuilder {
    let timeout = core::time::Duration::from_secs(5);
    reqwest::ClientBuilder::new()
        .timeout(timeout)
        .connect_timeout(timeout)
        .connection_verbose(true)
        .danger_accept_invalid_certs(true)
}

pub type FlowResp<T> = std::pin::Pin<Box<dyn std::future::Future<Output = TestResult<(E2eTest, T)>>>>;
pub type Flow<P, R> = Box<dyn FnOnce(E2eTest, P) -> FlowResp<R>>;

pub struct EnrollmentFlow {
    pub acme_directory: Flow<(), AcmeDirectory>,
    pub get_acme_nonce: Flow<AcmeDirectory, String>,
    pub new_account: Flow<(AcmeDirectory, String), (AcmeAccount, String)>,
    pub new_order: Flow<(AcmeDirectory, AcmeAccount, String), (AcmeOrder, url::Url, String)>,
    pub new_authorization: Flow<(AcmeAccount, AcmeOrder, String), (AcmeAuthz, AcmeAuthz, String)>,
    pub extract_challenges: Flow<(AcmeAuthz, AcmeAuthz), (AcmeChallenge, AcmeChallenge)>,
    pub get_wire_server_nonce: Flow<(), BackendNonce>,
    pub create_dpop_token: Flow<
        (
            AcmeChallenge,
            BackendNonce,
            QualifiedHandle,
            Team,
            String,
            core::time::Duration,
        ),
        String,
    >,
    pub get_access_token: Flow<(AcmeChallenge, String), String>,
    pub verify_dpop_challenge: Flow<(AcmeAccount, AcmeChallenge, String, String), String>,
    pub fetch_id_token: Flow<(AcmeChallenge, String), String>,
    pub verify_oidc_challenge: Flow<(AcmeAccount, AcmeChallenge, String, String), String>,
    pub verify_order_status: Flow<(AcmeAccount, url::Url, String), (AcmeOrder, String)>,
    pub finalize: Flow<(AcmeAccount, AcmeOrder, String), (AcmeFinalize, String)>,
    pub get_x509_certificates: Flow<(AcmeAccount, AcmeFinalize, AcmeOrder, String), ()>,
}

impl Default for EnrollmentFlow {
    fn default() -> Self {
        Self {
            acme_directory: Box::new(|mut test, _| {
                Box::pin(async move {
                    let directory = test.get_acme_directory().await?;
                    Ok((test, directory))
                })
            }),
            get_acme_nonce: Box::new(|mut test, directory| {
                Box::pin(async move {
                    let previous_nonce = test.get_acme_nonce(&directory).await?;
                    Ok((test, previous_nonce))
                })
            }),
            new_account: Box::new(|mut test, (directory, previous_nonce)| {
                Box::pin(async move {
                    let (account, previous_nonce) = test.new_account(&directory, previous_nonce).await?;
                    Ok((test, (account, previous_nonce)))
                })
            }),
            new_order: Box::new(|mut test, (directory, account, previous_nonce)| {
                Box::pin(async move {
                    let (order, order_url, previous_nonce) =
                        test.new_order(&directory, &account, previous_nonce).await?;
                    Ok((test, (order, order_url, previous_nonce)))
                })
            }),
            new_authorization: Box::new(|mut test, (account, order, previous_nonce)| {
                Box::pin(async move {
                    let (authz_a, authz_b, previous_nonce) =
                        test.new_authorization(&account, order, previous_nonce).await?;
                    Ok((test, (authz_a, authz_b, previous_nonce)))
                })
            }),
            extract_challenges: Box::new(|mut test, (authz_a, authz_b)| {
                Box::pin(async move {
                    let (dpop_chall, oidc_chall) = test.extract_challenges(authz_a, authz_b)?;
                    Ok((test, (dpop_chall, oidc_chall)))
                })
            }),
            get_wire_server_nonce: Box::new(|mut test, _| {
                Box::pin(async move {
                    let backend_nonce = test.get_wire_server_nonce().await?;
                    Ok((test, backend_nonce))
                })
            }),
            create_dpop_token: Box::new(
                |mut test, (dpop_chall, backend_nonce, handle, team, display_name, expiry)| {
                    Box::pin(async move {
                        let client_dpop_token = test
                            .create_dpop_token(&dpop_chall, backend_nonce, handle, team, display_name, expiry)
                            .await?;
                        Ok((test, client_dpop_token))
                    })
                },
            ),
            get_access_token: Box::new(|mut test, (dpop_chall, client_dpop_token)| {
                Box::pin(async move {
                    let access_token = test.get_access_token(&dpop_chall, client_dpop_token).await?;
                    Ok((test, access_token))
                })
            }),
            verify_dpop_challenge: Box::new(|mut test, (account, dpop_chall, access_token, previous_nonce)| {
                Box::pin(async move {
                    let previous_nonce = test
                        .verify_dpop_challenge(&account, dpop_chall, access_token, previous_nonce)
                        .await?;
                    Ok((test, previous_nonce))
                })
            }),
            fetch_id_token: Box::new(|mut test, (oidc_chall, keyauth)| {
                Box::pin(async move {
                    let id_token = test.fetch_id_token(&oidc_chall, keyauth).await?;
                    Ok((test, id_token))
                })
            }),
            verify_oidc_challenge: Box::new(|mut test, (account, oidc_chall, id_token, previous_nonce)| {
                Box::pin(async move {
                    let previous_nonce = test
                        .verify_oidc_challenge(&account, oidc_chall, id_token, previous_nonce)
                        .await?;
                    Ok((test, previous_nonce))
                })
            }),
            verify_order_status: Box::new(|mut test, (account, order_url, previous_nonce)| {
                Box::pin(async move {
                    let (order, previous_nonce) = test.verify_order_status(&account, order_url, previous_nonce).await?;
                    Ok((test, (order, previous_nonce)))
                })
            }),
            finalize: Box::new(|mut test, (account, order, previous_nonce)| {
                Box::pin(async move {
                    let (finalize, previous_nonce) = test.finalize(&account, &order, previous_nonce).await?;
                    Ok((test, (finalize, previous_nonce)))
                })
            }),
            get_x509_certificates: Box::new(|mut test, (account, finalize, order, previous_nonce)| {
                Box::pin(async move {
                    test.get_x509_certificates(account, finalize, order, previous_nonce, None)
                        .await?;
                    Ok((test, ()))
                })
            }),
        }
    }
}
