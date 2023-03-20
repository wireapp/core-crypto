use crate::utils::wire_server::WireServerCfg;
use crate::utils::{
    ctx::ctx_store_http_client,
    display::TestDisplay,
    rand_base64_str, rand_str,
    wire_server::{oidc::OidcCfg, WireServer},
    TestResult,
};
use jwt_simple::prelude::*;
use rand::random;
use rusty_acme::prelude::{
    dex::{DexCfg, DexImage, DexServer},
    ldap::{LdapCfg, LdapImage, LdapServer},
    stepca::{AcmeServer, CaCfg, StepCaImage},
    AcmeAccount, AcmeAuthz, AcmeChallenge, AcmeDirectory, AcmeFinalize, AcmeOrder,
};
use rusty_jwt_tools::{jwk::TryIntoJwk, prelude::*};
use std::future::Future;
use std::pin::Pin;
use std::{
    collections::{hash_map::RandomState, HashMap},
    net::SocketAddr,
};
use testcontainers::clients::Cli;

pub struct E2eTest<'a> {
    pub display_name: String,
    pub domain: String,
    pub wire_client_id: u64,
    pub sub: ClientId,
    pub handle: String,
    pub ldap_cfg: LdapCfg,
    pub dex_cfg: DexCfg,
    pub ca_cfg: CaCfg,
    pub wire_server_cfg: WireServerCfg,
    pub backend_kp: Pem,
    pub alg: JwsAlgorithm,
    pub hash_alg: HashAlgorithm,
    pub client_kp: Pem,
    pub client_jwk: Jwk,
    pub is_demo: bool,
    pub display: TestDisplay,
    pub wire_server: Option<WireServer>,
    pub ldap_server: Option<LdapServer<'a>>,
    pub dex_server: Option<DexServer<'a>>,
    pub acme_server: Option<AcmeServer<'a>>,
    pub oidc_cfg: Option<OidcCfg>,
    pub client: reqwest::Client,
}

unsafe impl<'a> Send for E2eTest<'a> {}
unsafe impl<'a> Sync for E2eTest<'a> {}

impl<'a> E2eTest<'a> {
    const DEX_HOST: &'static str = "dex";
    const STEPCA_HOST: &'static str = "stepca";
    const LDAP_HOST: &'static str = "ldap";
    const WIRE_HOST: &'static str = "wire.com";
    const HOSTS: [&'static str; 4] = [Self::DEX_HOST, Self::STEPCA_HOST, Self::LDAP_HOST, Self::WIRE_HOST];

    pub fn new() -> Self {
        Self::new_internal(false)
    }

    pub fn new_demo() -> Self {
        Self::new_internal(true)
    }

    fn new_internal(is_demo: bool) -> Self {
        let [dex_host, ca_host, ldap_host, domain] = if is_demo {
            Self::HOSTS.map(|h| h.to_string())
        } else {
            Self::HOSTS.map(|h| format!("{h}.{}", rand_str(6).to_lowercase()))
        };

        let display_name = "Smith, Alice M (QA)";
        let wire_user_id = uuid::Uuid::new_v4();
        let wire_client_id = random::<u64>();
        let sub = ClientId::try_new(wire_user_id.to_string(), wire_client_id, &domain).unwrap();
        let handle = format!("{}alice.smith.qa@{domain}", ClientId::URI_PREFIX);
        let password = "foo";
        let email = format!("alicesmith@{domain}");
        let audience = "wireapp";
        let client_secret = rand_base64_str(24);
        let dex_host_port = portpicker::pick_unused_port().unwrap();
        let issuer = format!("http://{dex_host}:{dex_host_port}/dex");
        // this will be called from Docker network so we don't want to use the host port
        // TODO: support https for jwks uri
        let jwks_uri = format!("http://{dex_host}:{}/dex/keys", DexImage::PORT);

        let alg = JwsAlgorithm::Ed25519;
        let hash_alg = HashAlgorithm::SHA256;
        let client_kp = Ed25519KeyPair::generate();
        let backend_kp = Ed25519KeyPair::generate();

        let display = TestDisplay::new(format!("{:?} - {:?}", alg, hash_alg), false);

        Self {
            domain: domain.to_string(),
            display_name: display_name.to_string(),
            wire_client_id,
            sub: sub.clone(),
            handle: handle.clone(),
            ldap_cfg: LdapCfg {
                host: ldap_host.to_string(),
                display_name: display_name.to_string(),
                handle,
                email: email.to_string(),
                password: password.to_string(),
                domain: domain.to_string(),
                sub: sub.to_uri(),
            },
            dex_cfg: DexCfg {
                host: dex_host,
                ldap_host,
                host_port: dex_host_port,
                issuer: issuer.to_string(),
                client_id: audience.to_string(),
                client_secret: client_secret.to_string(),
                domain,
            },
            ca_cfg: CaCfg {
                sign_key: backend_kp.public_key().to_pem(),
                issuer,
                audience: audience.to_string(),
                jwks_uri,
                host: ca_host,
            },
            wire_server_cfg: WireServerCfg {
                issuer_uri: "".to_string(),
                client_id: audience.to_string(),
                client_secret,
                redirect_uri: "".to_string(),
            },
            alg,
            hash_alg,
            client_kp: client_kp.to_pem().into(),
            client_jwk: client_kp.public_key().try_into_jwk().unwrap(),
            backend_kp: backend_kp.to_pem().into(),
            display,
            wire_server: None,
            ldap_server: None,
            dex_server: None,
            acme_server: None,
            oidc_cfg: None,
            is_demo,
            client: reqwest::Client::new(),
        }
    }

    pub fn with_alg(self, alg: JwsAlgorithm) -> Self {
        match alg {
            JwsAlgorithm::Ed25519 => {
                let client_kp = Ed25519KeyPair::generate();
                let backend_kp = Ed25519KeyPair::generate();
                Self {
                    ca_cfg: CaCfg {
                        sign_key: backend_kp.public_key().to_pem(),
                        ..self.ca_cfg
                    },
                    alg,
                    hash_alg: alg.into(),
                    client_kp: client_kp.to_pem().into(),
                    client_jwk: client_kp.public_key().try_into_jwk().unwrap(),
                    backend_kp: backend_kp.to_pem().into(),
                    ..self
                }
            }
            JwsAlgorithm::P256 => {
                let client_kp = ES256KeyPair::generate();
                let backend_kp = ES256KeyPair::generate();
                Self {
                    ca_cfg: CaCfg {
                        sign_key: backend_kp.public_key().to_pem().unwrap(),
                        ..self.ca_cfg
                    },
                    alg,
                    hash_alg: alg.into(),
                    client_kp: client_kp.to_pem().unwrap().into(),
                    client_jwk: client_kp.public_key().try_into_jwk().unwrap(),
                    backend_kp: backend_kp.to_pem().unwrap().into(),
                    ..self
                }
            }
            JwsAlgorithm::P384 => {
                let client_kp = ES384KeyPair::generate();
                let backend_kp = ES384KeyPair::generate();
                Self {
                    ca_cfg: CaCfg {
                        sign_key: backend_kp.public_key().to_pem().unwrap(),
                        ..self.ca_cfg
                    },
                    alg,
                    hash_alg: alg.into(),
                    client_kp: client_kp.to_pem().unwrap().into(),
                    client_jwk: client_kp.public_key().try_into_jwk().unwrap(),
                    backend_kp: backend_kp.to_pem().unwrap().into(),
                    ..self
                }
            }
        }
    }

    pub async fn start(mut self, docker: &'a Cli) -> E2eTest<'a> {
        if self.is_demo {
            TestDisplay::clear();
            self.display.set_active();
        }

        // wire-server
        let wire_server_port = portpicker::pick_unused_port().unwrap();
        let wire_server = WireServer::run_on_port(wire_server_port).await;
        // LDAP (required by Dex)
        let ldap_server = LdapImage::run(docker, self.ldap_cfg.clone());

        // Dex (OIDC provider)
        let redirect_uri = format!("http://{}:{}/callback", self.domain, wire_server.port);
        let dex_server = DexImage::run(docker, self.dex_cfg.clone(), redirect_uri.clone());

        // Acme server
        let acme_server = StepCaImage::run(docker, self.ca_cfg.clone());

        // configure http client custom dns resolution for this test
        // this helps having domain names in request URIs instead of 'localhost:{port}'
        let dns_mappings = HashMap::<String, SocketAddr, RandomState>::from_iter(vec![
            (self.dex_cfg.host.clone(), dex_server.socket),
            (self.ldap_cfg.host.clone(), ldap_server.socket),
            (self.ca_cfg.host.clone(), acme_server.socket),
            (self.domain.clone(), wire_server.socket),
        ]);
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

        self.dex_server = Some(dex_server);
        let oidc_cfg = self.fetch_oidc_cfg().await;
        self.dex_cfg.issuer = oidc_cfg.issuer.clone();
        self.ca_cfg.issuer = oidc_cfg.issuer.clone();
        self.wire_server_cfg.issuer_uri = oidc_cfg.issuer_uri.as_ref().unwrap().to_string();
        self.wire_server_cfg.redirect_uri = redirect_uri;
        self.oidc_cfg = Some(oidc_cfg);

        self.acme_server = Some(acme_server);
        self.ldap_server = Some(ldap_server);
        self.wire_server = Some(wire_server);

        self
    }

    pub async fn fetch_oidc_cfg(&self) -> OidcCfg {
        let authz_server_uri = self.authorization_server_uri();
        let uri = format!("{authz_server_uri}/dex/.well-known/openid-configuration");
        let resp = self.client.get(&uri).send().await.unwrap();
        let mut cfg = resp.json::<OidcCfg>().await.unwrap();
        cfg.set_issuer_uri(&authz_server_uri);
        cfg
    }

    pub fn wire_server_uri(&self) -> String {
        let port = self.wire_server.as_ref().unwrap().port;
        format!("http://{}:{port}", self.domain)
    }

    pub fn issuer_uri(&self) -> String {
        self.oidc_cfg
            .as_ref()
            .and_then(|c| c.issuer_uri.as_ref())
            .unwrap()
            .to_string()
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/callback", self.wire_server_uri())
    }

    pub fn authorization_server_uri(&self) -> String {
        self.dex_server.as_ref().unwrap().uri.clone()
    }
}

impl std::ops::Deref for E2eTest<'_> {
    type Target = TestDisplay;

    fn deref(&self) -> &Self::Target {
        &self.display
    }
}

impl std::ops::DerefMut for E2eTest<'_> {
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

pub type E2eT = E2eTest<'static>;
pub type FlowResp<T> = Pin<Box<dyn Future<Output = TestResult<(E2eT, T)>>>>;
pub type Flow<P, R> = Box<dyn FnOnce(E2eT, P) -> FlowResp<R>>;

pub struct EnrollmentFlow {
    pub acme_directory: Flow<(), AcmeDirectory>,
    pub get_acme_nonce: Flow<AcmeDirectory, String>,
    pub new_account: Flow<(AcmeDirectory, String), (AcmeAccount, String)>,
    pub new_order: Flow<(AcmeDirectory, AcmeAccount, String), (AcmeOrder, url::Url, String)>,
    pub new_authz: Flow<(AcmeAccount, AcmeOrder, String), (AcmeAuthz, String)>,
    pub extract_challenges: Flow<AcmeAuthz, (AcmeChallenge, AcmeChallenge)>,
    pub get_wire_server_nonce: Flow<(), BackendNonce>,
    pub create_dpop_token: Flow<(AcmeChallenge, BackendNonce, core::time::Duration), String>,
    pub get_access_token: Flow<String, String>,
    pub verify_dpop_challenge: Flow<(AcmeAccount, AcmeChallenge, String, String), String>,
    pub fetch_id_token: Flow<(), String>,
    pub verify_oidc_challenge: Flow<(AcmeAccount, AcmeChallenge, String, String), String>,
    pub verify_order_status: Flow<(AcmeAccount, url::Url, String), (AcmeOrder, String)>,
    pub finalize: Flow<(AcmeAccount, AcmeOrder, String), (AcmeFinalize, String)>,
    pub get_x509_certificates: Flow<(AcmeAccount, AcmeFinalize, String), ()>,
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
            new_authz: Box::new(|mut test, (account, order, previous_nonce)| {
                Box::pin(async move {
                    let (authz, previous_nonce) = test.new_authz(&account, order, previous_nonce).await?;
                    Ok((test, (authz, previous_nonce)))
                })
            }),
            extract_challenges: Box::new(|mut test, authz| {
                Box::pin(async move {
                    let (dpop_chall, oidc_chall) = test.extract_challenges(authz)?;
                    Ok((test, (dpop_chall, oidc_chall)))
                })
            }),
            get_wire_server_nonce: Box::new(|mut test, _| {
                Box::pin(async move {
                    let backend_nonce = test.get_wire_server_nonce().await?;
                    Ok((test, backend_nonce))
                })
            }),
            create_dpop_token: Box::new(|mut test, (dpop_chall, backend_nonce, expiry)| {
                Box::pin(async move {
                    let client_dpop_token = test.create_dpop_token(&dpop_chall, backend_nonce, expiry).await?;
                    Ok((test, client_dpop_token))
                })
            }),
            get_access_token: Box::new(|mut test, client_dpop_token| {
                Box::pin(async move {
                    let access_token = test.get_access_token(client_dpop_token).await?;
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
            fetch_id_token: Box::new(|mut test, _| {
                Box::pin(async move {
                    let id_token = test.fetch_id_token().await?;
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
                    let (finalize, previous_nonce) = test.finalize(&account, order, previous_nonce).await?;
                    Ok((test, (finalize, previous_nonce)))
                })
            }),
            get_x509_certificates: Box::new(|mut test, (account, finalize, previous_nonce)| {
                Box::pin(async move {
                    test.get_x509_certificates(account, finalize, previous_nonce).await?;
                    Ok((test, ()))
                })
            }),
        }
    }
}
