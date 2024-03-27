use std::{
    collections::{hash_map::RandomState, HashMap},
    net::SocketAddr,
};

use jwt_simple::prelude::*;
use rand::random;
use testcontainers::clients::Cli;

use rusty_acme::prelude::{AcmeAccount, AcmeAuthz, AcmeChallenge, AcmeDirectory, AcmeFinalize, AcmeOrder};
use rusty_jwt_tools::{jwk::TryIntoJwk, prelude::*};

use crate::utils::{
    ctx::ctx_store_http_client,
    display::TestDisplay,
    docker::{
        dex::{DexCfg, DexImage, DexServer},
        keycloak::{KeycloakCfg, KeycloakImage, KeycloakServer},
        ldap::{LdapCfg, LdapImage, LdapServer},
        stepca::{AcmeServer, CaCfg, StepCaImage},
    },
    rand_base64_str, rand_str,
    wire_server::{oidc::OidcCfg, OauthCfg, WireServer},
    TestResult,
};

pub struct E2eTest<'a> {
    pub display_name: String,
    pub domain: String,
    pub team: Option<String>,
    pub device_id: u64,
    pub sub: ClientId,
    pub handle: String,
    pub ldap_cfg: LdapCfg,
    pub dex_cfg: DexCfg,
    pub keycloak_cfg: KeycloakCfg,
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
    pub wire_server: Option<WireServer>,
    pub ldap_server: Option<LdapServer<'a>>,
    pub keycloak_server: Option<KeycloakServer<'a>>,
    pub dex_server: Option<DexServer<'a>>,
    pub acme_server: Option<AcmeServer<'a>>,
    pub oidc_cfg: Option<OidcCfg>,
    pub client: reqwest::Client,
    pub oidc_provider: OidcProvider,
}

impl std::fmt::Debug for E2eTest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OidcProvider {
    Dex,
    Keycloak,
    Google,
}

unsafe impl<'a> Send for E2eTest<'a> {}

unsafe impl<'a> Sync for E2eTest<'a> {}

impl<'a> E2eTest<'a> {
    const STEPCA_HOST: &'static str = "stepca";
    const LDAP_HOST: &'static str = "ldap";
    const WIRE_HOST: &'static str = "wire.com";

    pub fn default_template(org: &str) -> String {
        // we use '{' to escape '{'. That's why we sometimes have 4: this uses handlebars template
        format!(
            r#"{{
        	"subject": {{
        	    "organization": "{org}",
        	    "commonName": {{{{ toJson .Oidc.name }}}}
        	}},
        	"uris": [{{{{ toJson .Oidc.preferred_username }}}}, {{{{ toJson .Dpop.sub }}}}],
        	"keyUsage": ["digitalSignature"],
        	"extKeyUsage": ["clientAuth"]
        }}"#
        )
    }

    pub fn new() -> Self {
        Self::new_internal(false, JwsAlgorithm::Ed25519, OidcProvider::Keycloak)
    }

    pub fn new_demo() -> Self {
        Self::new_internal(true, JwsAlgorithm::Ed25519, OidcProvider::Keycloak)
    }

    pub fn new_internal(is_demo: bool, alg: JwsAlgorithm, oidc_provider: OidcProvider) -> Self {
        let idp_host = match oidc_provider {
            OidcProvider::Dex => "dex",
            OidcProvider::Keycloak => "keycloak",
            OidcProvider::Google => "",
        };
        let hosts = [idp_host, Self::STEPCA_HOST, Self::LDAP_HOST, Self::WIRE_HOST];
        let [idp_host, ca_host, ldap_host, domain] = if is_demo {
            hosts.map(|h| h.to_string())
        } else {
            hosts.map(|h| format!("{h}.{}", rand_str(6).to_lowercase()))
        };

        let (firstname, lastname) = ("Alice", "Smith");
        let display_name = format!("{firstname} {lastname}");
        let wire_user_id = uuid::Uuid::new_v4();
        let wire_client_id = random::<u64>();
        let sub = ClientId::try_new(wire_user_id.to_string(), wire_client_id, &domain).unwrap();
        let (handle, team, password) = ("alice_wire", "wire", "foo");
        let qualified_handle = Handle::from(handle).try_to_qualified(&domain).unwrap();
        let keycloak_handle = format!("{handle}@{domain}");
        let email = format!("alicesmith@{domain}");
        let audience = "wireapp";
        let client_secret = rand_base64_str(24);
        let idp_host_port = portpicker::pick_unused_port().unwrap();
        std::env::set_var("IDP_HOST_PORT", idp_host_port.to_string());
        let idp_base = format!("http://{idp_host}");
        let (issuer, jwks_url, discovery_base_url) = match oidc_provider {
            OidcProvider::Dex => {
                // this will be called from Docker network so we don't want to use the host port
                let docker_port = DexImage::PORT;
                (
                    format!("{idp_base}:{idp_host_port}/dex"),
                    format!("{idp_base}:{docker_port}/dex/keys"),
                    "TODO".to_string(),
                )
            }
            OidcProvider::Keycloak => {
                let realm = KeycloakImage::REALM;
                (
                    format!("{idp_base}:{idp_host_port}/realms/{realm}"),
                    format!("{idp_base}:{idp_host_port}/realms/{realm}/protocol/openid-connect/certs",),
                    format!("{idp_base}:{idp_host_port}/realms/{realm}",),
                )
            }
            OidcProvider::Google => (
                "https://accounts.google.com".to_string(),
                "https://www.googleapis.com/oauth2/v3/certs".to_string(),
                "TODO".to_string(),
            ),
        };

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
            JwsAlgorithm::P521 => unimplemented!(),
        };

        let hash_alg = HashAlgorithm::SHA256;
        let display = TestDisplay::new(format!("{:?} - {:?}", alg, hash_alg), false);
        let template = Self::default_template(&domain);

        Self {
            domain: domain.to_string(),
            display_name: display_name.to_string(),
            device_id: wire_client_id,
            sub: sub.clone(),
            handle: handle.to_string(),
            team: Some(team.to_string()),
            ldap_cfg: LdapCfg {
                host: ldap_host.to_string(),
                display_name: display_name.to_string(),
                handle: qualified_handle.to_string(),
                email: email.clone(),
                password: password.to_string(),
                domain: domain.to_string(),
                sub: sub.to_uri(),
            },
            dex_cfg: DexCfg {
                host: idp_host.clone(),
                ldap_host,
                host_port: idp_host_port,
                issuer: issuer.to_string(),
                client_id: audience.to_string(),
                client_secret: client_secret.to_string(),
                domain,
            },
            keycloak_cfg: KeycloakCfg {
                oauth_client_id: audience.to_string(),
                http_host_port: idp_host_port,
                host: idp_host,
                firstname: firstname.to_string(),
                lastname: lastname.to_string(),
                username: keycloak_handle.to_string(),
                // username: qualified_handle.to_string(),
                email,
                password: password.to_string(),
            },
            ca_cfg: CaCfg {
                sign_key,
                issuer,
                audience: audience.to_string(),
                jwks_url,
                discovery_base_url,
                dpop_target_uri: None,
                x509_template: serde_json::json!({ "template": template }),
                oidc_template: serde_json::json!({
                    "name": "{{ .name }}",
                    "preferred_username": "wireapp://%40{{ .preferred_username }}"
                }),
                host: ca_host,
            },
            oauth_cfg: OauthCfg {
                issuer_uri: "".to_string(),
                client_id: audience.to_string(),
                client_secret,
                redirect_uri: "".to_string(),
            },
            alg,
            hash_alg,
            client_kp,
            acme_kp,
            acme_jwk,
            backend_kp,
            display,
            wire_server: None,
            ldap_server: None,
            dex_server: None,
            keycloak_server: None,
            acme_server: None,
            oidc_cfg: None,
            is_demo,
            client: reqwest::Client::new(),
            oidc_provider,
        }
    }

    pub async fn start(mut self, docker: &'a Cli) -> E2eTest<'a> {
        if self.is_demo {
            TestDisplay::clear();
            self.display.set_active();
        }

        // wire-server
        let (wire_server_host, wire_server_port, redirect) = match self.oidc_provider {
            OidcProvider::Dex | OidcProvider::Keycloak => {
                (self.domain.clone(), portpicker::pick_unused_port().unwrap(), "callback")
            }
            // need to use a fixed port for Google in order to have a constant redirect_uri
            OidcProvider::Google => ("localhost".to_string(), 9090, "callback-google"),
        };
        let wire_server = WireServer::run_on_port(wire_server_port).await;

        let wire_server_uri = format!("http://{wire_server_host}:{wire_server_port}");
        let redirect_uri = format!("{wire_server_uri}/{redirect}");

        let mut dns_mappings = HashMap::<String, SocketAddr, RandomState>::new();

        // start OIDC server
        match self.oidc_provider {
            OidcProvider::Dex => {
                // LDAP (required by Dex)
                let ldap_server = LdapImage::run(docker, self.ldap_cfg.clone());
                self.ldap_server = Some(ldap_server);

                // Dex (OIDC provider)
                let dex_server = DexImage::run(docker, self.dex_cfg.clone(), redirect_uri.clone());
                dns_mappings.insert(self.dex_cfg.host.clone(), dex_server.socket);
                self.dex_server = Some(dex_server);
            }
            OidcProvider::Keycloak => {
                let keycloak_server = KeycloakImage::run(docker, self.keycloak_cfg.clone(), redirect_uri.clone()).await;
                dns_mappings.insert(self.keycloak_cfg.host.clone(), keycloak_server.socket);
                self.keycloak_server = Some(keycloak_server);
            }
            OidcProvider::Google => {}
        }

        // start ACME server
        let template = r#"{{.DeviceID}}"#;
        let dpop_target_uri = format!("{wire_server_uri}/clients/{template}/access-token");
        self.ca_cfg.dpop_target_uri = Some(dpop_target_uri);
        // Acme server
        let acme_server = StepCaImage::run(docker, self.ca_cfg.clone());

        // configure http client custom dns resolution for this test
        // this helps having domain names in request URIs instead of 'localhost:{port}'
        dns_mappings.insert(self.ca_cfg.host.clone(), acme_server.socket);
        dns_mappings.insert(self.domain.clone(), wire_server.socket);

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
        self.dex_cfg.issuer = oidc_cfg.issuer.clone();
        self.ca_cfg.issuer = oidc_cfg.issuer.clone();
        let issuer_uri = oidc_cfg.issuer_uri.as_ref().unwrap().trim_end_matches('/').to_string();
        self.oauth_cfg.issuer_uri = issuer_uri;
        self.oauth_cfg.redirect_uri = redirect_uri;
        self.oidc_cfg = Some(oidc_cfg);

        self.acme_server = Some(acme_server);
        self.wire_server = Some(wire_server);

        self
    }

    pub async fn fetch_oidc_cfg(&self) -> OidcCfg {
        let authz_server_uri = match self.oidc_provider {
            OidcProvider::Dex => self.dex_authorization_server_uri(),
            OidcProvider::Keycloak => self.keycloak_server.as_ref().unwrap().http_uri.clone(),
            OidcProvider::Google => "https://accounts.google.com".to_string(),
        };
        let uri = match self.oidc_provider {
            OidcProvider::Dex => format!("{authz_server_uri}/dex/.well-known/openid-configuration"),
            OidcProvider::Keycloak => {
                format!(
                    "{authz_server_uri}/realms/{}/.well-known/openid-configuration",
                    KeycloakImage::REALM
                )
            }
            OidcProvider::Google => "https://accounts.google.com/.well-known/openid-configuration".to_string(),
        };
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

    pub fn dex_authorization_server_uri(&self) -> String {
        self.dex_server.as_ref().unwrap().uri.clone()
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
pub type FlowResp<T> = std::pin::Pin<Box<dyn std::future::Future<Output = TestResult<(E2eT, T)>>>>;
pub type Flow<P, R> = Box<dyn FnOnce(E2eT, P) -> FlowResp<R>>;

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
                    test.get_x509_certificates(account, finalize, order, previous_nonce)
                        .await?;
                    Ok((test, ()))
                })
            }),
        }
    }
}
