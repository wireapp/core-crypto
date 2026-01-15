use std::{borrow::Cow, collections::HashMap, env, net::SocketAddr, process::Command, sync::OnceLock};

use http::header;
use itertools::Itertools as _;
use keycloak::{
    KeycloakAdmin, KeycloakAdminToken,
    types::{ClientRepresentation, CredentialRepresentation, ProtocolMapperRepresentation, UserRepresentation},
};
use oauth2::{CsrfToken, PkceCodeChallenge, RedirectUrl, Scope};
use openidconnect::{
    IssuerUrl, Nonce,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use serde_json::json;
use testcontainers::{
    Image, ImageExt, ReuseDirective,
    core::{ContainerPort, IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
};
use url::Url;

use crate::utils::{
    NETWORK, SHM,
    cfg::scrap_login,
    ctx::{ctx_get_http_client, custom_oauth_client},
    idp::{IdpServer, IdpServerConfig, OAUTH_CLIENT_ID, OAUTH_CLIENT_NAME, OauthCfg, OidcProvider, User},
};

#[derive(Debug)]
struct KeycloakImage {
    pub volumes: Vec<Mount>,
    pub env_vars: HashMap<String, String>,
    tag: String,
    host_port: ContainerPort,
}

static KEYCLOAK_PORTS: OnceLock<[ContainerPort; 1]> = OnceLock::new();

impl KeycloakImage {
    const NAME: &'static str = "wire-keycloak";
    const TAG: &'static str = "latest";
    // Keep keycloak versions in sync (search for this comment to find all places to update)
    const VERSION: &'static str = "26.4.6";

    const USER: &'static str = "admin";
    const PASSWORD: &'static str = "changeme";
    const REALM: &'static str = "master";
    const LOG_LEVEL: &'static str = "info";

    fn build(port: u16) {
        let cwd = env::var("CARGO_MANIFEST_DIR").unwrap();
        Command::new("docker")
            .args(["image", "rm", &format!("{}:{}", Self::NAME, Self::TAG)])
            .output()
            .unwrap();

        let build_args = &[
            "build",
            "--file",
            &format!("{cwd}/tests/utils/idp/keycloak/Dockerfile"),
            "--force-rm=true",
            "--build-arg",
            &format!("kc_port={port}"),
            &format!("--tag={}:{}", Self::NAME, Self::TAG),
            ".",
        ];
        let output = Command::new("docker").args(build_args).output().unwrap();
        if !output.status.success() {
            panic!("stderr: {}", String::from_utf8(output.stderr).unwrap());
        }
    }

    fn new(host_port: ContainerPort) -> Self {
        Self {
            volumes: vec![],
            env_vars: HashMap::from_iter(vec![
                ("KEYCLOAK_ADMIN".to_string(), Self::USER.to_string()),
                ("KEYCLOAK_ADMIN_PASSWORD".to_string(), Self::PASSWORD.to_string()),
                ("KC_LOG_LEVEL".to_string(), Self::LOG_LEVEL.to_string()),
            ]),
            tag: env::var("KEYCLOAK_VERSION").unwrap_or(Self::TAG.to_string()),
            host_port,
        }
    }

    async fn configure(config: &IdpServerConfig, external_port: u16) {
        let url = format!("http://localhost:{external_port}");
        let user = Self::USER.to_string();
        let password = Self::PASSWORD.to_string();
        let client = reqwest::Client::new();
        let admin_token = KeycloakAdminToken::acquire(&url, &user, &password, &client)
            .await
            .unwrap();
        let admin = KeycloakAdmin::new(&url, admin_token, client);

        // Create a User for the test
        let user = (&config.user).into();
        admin.realm_users_post(Self::REALM, user).await.unwrap();

        // Then create an OAuth public Client (w/o client-secret)
        let client = ClientRepresentation {
            client_id: Some(OAUTH_CLIENT_ID.to_string()),
            name: Some(OAUTH_CLIENT_NAME.to_string()),
            consent_required: Some(false),
            always_display_in_console: Some(true),
            enabled: Some(true),
            implicit_flow_enabled: Some(false),
            standard_flow_enabled: Some(true),
            redirect_uris: Some(vec![config.redirect_uri.clone()]),
            public_client: Some(true),
            ..Default::default()
        };
        admin.realm_clients_post(Self::REALM, client).await.unwrap();

        // Now we need to turn on the "oidc-claims-param-token-mapper" mapper to activate the claims request mapping
        // https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
        // (event though the discovery endpoint already advertises supporting it)
        let component_type = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy";
        let components = admin
            .realm_components_get(Self::REALM, None, None, Some(component_type.to_string()))
            .await
            .unwrap();
        let mut component = components
            .into_iter()
            .find(|c| {
                c.provider_id == Some("allowed-protocol-mappers".to_string())
                    && c.name == Some("Allowed Protocol Mapper Types".to_string())
                    && c.sub_type == Some("anonymous".to_string())
            })
            .unwrap();

        let component_id = component.id.as_ref().unwrap();
        if let Some(component_cfg) = component.config.as_mut() {
            component_cfg
                .entry("allowed-protocol-mapper-types".to_string())
                .and_modify(|e| {
                    e.push("oidc-claims-param-value-idtoken-mapper".to_string());
                });
        }

        admin
            .realm_components_with_id_put(Self::REALM, component_id, component.clone())
            .await
            .unwrap();

        // Configure Keycloak to include extra claims, 'keyauth' and 'acme_aud',
        // in the returned ID token.
        let scopes = admin.realm_client_scopes_get(Self::REALM).await.unwrap();
        let profile_scope = scopes.iter().find(|s| s.name == Some("profile".to_string())).unwrap();
        let scope_id = profile_scope.id.clone().unwrap();

        Self::configure_extra_claim(&admin, &scope_id, "keyauth").await;
        Self::configure_extra_claim(&admin, &scope_id, "acme_aud").await;
    }

    async fn configure_extra_claim(admin: &KeycloakAdmin, scope_id: &str, claim_name: &str) {
        let mapper = ProtocolMapperRepresentation {
            config: Some(HashMap::from_iter([
                ("claim.name".to_string(), claim_name.to_string()),
                ("id.token.claim".to_string(), "true".to_string()),
            ])),
            name: Some(format!("wire-{claim_name}-id-token-mapper")),
            protocol: Some("openid-connect".to_string()),
            protocol_mapper: Some("oidc-claims-param-value-idtoken-mapper".to_string()),
            ..Default::default()
        };

        admin
            .realm_client_scopes_with_client_scope_id_protocol_mappers_models_post(Self::REALM, scope_id, mapper)
            .await
            .unwrap();
    }
}

impl From<&User> for UserRepresentation {
    fn from(user: &User) -> Self {
        Self {
            username: Some(user.username.clone()),
            email: Some(user.email.clone()),
            enabled: Some(true),
            email_verified: Some(true),
            first_name: Some(user.first_name.clone()),
            last_name: Some(user.last_name.clone()),
            credentials: Some(vec![CredentialRepresentation {
                temporary: Some(false),
                value: Some("foo".to_string()),
                credential_data: Some("foo".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }
}

impl Image for KeycloakImage {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        let msg = format!("Keycloak {} on JVM", Self::VERSION);
        vec![WaitFor::message_on_stdout(msg)]
    }

    fn env_vars(&self) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        &self.env_vars
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        self.volumes.as_slice()
    }

    fn cmd(&self) -> impl IntoIterator<Item = impl Into<Cow<'_, str>>> {
        let options = ["--verbose", "start-dev"].map(str::to_string);
        Box::new(options.into_iter())
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        KEYCLOAK_PORTS.get_or_init(|| [self.host_port])
    }
}

pub async fn start_server(config: &IdpServerConfig, port: u16) -> IdpServer {
    KeycloakImage::build(port);

    let instance = KeycloakImage::new(port.tcp());
    let image = instance
        .with_container_name(&config.hostname)
        .with_network(NETWORK)
        .with_mapped_port(port, port.tcp())
        .with_privileged(true)
        .with_reuse(ReuseDirective::Always)
        .with_shm_size(SHM);

    image.start().await.expect("starting Keycloak will succeed");
    KeycloakImage::configure(config, port).await;

    let hostname = config.hostname.clone();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let realm = KeycloakImage::REALM;
    let issuer = format!("http://{hostname}:{port}/realms/{realm}");
    let discovery_base_url = issuer.clone();

    IdpServer {
        provider: OidcProvider::Keycloak,
        hostname,
        addr,
        issuer,
        discovery_base_url,
        user: config.user.clone(),
    }
}

pub(super) async fn fetch_id_token(
    idp_server: &IdpServer,
    oauth_cfg: &OauthCfg,
    oidc_target: &Url,
    keyauth: &str,
    acme_audience: &str,
) -> String {
    let issuer_url = IssuerUrl::new(oidc_target.as_str().to_string()).unwrap();

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), &async |r| {
        custom_oauth_client("discovery", ctx_get_http_client(), r).await
    })
    .await
    .unwrap();

    let client_id = openidconnect::ClientId::new(oauth_cfg.client_id.clone());
    let redirect_url = RedirectUrl::new(oauth_cfg.redirect_uri.clone()).unwrap();
    let oidc_client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, None).set_redirect_uri(redirect_url);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // A variant of https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
    let extra = json!({
        "id_token": {
            "keyauth": { "essential": true, "value": keyauth },
            "acme_aud": { "essential": true, "value": acme_audience }
        }
    })
    .to_string();

    let (authz_url, ..) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".to_string()))
        .add_extra_param("claims", extra)
        .set_pkce_challenge(pkce_challenge)
        .url();

    let client = ctx_get_http_client();
    let authz_req = client.get(authz_url.as_str()).build().unwrap();

    // Authorization Server redirects to login prompt
    let resp = client.execute(authz_req).await.unwrap();

    let cookies = resp.cookies().map(|c| format!("{}={}", c.name(), c.value())).join("; ");

    let html = resp.text().await.unwrap();
    let action = scrap_login(html);

    // client signs in
    let mut form_uri = Url::parse(&action).unwrap();
    form_uri.set_host(Some("127.0.0.1")).unwrap();
    let form_body = HashMap::<&str, String>::from_iter(vec![
        ("username", idp_server.user.username.clone()),
        ("password", idp_server.user.password.clone()),
        ("credentialId", "".to_string()),
    ]);

    // Client submits login form
    let login_form_req = client
        .post(form_uri)
        .form(&form_body)
        .header(header::COOKIE, cookies)
        .build()
        .unwrap();
    let resp = client.execute(login_form_req).await.unwrap();
    let authz_code = resp.text().await.unwrap();

    let token_request = oidc_client
        .exchange_code(openidconnect::AuthorizationCode::new(authz_code))
        .unwrap()
        .set_pkce_verifier(pkce_verifier);

    // Authorization server validates Verifier & Challenge Codes
    let oauth_token_response = token_request
        .request_async(&async |r| custom_oauth_client("exchange-code", ctx_get_http_client(), r).await)
        .await
        .unwrap();

    use openidconnect::TokenResponse as _;
    oauth_token_response.id_token().unwrap().to_string()
}
