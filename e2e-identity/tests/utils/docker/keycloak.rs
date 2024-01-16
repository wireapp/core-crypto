use std::{collections::HashMap, env, net::SocketAddr};

use keycloak::{
    types::ProtocolMapperRepresentation,
    types::{ClientRepresentation, CredentialRepresentation, UserRepresentation},
    KeycloakAdmin, KeycloakAdminToken,
};
use serde_json::json;
use testcontainers::{clients::Cli, core::WaitFor, Container, Image, ImageArgs, RunnableImage};

use crate::utils::docker::SHM;

pub struct KeycloakServer<'a> {
    pub http_uri: String,
    pub https_uri: String,
    pub node: Container<'a, KeycloakImage>,
    pub socket: SocketAddr,
}

#[derive(Debug)]
pub struct KeycloakImage {
    pub volumes: HashMap<String, String>,
    pub env_vars: HashMap<String, String>,
}

impl KeycloakImage {
    const NAME: &'static str = "quay.io/keycloak/keycloak";
    const TAG: &'static str = "22.0.5"; // has to match the version of Keycloak crate
    pub const HTTP_PORT: u16 = 8080;
    pub const HTTPS_PORT: u16 = 8443;

    pub const USER: &'static str = "admin";
    pub const PASSWORD: &'static str = "changeme";
    pub const REALM: &'static str = "master";
    pub const LOG_LEVEL: &'static str = "info";

    pub async fn run(docker: &Cli, cfg: KeycloakCfg, redirect_uri: String) -> KeycloakServer {
        let instance = Self::new();
        let image: RunnableImage<Self> = instance.into();
        let image = image
            .with_container_name(&cfg.host)
            .with_network(super::NETWORK)
            .with_mapped_port((cfg.http_host_port, Self::HTTP_PORT))
            .with_mapped_port((cfg.https_host_port, Self::HTTPS_PORT))
            .with_privileged(true)
            .with_shm_size(SHM);
        let node = docker.run(image);

        let http_port = node.get_host_port_ipv4(Self::HTTP_PORT);
        let http_uri = format!("http://{}:{http_port}", cfg.host);

        let https_port = node.get_host_port_ipv4(Self::HTTPS_PORT);
        let https_uri = format!("http://{}:{https_port}", cfg.host);

        let ip = std::net::IpAddr::V4("127.0.0.1".parse().unwrap());
        let socket = SocketAddr::new(ip, http_port);

        Self::configure(http_port, &cfg, &redirect_uri).await;

        KeycloakServer {
            http_uri,
            https_uri,
            socket,
            node,
        }
    }

    pub fn new() -> Self {
        Self {
            volumes: HashMap::new(),
            env_vars: HashMap::from_iter(vec![
                ("KEYCLOAK_ADMIN".to_string(), Self::USER.to_string()),
                ("KEYCLOAK_ADMIN_PASSWORD".to_string(), Self::PASSWORD.to_string()),
                ("KC_LOG_LEVEL".to_string(), Self::LOG_LEVEL.to_string()),
            ]),
        }
    }

    async fn configure(external_port: u16, cfg: &KeycloakCfg, redirect_uri: &str) {
        let url = format!("http://localhost:{external_port}");
        let user = Self::USER.to_string();
        let password = Self::PASSWORD.to_string();
        let client = reqwest::Client::new();
        let admin_token = KeycloakAdminToken::acquire(&url, &user, &password, &client)
            .await
            .unwrap();
        let admin = KeycloakAdmin::new(&url, admin_token, client);

        // Create a User for the test
        let user = cfg.into();
        admin.realm_users_post(Self::REALM, user).await.unwrap();

        // Then create an OAuth public Client (w/o client-secret)
        let client = ClientRepresentation {
            client_id: Some(cfg.oauth_client_id.clone()),
            name: Some("wireapp-oauth-client".to_string()),
            consent_required: Some(false),
            always_display_in_console: Some(true),
            enabled: Some(true),
            implicit_flow_enabled: Some(false),
            standard_flow_enabled: Some(true),
            redirect_uris: Some(vec![redirect_uri.to_string()]),
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
                    e.push(json!("oidc-claims-param-value-idtoken-mapper"));
                });
        }

        admin
            .realm_components_with_id_put(Self::REALM, component_id, component.clone())
            .await
            .unwrap();

        // Now enable the mapper for the scope "profile"
        // First find the scope "profile"
        let scopes = admin.realm_client_scopes_get(Self::REALM).await.unwrap();
        let profile_scope = scopes.iter().find(|s| s.name == Some("profile".to_string())).unwrap();

        // Then register this protocol mapper for this scope
        let scope_id = profile_scope.id.clone().unwrap();
        let keyauth_protocol_mapper = ProtocolMapperRepresentation {
            config: Some(HashMap::from_iter([
                ("claim.name".to_string(), json!("keyauth")),
                ("id.token.claim".to_string(), json!("true")),
            ])),
            name: Some("wire-keyauth-id-token-mapper".to_string()),
            protocol: Some("openid-connect".to_string()),
            protocol_mapper: Some("oidc-claims-param-value-idtoken-mapper".to_string()),
            ..Default::default()
        };
        admin
            .realm_client_scopes_with_id_protocol_mappers_models_post(Self::REALM, &scope_id, keyauth_protocol_mapper)
            .await
            .unwrap();
        let audience_protocol_mapper = ProtocolMapperRepresentation {
            config: Some(HashMap::from_iter([
                ("claim.name".to_string(), json!("acme_aud")),
                ("id.token.claim".to_string(), json!("true")),
            ])),
            name: Some("wire-acme-audience-id-token-mapper".to_string()),
            protocol: Some("openid-connect".to_string()),
            protocol_mapper: Some("oidc-claims-param-value-idtoken-mapper".to_string()),
            ..Default::default()
        };
        admin
            .realm_client_scopes_with_id_protocol_mappers_models_post(Self::REALM, &scope_id, audience_protocol_mapper)
            .await
            .unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct KeycloakCfg {
    pub oauth_client_id: String,
    pub firstname: String,
    pub lastname: String,
    pub username: String,
    pub email: String,
    pub password: String,
    pub host: String,
    pub http_host_port: u16,
    pub https_host_port: u16,
}

impl From<&KeycloakCfg> for UserRepresentation {
    fn from(cfg: &KeycloakCfg) -> Self {
        Self {
            username: Some(cfg.username.clone()),
            email: Some(cfg.email.clone()),
            enabled: Some(true),
            email_verified: Some(true),
            first_name: Some(cfg.firstname.clone()),
            last_name: Some(cfg.lastname.clone()),
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
    type Args = KeycloakArgs;

    fn name(&self) -> String {
        Self::NAME.to_string()
    }

    fn tag(&self) -> String {
        env::var("KEYCLOAK_VERSION").unwrap_or_else(|_| Self::TAG.to_string())
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        let msg = format!("Keycloak {} on JVM", Self::TAG);
        vec![WaitFor::message_on_stdout(msg)]
    }

    fn env_vars(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.env_vars.iter())
    }

    fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.volumes.iter())
    }

    fn expose_ports(&self) -> Vec<u16> {
        vec![KeycloakImage::HTTP_PORT, KeycloakImage::HTTPS_PORT]
    }
}

#[derive(Debug, Default, Clone)]
pub struct KeycloakArgs;

impl ImageArgs for KeycloakArgs {
    fn into_iterator(self) -> Box<dyn Iterator<Item = String>> {
        let options = ["--verbose", "start-dev"].map(str::to_string);
        Box::new(options.into_iter())
    }
}
