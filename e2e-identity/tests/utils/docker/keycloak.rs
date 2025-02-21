use std::borrow::Cow;
use std::process::Command;
use std::sync::OnceLock;
use std::{collections::HashMap, env, net::SocketAddr};

use keycloak::{
    KeycloakAdmin, KeycloakAdminToken,
    types::ProtocolMapperRepresentation,
    types::{ClientRepresentation, CredentialRepresentation, UserRepresentation},
};

use testcontainers::core::{ContainerPort, IntoContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, Image, ImageExt, core::WaitFor};

use crate::utils::docker::SHM;

pub struct KeycloakServer {
    pub http_uri: String,
    pub node: ContainerAsync<KeycloakImage>,
    pub socket: SocketAddr,
}

#[derive(Debug)]
pub struct KeycloakImage {
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
    const VERSION: &'static str = "26.0.1";

    pub const USER: &'static str = "admin";
    pub const PASSWORD: &'static str = "changeme";
    pub const REALM: &'static str = "master";
    pub const LOG_LEVEL: &'static str = "info";

    pub async fn run(cfg: KeycloakCfg, redirect_uri: String) -> KeycloakServer {
        Self::build(cfg.http_host_port.to_string());
        let instance = Self::new(cfg.http_host_port.tcp());
        let image = instance
            .with_container_name(&cfg.host)
            .with_network(super::NETWORK)
            .with_mapped_port(cfg.http_host_port, cfg.http_host_port.tcp())
            .with_privileged(true)
            .with_shm_size(SHM);
        let node = image.start().await.unwrap();

        let http_port = node.get_host_port_ipv4(cfg.http_host_port).await.unwrap();
        let http_uri = format!("http://{}:{http_port}", cfg.host);

        let ip = std::net::IpAddr::V4("127.0.0.1".parse().unwrap());
        let socket = SocketAddr::new(ip, http_port);

        Self::configure(http_port, &cfg, &redirect_uri).await;

        KeycloakServer { http_uri, socket, node }
    }

    fn build(port: String) {
        let cwd = env::var("CARGO_MANIFEST_DIR").unwrap();
        Command::new("docker")
            .args(["image", "rm", &format!("{}:{}", Self::NAME, Self::TAG)])
            .output()
            .unwrap();

        let build_args = &[
            "build",
            "--file",
            &format!("{cwd}/tests/utils/docker/keycloak/Dockerfile"),
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

    pub fn new(host_port: ContainerPort) -> Self {
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
                    e.push("oidc-claims-param-value-idtoken-mapper".to_string());
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
                ("claim.name".to_string(), "keyauth".to_string()),
                ("id.token.claim".to_string(), "true".to_string()),
            ])),
            name: Some("wire-keyauth-id-token-mapper".to_string()),
            protocol: Some("openid-connect".to_string()),
            protocol_mapper: Some("oidc-claims-param-value-idtoken-mapper".to_string()),
            ..Default::default()
        };
        admin
            .realm_client_scopes_with_client_scope_id_protocol_mappers_models_post(
                Self::REALM,
                &scope_id,
                keyauth_protocol_mapper,
            )
            .await
            .unwrap();
        let audience_protocol_mapper = ProtocolMapperRepresentation {
            config: Some(HashMap::from_iter([
                ("claim.name".to_string(), "acme_aud".to_string()),
                ("id.token.claim".to_string(), "true".to_string()),
            ])),
            name: Some("wire-acme-audience-id-token-mapper".to_string()),
            protocol: Some("openid-connect".to_string()),
            protocol_mapper: Some("oidc-claims-param-value-idtoken-mapper".to_string()),
            ..Default::default()
        };
        admin
            .realm_client_scopes_with_client_scope_id_protocol_mappers_models_post(
                Self::REALM,
                &scope_id,
                audience_protocol_mapper,
            )
            .await
            .unwrap();

        // Create the client profile to attach the executor
        const EXECUTOR_NAME: &str = "wire-e2ei-claims-refresh";
        const CLIENT_PROFILE_NAME: &str = "wire-e2ei-claims-refresh-client-profile";
        let executor = keycloak::types::ClientPolicyExecutorRepresentation {
            configuration: Some(Default::default()),
            executor: Some(EXECUTOR_NAME.to_string()),
        };
        let client_profile = keycloak::types::ClientProfileRepresentation {
            name: Some(CLIENT_PROFILE_NAME.to_string()),
            description: Some("TODO".to_string()),
            executors: Some(vec![executor]),
        };
        let client_profiles = keycloak::types::ClientProfilesRepresentation {
            global_profiles: None,
            profiles: Some(vec![client_profile]),
        };
        admin
            .realm_client_policies_profiles_put(Self::REALM, client_profiles)
            .await
            .unwrap();

        let condition = keycloak::types::ClientPolicyConditionRepresentation {
            condition: Some("any-client".to_string()),
            configuration: Some(Default::default()),
        };

        let client_policy = keycloak::types::ClientPolicyRepresentation {
            name: Some(format!("{EXECUTOR_NAME}-client-profile")),
            conditions: Some(vec![condition]),
            description: Some("TODO".to_string()),
            enabled: Some(true),
            profiles: Some(vec![CLIENT_PROFILE_NAME.to_string()]),
        };
        let client_policies = keycloak::types::ClientPoliciesRepresentation {
            policies: Some(vec![client_policy]),
            global_policies: None,
        };
        admin
            .realm_client_policies_policies_put(Self::REALM, client_policies)
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
