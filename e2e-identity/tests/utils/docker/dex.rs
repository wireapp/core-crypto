use std::{collections::HashMap, net::SocketAddr};

use testcontainers::core::{ContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, Image, ImageExt, core::WaitFor};

use crate::utils::docker::{SHM, ldap::LdapCfg, rand_str};

pub struct DexServer {
    pub uri: String,
    pub node: ContainerAsync<DexImage>,
    pub socket: SocketAddr,
}

#[derive(Debug)]
pub struct DexImage {
    pub volumes: Vec<Mount>,
    pub env_vars: HashMap<String, String>,
    tag: String,
}

impl DexImage {
    const NAME: &'static str = "dexidp/dex";
    const TAG: &'static str = "v2.35.3";
    pub const PORT: ContainerPort = ContainerPort::Tcp(5556);
    const PORTS: &'static [ContainerPort] = &[Self::PORT];

    pub async fn run(cfg: DexCfg, redirect_uri: String) -> DexServer {
        let instance = Self::new(&cfg, &redirect_uri);
        let image = instance
            .with_container_name(&cfg.host)
            .with_network(super::NETWORK)
            .with_mapped_port(cfg.host_port, Self::PORT)
            .with_privileged(true)
            .with_shm_size(SHM);
        let node = image.start().await.unwrap();
        let port = node.get_host_port_ipv4(Self::PORT).await.unwrap();
        let uri = format!("http://{}:{port}", cfg.host);

        let ip = std::net::IpAddr::V4("127.0.0.1".parse().unwrap());
        let socket = SocketAddr::new(ip, port);

        DexServer { uri, socket, node }
    }

    pub fn new(cfg: &DexCfg, redirect_uri: &str) -> Self {
        let host_vol = std::env::temp_dir().join(rand_str());
        std::fs::create_dir(&host_vol).unwrap();
        let host_cfg_file = host_vol.join("config.docker.yaml");

        std::fs::write(&host_cfg_file, cfg.to_yaml(redirect_uri)).unwrap();

        let host_vol_str = host_cfg_file.as_os_str().to_str().unwrap();
        let tag = std::env::var("DEX_VERSION").unwrap_or(Self::TAG.to_string());
        Self {
            volumes: vec![Mount::bind_mount(host_vol_str, "/etc/dex/config.docker.yaml")],
            env_vars: HashMap::new(),
            tag,
        }
    }
}

impl Image for DexImage {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        let msg = format!("listening (http) on 0.0.0.0:{}", Self::PORT);
        vec![WaitFor::message_on_stderr(msg)]
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        &self.volumes
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        Self::PORTS
    }
}

#[derive(Debug, Clone)]
pub struct DexCfg {
    pub client_id: String,
    pub client_secret: String,
    pub issuer: String,
    pub ldap_host: String,
    pub domain: String,
    pub host_port: u16,
    pub host: String,
}

impl DexCfg {
    pub fn to_yaml(&self, redirect_uri: &str) -> String {
        let Self {
            client_id,
            client_secret,
            issuer,
            ldap_host,
            domain,
            ..
        } = self;
        let domain = LdapCfg::domain_to_ldif(domain);
        format!(
            r#"
issuer: {issuer}
storage:
  type: memory
web:
  http: 0.0.0.0:5556
logger:
  level: "debug"
  format: "text"

oauth2:
  skipApprovalScreen: false
  alwaysShowLoginScreen: false

# expiry:
#   deviceRequests: "5m"
#   signingKeys: "6h"
#   idTokens: "24h"
#   refreshTokens:
#     reuseInterval: "3s"
#     validIfNotUsedFor: "2160h" # 90 days
#     absoluteLifetime: "3960h" # 165 days

connectors:
- type: ldap
  name: OpenLDAP
  id: ldap
  config:
    host: {ldap_host}:389
    insecureNoSSL: true
    insecureSkipVerify: true
    bindDN: cn=admin,{domain}
    bindPW: admin
    usernamePrompt: Email Address
    userSearch:
      baseDN: ou=People,{domain}
      filter: "(objectClass=person)"
      username: mail
      idAttr: uid
      emailAttr: mail
      nameAttr: cn
      preferredUsernameAttr: sn
staticClients:
- id: {client_id}
  redirectURIs:
  - '{redirect_uri}'
  name: 'Example App'
  secret: {client_secret}
"#
        )
    }
}
