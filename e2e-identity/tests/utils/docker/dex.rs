use std::{collections::HashMap, net::SocketAddr};

use testcontainers::{clients::Cli, core::WaitFor, Container, Image, RunnableImage};

use crate::utils::docker::{ldap::LdapCfg, rand_str, SHM};

pub struct DexServer<'a> {
    pub uri: String,
    pub node: Container<'a, DexImage>,
    pub socket: SocketAddr,
}

#[derive(Debug)]
pub struct DexImage {
    pub volumes: HashMap<String, String>,
    pub env_vars: HashMap<String, String>,
}

impl DexImage {
    const NAME: &'static str = "dexidp/dex";
    const TAG: &'static str = "v2.35.3";
    pub const PORT: u16 = 5556;

    pub fn run(docker: &Cli, cfg: DexCfg, redirect_uri: String) -> DexServer {
        let instance = Self::new(&cfg, &redirect_uri);
        let image: RunnableImage<Self> = instance.into();
        let image = image
            .with_container_name(&cfg.host)
            .with_network(super::NETWORK)
            .with_mapped_port((cfg.host_port, Self::PORT))
            .with_privileged(true)
            .with_shm_size(SHM);
        let node = docker.run(image);
        let port = node.get_host_port_ipv4(Self::PORT);
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

        let host_vol_str = host_cfg_file.as_os_str().to_str().unwrap().to_string();
        Self {
            volumes: HashMap::from_iter(vec![(host_vol_str, "/etc/dex/config.docker.yaml".to_string())]),
            env_vars: HashMap::new(),
        }
    }
}

impl Image for DexImage {
    type Args = ();

    fn name(&self) -> String {
        Self::NAME.to_string()
    }

    fn tag(&self) -> String {
        std::env::var("DEX_VERSION").unwrap_or_else(|_| Self::TAG.to_string())
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        let msg = format!("listening (http) on 0.0.0.0:{}", Self::PORT);
        vec![WaitFor::message_on_stderr(msg)]
    }

    fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.volumes.iter())
    }

    fn expose_ports(&self) -> Vec<u16> {
        vec![Self::PORT]
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
