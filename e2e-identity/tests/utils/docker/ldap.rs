use crate::utils::docker::{rand_str, SHM};
use std::borrow::Cow;
use std::{collections::HashMap, net::SocketAddr};
use testcontainers::core::{ContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use testcontainers::{core::WaitFor, ContainerAsync, Image, ImageExt};

pub struct LdapServer {
    pub node: ContainerAsync<LdapImage>,
    pub socket: SocketAddr,
}

#[derive(Debug)]
pub struct LdapImage {
    pub volumes: Vec<Mount>,
    pub env_vars: HashMap<String, String>,
    tag: String,
}

impl LdapImage {
    const NAME: &'static str = "osixia/openldap";
    const TAG: &'static str = "1.5.0";
    pub const PORT: ContainerPort = ContainerPort::Tcp(389);
    const PORTS: &'static [ContainerPort] = &[Self::PORT];

    pub async fn run(cfg: LdapCfg) -> LdapServer {
        let instance = Self::new(&cfg);
        let image = instance
            .with_container_name(&cfg.host)
            .with_network(super::NETWORK)
            .with_privileged(true)
            .with_shm_size(SHM);
        let node = image.start().await.unwrap();

        let port = node.get_host_port_ipv4(Self::PORT).await.unwrap();
        let ip = std::net::IpAddr::V4("127.0.0.1".parse().unwrap());
        let socket = SocketAddr::new(ip, port);

        LdapServer { node, socket }
    }

    pub fn new(cfg: &LdapCfg) -> Self {
        let host_vol = std::env::temp_dir().join(rand_str());
        std::fs::create_dir(&host_vol).unwrap();
        let cfg_file = host_vol.join("config-ldap.ldif");

        std::fs::write(cfg_file, cfg.to_ldif()).unwrap();

        let host_vol_str = host_vol.as_os_str().to_str().unwrap().to_string();
        let container_vol = "/container/service/slapd/assets/config/bootstrap/ldif/custom/".to_string();
        let host_vol_str = host_vol.as_os_str().to_str().unwrap();
        let container_vol = "/container/service/slapd/assets/config/bootstrap/ldif/custom/";
        Self {
            volumes: vec![Mount::bind_mount(host_vol_str, container_vol)],
            env_vars: HashMap::from_iter(
                vec![("LDAP_TLS_VERIFY_CLIENT", "try"), ("LDAP_DOMAIN", &cfg.domain)]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string())),
            ),
        }
    }
}

impl Image for LdapImage {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stderr("slapd starting")]
    }

    fn env_vars(&self) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        &self.env_vars
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        &self.volumes
    }

    fn cmd(&self) -> impl IntoIterator<Item = impl Into<Cow<'_, str>>> {
        vec![
            "--copy-service".to_string(),
            "--loglevel".to_string(),
            "debug".to_string(),
        ]
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        Self::PORTS
    }
}

#[derive(Debug, Clone)]
pub struct LdapCfg {
    pub display_name: String,
    pub handle: String,
    pub email: String,
    pub password: String,
    pub sub: String,
    pub domain: String,
    pub host: String,
}

impl LdapCfg {
    pub fn to_ldif(&self) -> String {
        let domain = Self::domain_to_ldif(&self.domain);
        let Self {
            display_name,
            handle,
            email,
            password,
            sub,
            ..
        } = self;
        format!(
            r#"
dn: ou=People,{domain}
objectClass: organizationalUnit
ou: People

dn: cn={email},ou=People,{domain}
objectClass: person
objectClass: inetOrgPerson
sn: {display_name}
uid: {sub}
cn: {handle}
mail: {email}
userpassword: {password}
"#
        )
    }

    pub fn domain_to_ldif(domain: &str) -> String {
        domain
            .split('.')
            .map(|p| format!("dc={p}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}
