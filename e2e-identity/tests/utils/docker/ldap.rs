use crate::utils::docker::rand_str;
use std::{collections::HashMap, net::SocketAddr};
use testcontainers::{clients::Cli, core::WaitFor, Container, Image, ImageArgs, RunnableImage};

pub struct LdapServer<'a> {
    pub node: Container<'a, LdapImage>,
    pub socket: SocketAddr,
}

#[derive(Debug)]
pub struct LdapImage {
    pub volumes: HashMap<String, String>,
    pub env_vars: HashMap<String, String>,
}

impl LdapImage {
    const NAME: &'static str = "osixia/openldap";
    const TAG: &'static str = "1.5.0";
    pub const PORT: u16 = 389;

    pub fn run(docker: &Cli, cfg: LdapCfg) -> LdapServer<'_> {
        let instance = Self::new(&cfg);
        let image: RunnableImage<Self> = instance.into();
        let image = image.with_container_name(&cfg.host).with_network(super::NETWORK);
        let node = docker.run(image);

        let port = node.get_host_port_ipv4(Self::PORT);
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
        Self {
            volumes: HashMap::from_iter(vec![(host_vol_str, container_vol)]),
            env_vars: HashMap::from_iter(
                vec![("LDAP_TLS_VERIFY_CLIENT", "try"), ("LDAP_DOMAIN", &cfg.domain)]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string())),
            ),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct LdapArgs;

impl ImageArgs for LdapArgs {
    fn into_iterator(self) -> Box<dyn Iterator<Item = String>> {
        Box::new(
            vec![
                "--copy-service".to_string(),
                "--loglevel".to_string(),
                "debug".to_string(),
            ]
            .into_iter(),
        )
    }
}

impl Image for LdapImage {
    type Args = LdapArgs;

    fn name(&self) -> String {
        Self::NAME.to_string()
    }

    fn tag(&self) -> String {
        Self::TAG.to_string()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stderr("slapd starting")]
    }

    fn env_vars(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.env_vars.iter())
    }

    fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.volumes.iter())
    }

    fn expose_ports(&self) -> Vec<u16> {
        vec![Self::PORT]
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
