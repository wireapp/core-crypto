use std::net::SocketAddr;
use std::{collections::HashMap, path::PathBuf};

use serde_json::json;
use testcontainers::{clients::Cli, core::WaitFor, Container, Image, RunnableImage};

use crate::utils::docker::{rand_str, NETWORK};

pub struct AcmeServer<'a> {
    pub uri: String,
    pub ca_cert: reqwest::Certificate,
    pub node: Container<'a, StepCaImage>,
    pub socket: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct CaCfg {
    pub sign_key: String,
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: String,
    pub dpop_target_uri: Option<String>,
    pub template: serde_json::Value,
    pub host: String,
}

impl CaCfg {
    fn cfg(&self) -> serde_json::Value {
        // see https://github.com/wireapp/smallstep-certificates/blob/b6019aeb7ffaae1c978c87760656980162e9b785/helm/values.yaml#L88-L100
        let provisioner = StepCaImage::ACME_PROVISIONER;
        let Self {
            sign_key,
            issuer,
            audience,
            jwks_uri,
            dpop_target_uri,
            template,
            ..
        } = self;
        let dpop_target_uri = dpop_target_uri.as_ref().unwrap();
        let x509 = template.clone();
        // TODO: remove RS256 when EcDSA & EdDSA are supported in Dex
        json!({
            "provisioners": [
                {
                    "type": "ACME",
                    "name": provisioner,
                    "forceCN": true,
                    "claims": {
                        "disableRenewal": false,
                        "allowRenewalAfterExpiry": false,
                        "maxTLSCertDuration": "87600h",
                        "defaultTLSCertDuration": "87600h"
                    },
                    "options": {
                        "oidc": {
                            "provider": {
                                "issuer": issuer,
                                "authorization_endpoint": "https://authorization_endpoint.com",
                                "token_endpoint": "https://token_endpoint.com",
                                "jwks_uri": jwks_uri,
                                "userinfo_endpoint": "https://userinfo_endpoint.com",
                                "id_token_signing_alg_values_supported": [
                                    "RS256",
                                    "ES256",
                                    "ES384",
                                    "EdDSA"
                                ]
                            },
                            "config": {
                                "client-id": audience,
                                "support-signing-algs": [
                                    "RS256",
                                    "ES256",
                                    "ES384",
                                    "EdDSA"
                                ]
                            }
                        },
                        "x509": x509,
                        "dpop": {
                            "key": sign_key,
                            "dpop-target": dpop_target_uri,
                            "validation-exec-path": "/usr/local/bin/rusty-jwt-cli"
                        }
                    }
                }
            ]
        })
    }
}

#[derive(Debug)]
pub struct StepCaImage {
    pub is_builder: bool,
    pub volumes: HashMap<String, String>,
    pub env_vars: HashMap<String, String>,
    pub host_volume: PathBuf,
}

impl StepCaImage {
    const NAME: &'static str = "quay.io/wire/smallstep-acme";
    const TAG: &'static str = "0.0.42-test.85";
    const CA_NAME: &'static str = "wire";
    pub const ACME_PROVISIONER: &'static str = "wire";
    pub const PORT: u16 = 9000;

    pub fn run(docker: &Cli, ca_cfg: CaCfg) -> AcmeServer<'_> {
        // We have to create an ACME provisioner at startup which is done in `exec_after_start`.
        // Since step-ca does not support hot reload of the configuration and we cannot
        // restart the process within the container with testcontainers cli, we will start a first
        // container, do the initialization step, copy the generated configuration then use it to
        // start a second, final one
        let builder = Self::new(true, None);
        let host_volume = builder.host_volume.clone();

        let builder_image: RunnableImage<Self> = builder.into();
        let builder_image = builder_image.with_container_name(format!("{}.builder", ca_cfg.host));
        let builder_container = docker.run(builder_image);
        // now the configuration should have been generated and mapped to our host volume.
        // We can kill this container
        drop(builder_container);

        let image: RunnableImage<Self> = Self::new(false, Some(host_volume.clone())).into();

        // Alter the configuration by adding an ACME provisioner manually, waaaaay simpler than using the cli
        let cfg_file = host_volume.join("config").join("ca.json");
        let cfg_content = std::fs::read_to_string(&cfg_file).unwrap();
        let mut cfg = serde_json::from_str::<serde_json::Value>(&cfg_content).unwrap();
        cfg.as_object_mut()
            .unwrap()
            .insert("authority".to_string(), ca_cfg.cfg());
        std::fs::write(&cfg_file, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

        let image = image.with_container_name(&ca_cfg.host).with_network(NETWORK);
        let node = docker.run(image);
        let port = node.get_host_port_ipv4(Self::PORT);
        let uri = format!("https://{}:{}", &ca_cfg.host, port);
        let ca_cert = Self::ca_cert(host_volume);

        let ip = std::net::IpAddr::V4("127.0.0.1".parse().unwrap());
        let socket = SocketAddr::new(ip, port);

        AcmeServer {
            uri,
            ca_cert,
            socket,
            node,
        }
    }

    pub fn ca_cert(host_volume: PathBuf) -> reqwest::Certificate {
        // we need to call step-ca over https so we need to fetch its self-signed CA
        let ca_cert = host_volume.join("certs").join("root_ca.crt");
        let ca_pem = std::fs::read(ca_cert).unwrap();
        reqwest::tls::Certificate::from_pem(ca_pem.as_slice()).expect("SmallStep issued an invalid certificate")
    }
}

impl StepCaImage {
    fn new(is_builder: bool, host_volume: Option<PathBuf>) -> Self {
        let host_volume = host_volume.unwrap_or_else(|| std::env::temp_dir().join(rand_str()));
        if !host_volume.exists() {
            std::fs::create_dir(&host_volume).unwrap();
        }
        let host_volume_str = host_volume.as_os_str().to_str().unwrap();
        Self {
            is_builder,
            volumes: HashMap::from_iter(vec![(host_volume_str.to_string(), "/home/step".to_string())]),
            env_vars: HashMap::from_iter(
                vec![
                    ("DOCKER_STEPCA_INIT_PROVISIONER_NAME", Self::CA_NAME),
                    ("DOCKER_STEPCA_INIT_NAME", Self::CA_NAME),
                    ("DOCKER_STEPCA_INIT_DNS_NAMES", "localhost,$(hostname -f)"),
                    ("DOCKER_STEPCA_INIT_ACME", "true"),
                    ("DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT", "true"),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string())),
            ),
            host_volume,
        }
    }
}

impl Image for StepCaImage {
    type Args = ();

    fn name(&self) -> String {
        Self::NAME.to_string()
    }

    fn tag(&self) -> String {
        Self::TAG.to_string()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stderr("Serving HTTPS on :")]
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
