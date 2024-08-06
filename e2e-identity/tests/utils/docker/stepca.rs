use base64::prelude::*;
use std::borrow::Cow;
use std::net::SocketAddr;
use std::{collections::HashMap, path::PathBuf};

use serde_json::json;
use testcontainers::core::{ContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use testcontainers::{core::WaitFor, ContainerAsync, Image, ImageExt};

use crate::utils::docker::{rand_str, NETWORK, SHM};

pub struct AcmeServer {
    pub uri: String,
    pub ca_cert: reqwest::Certificate,
    pub node: ContainerAsync<StepCaImage>,
    pub socket: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct CaCfg {
    pub sign_key: String,
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub discovery_base_url: String,
    pub dpop_target_uri: Option<String>,
    pub x509_template: serde_json::Value,
    pub oidc_template: serde_json::Value,
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
            // jwks_url,
            discovery_base_url,
            dpop_target_uri,
            x509_template,
            oidc_template,
            ..
        } = self;
        let dpop_target_uri = dpop_target_uri.as_ref().unwrap();
        let x509_template = x509_template.clone();
        let b64_sign_key = BASE64_STANDARD.encode(sign_key);
        let transform = serde_json::to_string(oidc_template).unwrap();

        // TODO: remove RS256 when EcDSA & EdDSA are supported in Dex
        json!({
            "provisioners": [
                {
                    "type": "ACME",
                    "name": provisioner,
                    "forceCN": true,
                    "challenges": ["wire-oidc-01", "wire-dpop-01"],
                    "claims": {
                        "disableRenewal": false,
                        "allowRenewalAfterExpiry": false,
                        "minTLSCertDuration": "60s",
                        "maxTLSCertDuration": "87600h",
                        "defaultTLSCertDuration": "87600h"
                    },
                    "options": {
                        "x509": x509_template,
                        "wire": {
                            "oidc": {
                                "provider": {
                                    "issuerUrl": issuer,
                                    "discoveryBaseUrl": discovery_base_url,
                                    "id_token_signing_alg_values_supported": [
                                        "RS256",
                                        "ES256",
                                        "ES384",
                                        "EdDSA"
                                    ]
                                },
                                "config": {
                                    "clientId": audience,
                                    "signatureAlgorithms": [
                                        "RS256",
                                        "ES256",
                                        "ES384",
                                        "EdDSA"
                                    ]
                                },
                                "transform": transform
                            },
                            "dpop": {
                                "key": b64_sign_key,
                                "target": dpop_target_uri
                            }
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
    pub volumes: Vec<Mount>,
    pub env_vars: HashMap<String, String>,
    pub host_volume: PathBuf,
    name: String,
    tag: String,
}

impl StepCaImage {
    // const NAME: &'static str = "smallstep/step-ca";
    const NAME: &'static str = "wire-smallstep-stepca";
    // const TAG: &'static str = "0.25.3-rc3";
    const TAG: &'static str = "latest";
    const CA_NAME: &'static str = "wire";
    pub const ACME_PROVISIONER: &'static str = "wire";
    pub const PORT: ContainerPort = ContainerPort::Tcp(9000);
    const PORTS: &'static [ContainerPort] = &[Self::PORT];

    pub async fn run(ca_cfg: CaCfg) -> AcmeServer {
        // We have to create an ACME provisioner at startup which is done in `exec_after_start`.
        // Since step-ca does not support hot reload of the configuration and we cannot
        // restart the process within the container with testcontainers cli, we will start a first
        // container, do the initialization step, copy the generated configuration then use it to
        // start a second, final one
        let builder_image = Self::new(true, None);
        let host_volume = builder_image.host_volume.clone();

        let builder_image = builder_image
            .with_container_name(format!("{}.builder", ca_cfg.host))
            .with_privileged(true)
            .with_shm_size(SHM);

        let container = builder_image.start().await.expect("Error running Step CA builder");

        // now the configuration should have been generated and mapped to our host volume.
        // We can kill this container
        drop(container);

        let image = Self::new(false, Some(host_volume.clone()));

        // Alter the configuration by adding an ACME provisioner manually, waaaaay simpler than using the cli
        let cfg_file = host_volume.join("config").join("ca.json");
        let cfg_content = std::fs::read_to_string(&cfg_file).unwrap();
        let mut cfg = serde_json::from_str::<serde_json::Value>(&cfg_content).unwrap();
        cfg.as_object_mut()
            .unwrap()
            .insert("authority".to_string(), ca_cfg.cfg());
        std::fs::write(&cfg_file, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

        let image = image
            .with_container_name(&ca_cfg.host)
            .with_network(NETWORK)
            .with_privileged(true)
            .with_shm_size(SHM);
        let node = image.start().await.expect("Error running Step CA image");
        let port = node.get_host_port_ipv4(Self::PORT).await.unwrap();
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
        reqwest::tls::Certificate::from_pem(ca_pem.as_slice()).expect("Smallstep issued an invalid certificate")
    }
}

impl StepCaImage {
    fn new(is_builder: bool, host_volume: Option<PathBuf>) -> Self {
        let host_volume = host_volume.unwrap_or_else(|| std::env::temp_dir().join(rand_str()));
        if !host_volume.exists() {
            std::fs::create_dir(&host_volume).unwrap();
        }
        let host_volume_str = host_volume.as_os_str().to_str().unwrap();
        let tag = std::env::var("STEPCA_VERSION").unwrap_or(Self::TAG.to_string());
        let name = std::env::var("STEPCA_NAME").unwrap_or(Self::NAME.to_string());
        Self {
            is_builder,
            volumes: vec![Mount::bind_mount(host_volume_str, "/home/step")],
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
            tag,
            name,
        }
    }
}

impl Image for StepCaImage {
    fn name(&self) -> &str {
        &self.name
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stderr("Serving HTTPS on :")]
    }

    fn env_vars(&self) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        &self.env_vars
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        &self.volumes
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        Self::PORTS
    }
}
