use base64::prelude::*;
use std::net::SocketAddr;
use std::path::Path;

use serde_json::json;
use testcontainers::core::{CmdWaitFor, ContainerPort, ExecCommand, Mount};
use testcontainers::{runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt};

use crate::utils::docker::{rand_str, NETWORK, SHM};

pub struct AcmeServer {
    pub uri: String,
    pub ca_cert: reqwest::Certificate,
    pub node: ContainerAsync<GenericImage>,
    pub socket: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct CaCfg {
    pub sign_key: String,
    pub issuer: String,
    pub audience: String,
    pub discovery_base_url: String,
    pub dpop_target_uri: Option<String>,
    pub domain: String,
    pub host: String,
}

/// Generates the 'authority' part of the Smallstep
/// ACME server configuration (config/ca.json).
fn generate_authority_config(cfg: &CaCfg) -> serde_json::Value {
    // see https://github.com/wireapp/smallstep-certificates/blob/b6019aeb7ffaae1c978c87760656980162e9b785/helm/values.yaml#L88-L100
    let CaCfg {
        sign_key,
        issuer,
        audience,
        discovery_base_url,
        dpop_target_uri,
        domain,
        ..
    } = cfg;

    let x509_template = serde_json::json!({ "template": leaf_cert_template(&domain) });
    let oidc_template = serde_json::json!({
        "name": "{{ .name }}",
        "preferred_username": "wireapp://%40{{ .preferred_username }}"
    });

    let dpop_target_uri = dpop_target_uri.as_ref().unwrap();
    let b64_sign_key = BASE64_STANDARD.encode(sign_key);
    let transform = serde_json::to_string(&oidc_template).unwrap();

    // TODO: remove RS256 when EcDSA & EdDSA are supported in Dex
    json!({
        "provisioners": [
        {
            "type": "ACME",
            "name": ACME_PROVISIONER,
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

const INTERMEDIATE_CERT_TEMPLATE: &str = r#"
    {
        "subject": "Wire Intermediate CA",
        "keyUsage": ["certSign", "crlSign"],
        "basicConstraints": {
            "isCA": true,
            "maxPathLen": 0
        },
        "nameConstraints": {
            "critical": true,
            "permittedDNSDomains": ["localhost", "stepca"],
            "permittedURIDomains": ["wire.com"]
        }
    }
"#;

pub const ACME_PROVISIONER: &'static str = "wire";
const PORT: ContainerPort = ContainerPort::Tcp(9000);

/// This returns the Smallstep certificate template for leaf certificates, i.e. the ones
/// issued by the intermediate CA.
fn leaf_cert_template(org: &str) -> String {
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

async fn alter_configuration(host_volume: &Path, ca_cfg: &CaCfg) {
    let cfg_file = host_volume.join("config").join("ca.json");
    let cfg_content = std::fs::read_to_string(&cfg_file).unwrap();
    let mut cfg = serde_json::from_str::<serde_json::Value>(&cfg_content).unwrap();
    cfg.as_object_mut()
        .unwrap()
        .insert("authority".to_string(), generate_authority_config(ca_cfg));
    std::fs::write(&cfg_file, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
}

async fn run_command(node: &ContainerAsync<GenericImage>, cmd: &str) {
    let cmd = shlex::split(cmd).unwrap();

    // Note the usage of CmdWaitFor::exit_code here. This is because we want to wait
    // until the command finishes. Otherwise, it could happen that we submit the command
    // to the container, immediately return from this function and start another command
    // that requires the previous command to have completed.
    let cmd = ExecCommand::new(cmd).with_cmd_ready_condition(CmdWaitFor::exit_code(0));
    node.exec(cmd).await.unwrap();
}

pub async fn start_acme_server(ca_cfg: &CaCfg) -> AcmeServer {
    let host_volume = std::env::temp_dir().join(rand_str());
    std::fs::create_dir(&host_volume).unwrap();

    // Prepare the container image. Note that instead of just starting the image as-is, we're
    // overriding the command to be a long sleep, in order to be able to issue commands inside
    // the container, to generate exactly the root & intermediate certificates we need. Otherwise,
    // the CA server would start and automatically generate the PKI & CA configuration that would
    // not suit us. Specifically, the intermediate certificate auto-generated by step-ca would not
    // have the necessary x509 name constraints, which is why we have to use a custom certificate
    // template that includes name constraints.
    let image = GenericImage::new("smallstep/step-ca", "0.27.4")
        .with_exposed_port(PORT)
        .with_container_name(&ca_cfg.host)
        .with_network(NETWORK)
        .with_mount(Mount::bind_mount(host_volume.to_str().unwrap(), "/home/step"))
        .with_shm_size(SHM)
        .with_copy_to(
            "/home/step/intermediate.template",
            INTERMEDIATE_CERT_TEMPLATE.to_string().into_bytes(),
        )
        .with_cmd(["bash", "-c", "sleep 1h"]);

    let node = image.start().await.expect("Error running Step CA image");

    // Generate the root certificate.
    run_command(&node, "bash -c 'dd if=/dev/random bs=1 count=20 | base64 > password'").await;
    run_command(
        &node,
        "step certificate create 'Wire Root CA' root-ca.crt root-ca.key
                            --profile root-ca --password-file password",
    )
    .await;

    // Generate the intermediate certificate. Note that we have to use
    // a template in order to specify name constraints that will apply to
    // certificates issued by the intermediate CA.
    run_command(
        &node,
        "step certificate create 'Wire Intermediate CA' intermediate-ca.crt intermediate-ca.key
                            --template intermediate.template --password-file password --not-after 87600h
                            --ca root-ca.crt --ca-key root-ca.key --ca-password-file password",
    )
    .await;

    // Initialize the CA configuration. Note that we can specify an existing root certificate, but
    // we cannot tell 'step ca' to use an existing intermediate certificate. Because of that, we
    // will need to overwrite the intermediate certificate automatically generated by 'step ca'
    // with the one we just created above.
    let port = PORT.as_u16();
    run_command(
        &node,
        &format!(
            "step ca init --name=Wire --deployment-type=standalone
                            --root root-ca.crt --key root-ca.key --key-password-file password
                            --dns localhost,stepca --address :{port}
                            --provisioner wire
                            --provisioner-password-file password
                            --password-file password"
        ),
    )
    .await;

    // Overwrite the generated intermediate certificate and key with our own.
    run_command(&node, "mv intermediate-ca.crt certs/intermediate_ca.crt").await;
    run_command(&node, "mv intermediate-ca.key secrets/intermediate_ca_key").await;

    // Alter the CA configuration by substituting our provisioner.
    alter_configuration(&host_volume, &ca_cfg).await;

    // We're now ready to start.
    run_command(&node, "bash -c 'step-ca --password-file password &'").await;

    let port = node.get_host_port_ipv4(PORT).await.unwrap();
    let uri = format!("https://{}:{}", &ca_cfg.host, port);
    let ca_cert = ca_cert(&host_volume);
    dbg!(&uri);
    dbg!(&ca_cert);

    let ip = std::net::IpAddr::V4("127.0.0.1".parse().unwrap());
    let socket = SocketAddr::new(ip, port);

    AcmeServer {
        uri,
        ca_cert,
        socket,
        node,
    }
}

fn ca_cert(host_volume: &Path) -> reqwest::Certificate {
    // we need to call step-ca over https so we need to fetch its self-signed CA
    let ca_cert = host_volume.join("certs").join("root_ca.crt");
    let ca_pem = std::fs::read(ca_cert).unwrap();
    reqwest::tls::Certificate::from_pem(ca_pem.as_slice()).expect("Smallstep issued an invalid certificate")
}
