//! This module contains end-to-end tests that exercise different interactions in the
//! process of getting an X.509 certificate.
//!
//! Prerequisites:
//! - Docker
//! - a running test-wire-server instance, pointed at by the TEST_WIRE_SERVER_ADDR environment variable
//! - a configured IdP to use, via the TEST_IDP environment variable (currently supported: `keycloak`, `authelia`)
//!
//! An instance of the chosen IdP will be started automatically, but it will not be shut down
//! automatically.
//!
//! While test-wire-server runs as a regular process, the IdP instances and the ACME server
//! implementation, step-ca, run inside their own containers.
//!
//! During tests, containers are reachable via hostnames such as `keycloak`, `authelia.local` etc.,
//! however this does not actually rely or any OS or container networking facilities, but rather on
//! the manual mapping of host names to addresses (see `E2eTest::start` and the `utils/ctx.rs`
//! module).

// This file contains test mappings to automatically generate various reports for Zulu.
// They are marked with @SF and similar.
// DO NOT REMOVE OR CHANGE THESE OR THE TESTS WITHOUT TALKING TO SECURITY FIRST!

#![cfg(not(target_os = "unknown"))]

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use core_crypto_keystore::{ConnectionType, Database, DatabaseKey};
use jwt_simple::prelude::*;
use rstest::rstest;
use rusty_jwt_tools::prelude::*;
use utils::{
    TestEnvironment, WireServer,
    ctx::ctx_store_http_client,
    hooks::TestPkiEnvironmentHooks,
    idp::{IdpServer, OidcProvider, start_idp_server},
    rand_client_id, rand_str,
    stepca::CaCfg,
};
use wire_e2e_identity::{
    X509CredentialAcquisition, acquisition::X509CredentialConfiguration, pki_env::PkiEnvironment,
    x509_check::extract_crl_uris,
};
use x509_cert::{crl::CertificateList, der::Decode as _};

#[path = "utils/mod.rs"]
mod utils;

fn get_wire_server() -> WireServer {
    // We require that test-wire-server is listening on an endpoint
    // specified by TEST_WIRE_SERVER_ADDR, e.g. "127.0.0.1:1234".
    let addr = std::env::var("TEST_WIRE_SERVER_ADDR")
        .expect("TEST_WIRE_SERVER_ADDR must be set and point to a running test-wire-server")
        .parse()
        .unwrap();

    // We place the Wire server under the `.localhost` domain so that Authelia
    // doesn't complain about us using HTTP for the OAUTH redirect URL.
    WireServer {
        hostname: "wire.localhost".to_string(),
        addr,
    }
}

fn setup_test_environment() -> TestEnvironment {
    // It's fine if the logger was already initialized.
    let _ = env_logger::try_init();

    let run_id = std::env::var("NEXTEST_RUN_ID").expect("NEXTEST_RUN_ID must be defined");
    let mut path = std::env::temp_dir();
    path.push(run_id);

    let provider = std::env::var("TEST_IDP").expect("TEST_IDP must be defined");
    let provider = match provider.as_ref() {
        "authelia" => OidcProvider::Authelia,
        "keycloak" => OidcProvider::Keycloak,
        _ => panic!("unexpected OIDC provider: {provider}"),
    };

    let wire_server = get_wire_server();
    match std::fs::File::create_new(&path) {
        Ok(file) => {
            // We're the first, so it's up to us to start all servers.
            let env = std::thread::spawn(move || {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    let idp_server =
                        start_idp_server(provider, &wire_server.hostname, &wire_server.oauth_redirect_uri()).await;
                    TestEnvironment {
                        wire_server,
                        idp_server,
                    }
                })
            })
            .join()
            .unwrap();

            serde_json::to_writer_pretty(file, &env.idp_server).unwrap();
            env
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Some other test came first so now we just need to read the test environment
            // data. Note that it may take a while (~30s) between the moment file is created
            // and the moment data is available, so we need to wait until we can successfully
            // get the data.
            loop {
                let file = std::fs::File::open(&path).unwrap();
                let idp_server: IdpServer = match serde_json::from_reader(file) {
                    Ok(env) => env,
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        continue;
                    }
                };
                return TestEnvironment {
                    wire_server,
                    idp_server,
                };
            }
        }
        Err(e) => panic!("unexpected error: {:?}", e),
    }
}

#[rstest::fixture]
fn test_env() -> TestEnvironment {
    setup_test_environment()
}

async fn prepare_pki_env_and_config(
    test_env: &TestEnvironment,
    sign_alg: JwsAlgorithm,
) -> (PkiEnvironment, X509CredentialConfiguration) {
    let wire_server_keypair = wire_e2e_identity::utils::generate_key(sign_alg).unwrap();
    let template = r#"{{.DeviceID}}"#;
    let wire_server_uri = test_env.wire_server.uri();
    let dpop_target_uri = format!("{wire_server_uri}/clients/{template}/access-token");
    let issuer = test_env.idp_server.issuer.clone();
    let discovery_base_url = test_env.idp_server.discovery_base_url.clone();

    let wire_server_pubkey = match sign_alg {
        JwsAlgorithm::P256 => ES256KeyPair::from_pem(&wire_server_keypair)
            .unwrap()
            .public_key()
            .to_pem()
            .unwrap(),
        JwsAlgorithm::P384 => ES384KeyPair::from_pem(&wire_server_keypair)
            .unwrap()
            .public_key()
            .to_pem()
            .unwrap(),
        JwsAlgorithm::P521 => ES512KeyPair::from_pem(&wire_server_keypair)
            .unwrap()
            .public_key()
            .to_pem()
            .unwrap(),
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(&wire_server_keypair)
            .unwrap()
            .public_key()
            .to_pem(),
    };

    let ca_cfg = CaCfg {
        sign_key: wire_server_pubkey.to_string(),
        issuer,
        audience: "wireapp".to_string(),
        discovery_base_url,
        dpop_target_uri: Some(dpop_target_uri),
        domain: "wire.localhost".to_string(),
        host: format!("{}.stepca", rand_str(6).to_lowercase()),
    };

    let acme = utils::stepca::start_acme_server(&ca_cfg).await;
    let acme_url = acme.socket.to_string();

    // configure DNS mappings
    let mut dns_mappings = HashMap::<String, SocketAddr>::new();
    dns_mappings.insert(ca_cfg.host.clone(), acme.socket);
    dns_mappings.insert(test_env.wire_server.hostname.clone(), test_env.wire_server.addr);
    dns_mappings.insert(test_env.idp_server.hostname.clone(), test_env.idp_server.addr);

    ctx_store_http_client(&dns_mappings);

    let client_id = rand_client_id();
    let device_id = format!("{:x}", client_id.device_id);

    let config = X509CredentialConfiguration {
        acme_url,
        idp_url: test_env.idp_server.discovery_base_url.clone(),
        sign_alg,
        hash_alg: HashAlgorithm::SHA256,
        display_name: "Alice Smith".into(),
        handle: "alice_wire".into(),
        client_id: client_id.clone(),
        team: Some("team".into()),
        validity_period: std::time::Duration::from_hours(1),
    };
    let wire_server_context = serde_json::json!({
        "client-id": client_id.to_uri(),
        "backend-kp": wire_server_keypair,
        "hash-alg": config.hash_alg.to_string(),
        "wire-server-uri": format!("{wire_server_uri}/clients/{}/access-token", device_id),
        "handle": Handle::from(config.handle.clone()).try_to_qualified(&client_id.domain).unwrap(),
        "display_name": config.display_name,
        "team": config.team.as_ref().unwrap(),
    });

    let wire_server = test_env.wire_server.clone();
    let idp_server = test_env.idp_server.clone();
    let hooks = Arc::new(TestPkiEnvironmentHooks {
        acme,
        wire_server,
        idp_server,
        device_id,
        wire_server_context,
    });

    let db = Database::open(ConnectionType::InMemory, &DatabaseKey::generate())
        .await
        .unwrap();

    let pki_env = PkiEnvironment::new(hooks, db).await.unwrap();
    (pki_env, config)
}

// This test checks that certificate acquisition works for all key types
// (Ed25519, P256, P384, P521). For each key type, a comprehensive set of
// checks is done, including:
// - a check that the key type in the leaf certificate matches what was requested
// - a check that the key usage in the leaf certificate is signing only
// - a check that the intermediate CA cert has expected name constraints
// - a check that all certificates in the chain parse successfully
//
// @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
#[tokio::test]
#[rstest]
#[case(JwsAlgorithm::P256)]
#[case(JwsAlgorithm::P384)]
#[case(JwsAlgorithm::P521)]
#[case(JwsAlgorithm::Ed25519)]
async fn x509_cert_acquisition_works(test_env: TestEnvironment, #[case] sign_alg: JwsAlgorithm) {
    let (pki_env, config) = prepare_pki_env_and_config(&test_env, sign_alg).await;
    let acq = X509CredentialAcquisition::try_new(Arc::new(pki_env), config).unwrap();
    let (_sign_kp, _certs) = acq
        .complete_dpop_challenge()
        .await
        .unwrap()
        .complete_oidc_challenge()
        .await
        .unwrap();
}

#[tokio::test]
#[rstest]
#[case(JwsAlgorithm::P256)]
#[case(JwsAlgorithm::P384)]
#[case(JwsAlgorithm::P521)]
#[case(JwsAlgorithm::Ed25519)]
async fn fetching_crls_works(test_env: TestEnvironment, #[case] sign_alg: JwsAlgorithm) {
    let (pki_env, config) = prepare_pki_env_and_config(&test_env, sign_alg).await;
    let acq = X509CredentialAcquisition::try_new(Arc::new(pki_env.clone()), config).unwrap();
    let (_sign_kp, certs) = acq
        .complete_dpop_challenge()
        .await
        .unwrap()
        .complete_oidc_challenge()
        .await
        .unwrap();

    let crl_uris: HashSet<String> = certs
        .iter()
        .map(|cert| x509_cert::Certificate::from_der(cert).expect("certificate in chain parses"))
        .filter_map(|cert| extract_crl_uris(&cert).expect("CRL distribution points can be extracted"))
        .flatten()
        .collect();

    assert!(
        !crl_uris.is_empty(),
        "issued certificate chain should advertise at least one CRL"
    );

    let result = pki_env
        .fetch_crls(crl_uris.iter().map(String::as_str))
        .await
        .expect("fetched CRL URLs");

    assert_eq!(result.len(), crl_uris.len(), "each advertised CRL should be fetched");
    assert_eq!(
        result.keys().cloned().collect::<HashSet<_>>(),
        crl_uris,
        "fetched CRLs should match the advertised distribution points",
    );

    for crl_der in result.values() {
        assert!(!crl_der.is_empty(), "fetched CRL should not be empty");
        let _ = CertificateList::from_der(crl_der).expect("fetched body is a valid DER CRL");
    }
}

// @SF.PROVISIONING @TSFI.ACME
// TODO: ignore this test for now, until the relevant PKI environment checks are in place
#[ignore]
#[rstest]
#[tokio::test]
async fn should_fail_when_certificate_path_doesnt_contain_trust_anchor(test_env: TestEnvironment) {
    let (pki_env, config) = prepare_pki_env_and_config(&test_env, JwsAlgorithm::P256).await;
    let acq = X509CredentialAcquisition::try_new(Arc::new(pki_env), config).unwrap();
    let result = acq
        .complete_dpop_challenge()
        .await
        .unwrap()
        .complete_oidc_challenge()
        .await;
    assert!(result.is_err());
}
