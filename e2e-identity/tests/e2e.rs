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

#![cfg(not(target_family = "wasm"))]

use jwt_simple::prelude::*;
use rstest::rstest;
use rusty_jwt_tools::prelude::*;
use utils::{
    TestError,
    cfg::{E2eTest, EnrollmentFlow, TestEnvironment, WireServer},
    idp::{IdpServer, OidcProvider, start_idp_server},
    rand_base64_str, rand_client_id,
    stepca::CaCfg,
};
use wire_e2e_identity::acme::prelude::*;

#[path = "utils/mod.rs"]
mod utils;

/// Tests the nominal case and prints the pretty output with the mermaid chart in this crate README.
#[cfg(not(ci))]
#[rstest]
#[tokio::test]
async fn demo_should_succeed(test_env: TestEnvironment) {
    let test = E2eTest::new_demo(test_env).start().await;
    test.nominal_enrollment().await.unwrap();
}

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

/// Verify that it works for all MLS ciphersuites
mod alg {
    use super::*;

    // This and the following tests in this module test nominal enrollment with various key types
    // (Ed25519, P256, P384, P521). For each key type, a comprehensive set of checks is done,
    // including:
    // - a check that the key type in the leaf certificate matches what was requested
    // - a check that the key usage in the leaf certificate is signing only
    // - a check that the intermediate CA cert has expected name constraints
    // - a check that all certificates in the chain parse successfully
    // - a check that invokes `openssl verify` to verify the entire certificate chain
    //
    // @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
    #[rstest]
    #[tokio::test]
    async fn ed25519_should_succeed(test_env: TestEnvironment) {
        let test = E2eTest::new_internal(false, JwsAlgorithm::Ed25519, test_env)
            .start()
            .await;
        assert!(test.nominal_enrollment().await.is_ok());
    }

    // @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
    #[rstest]
    #[tokio::test]
    async fn p256_should_succeed(test_env: TestEnvironment) {
        let test = E2eTest::new_internal(false, JwsAlgorithm::P256, test_env).start().await;
        assert!(test.nominal_enrollment().await.is_ok());
    }

    // @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
    #[rstest]
    #[tokio::test]
    async fn p384_should_succeed(test_env: TestEnvironment) {
        let test = E2eTest::new_internal(false, JwsAlgorithm::P384, test_env).start().await;
        assert!(test.nominal_enrollment().await.is_ok());
    }

    // @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
    #[rstest]
    #[tokio::test]
    async fn p521_should_succeed(test_env: TestEnvironment) {
        let test = E2eTest::new_internal(false, JwsAlgorithm::P521, test_env).start().await;
        assert!(test.nominal_enrollment().await.is_ok());
    }
}

/// Since the acme server is a fork, verify its invariants are respected
mod acme_server {
    use wire_e2e_identity::acme::prelude::x509::{
        RustyX509CheckError,
        reexports::{certval, certval::PathValidationStatus},
        revocation::{PkiEnvironment, PkiEnvironmentParams},
    };
    use x509_cert::der::Decode;

    use super::*;

    #[rstest]
    #[tokio::test]
    /// Acme server has been man-in-middle:ed and returns untrusted certificates
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_certificate_path_doesnt_contain_trust_anchor(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            get_x509_certificates: Box::new(|mut test, (account, finalize, order, previous_nonce)| {
                Box::pin(async move {
                    let root_ca_pem = "-----BEGIN CERTIFICATE-----\n\
                                            MIIBjzCCATWgAwIBAgIQdHdgbnBWCOcqt0xfERAGSzAKBggqhkjOPQQDAjAmMQ0w\n\
                                            CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMjI2MDkz\n\
                                            NDM1WhcNMzQwMjIzMDkzNDM1WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3\n\
                                            aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATWsFsKwcSDoc+n\n\
                                            TXX9DO6f+Nb7gtIVSKtQl2xSJDvpNpdeYUZjg6nc8GeYNUKLqnJPIQAdj9JGLnw4\n\
                                            Why9AK8Co0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd\n\
                                            BgNVHQ4EFgQUphlmx0pZ/MHL67QV0pA7hF/TjekwCgYIKoZIzj0EAwIDSAAwRQIg\n\
                                            Bx8ho/AKTivBDXNS3nmjzTKiTkqoJgbm1DxvPGlAaZ8CIQDHucaxDKCkYxkwMOJN\n\
                                            AThK4U8jq2OyiecPruKv0Cj16Q==\n\
                                            -----END CERTIFICATE-----";
                    let root_ca = PkiEnvironment::decode_pem_cert(root_ca_pem.to_string());
                    let root_ca_der = PkiEnvironment::encode_cert_to_der(&root_ca.unwrap()).unwrap();
                    let trust_anchor = x509_cert::Certificate::from_der(&root_ca_der)
                        .map(x509_cert::anchor::TrustAnchorChoice::Certificate)
                        .unwrap();
                    let trust_roots = vec![trust_anchor];
                    let params = PkiEnvironmentParams {
                        trust_roots: &trust_roots,
                        intermediates: &[],
                        crls: &[],
                        time_of_interest: None,
                    };
                    let env = PkiEnvironment::init(params).unwrap();
                    test.get_x509_certificates(account, finalize, order, previous_nonce, Some(&env))
                        .await?;
                    Ok((test, ()))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::X509CheckError(RustyX509CheckError::CertValError(
                certval::Error::PathValidation(PathValidationStatus::NoPathsFound)
            )))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// Challenges returned by ACME server are mixed up
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_no_replay_nonce_requested(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            get_acme_nonce: Box::new(|test, _| {
                Box::pin(async move {
                    // this replay nonce has not been generated by the acme server
                    let unknown_replay_nonce = rand_base64_str(42);
                    Ok((test, unknown_replay_nonce))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::AccountCreationError
        ));
    }

    #[rstest]
    #[tokio::test]
    /// Replay nonce is reused by the client
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_replay_nonce_reused(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            new_order: Box::new(|mut test, (directory, account, previous_nonce)| {
                Box::pin(async move {
                    // same nonce is used for both 'new_order' & 'new_authz'
                    let (order, order_url, _previous_nonce) =
                        test.new_order(&directory, &account, previous_nonce.clone()).await?;
                    let (_, _, previous_nonce) =
                        test.new_authorization(&account, order.clone(), previous_nonce).await?;
                    Ok((test, (order, order_url, previous_nonce)))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::AuthzCreationError
        ));
    }

    /// Since this call a custom method on our acme server fork, verify we satisfy the invariant:
    /// request payloads must be signed by the same client key which created the acme account.
    #[rstest]
    #[tokio::test]
    /// This verifies the DPoP challenge verification method on the acme server
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_dpop_challenge_signed_by_a_different_key(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            verify_dpop_challenge: Box::new(|mut test, (account, dpop_chall, access_token, previous_nonce)| {
                Box::pin(async move {
                    let old_kp = test.acme_kp;
                    // use another key just for signing this request
                    test.acme_kp = Ed25519KeyPair::generate().to_pem().into();
                    let previous_nonce = test
                        .verify_dpop_challenge(&account, dpop_chall, access_token, previous_nonce)
                        .await?;
                    test.acme_kp = old_kp;
                    Ok((test, previous_nonce))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::DpopChallengeError
        ));
    }

    /// Since this call a custom method on our acme server fork, verify we satisfy the invariant:
    /// request payloads must be signed by the same client key which created the acme account.
    #[rstest]
    #[tokio::test]
    /// This verifies the DPoP challenge verification method on the acme server
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_oidc_challenge_signed_by_a_different_key(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            verify_oidc_challenge: Box::new(|mut test, (account, oidc_chall, access_token, previous_nonce)| {
                Box::pin(async move {
                    let old_kp = test.acme_kp;
                    // use another key just for signing this request
                    test.acme_kp = Ed25519KeyPair::generate().to_pem().into();
                    let previous_nonce = test
                        .verify_oidc_challenge(&account, oidc_chall, access_token, previous_nonce)
                        .await?;
                    test.acme_kp = old_kp;
                    Ok((test, previous_nonce))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::OidcChallengeError
        ));
    }
}

mod dpop_challenge {
    use super::*;

    #[rstest]
    #[tokio::test]
    /// Demonstrates that the client possesses the clientId. Client makes an authenticated request
    /// to wire-server, it delivers a nonce which the client seals in a signed DPoP JWT.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_client_dpop_token_has_wrong_backend_nonce(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(
                |mut test, (dpop_chall, backend_nonce, handle, team, display_name, expiry)| {
                    Box::pin(async move {
                        // use a different nonce than the supplied one
                        let wrong_nonce = rand_base64_str(32).into();
                        assert_ne!(wrong_nonce, backend_nonce);

                        let client_dpop_token = test
                            .create_dpop_token(&dpop_chall, wrong_nonce, handle, team, display_name, expiry)
                            .await?;
                        Ok((test, client_dpop_token))
                    })
                },
            ),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::WireServerError
        ));
    }

    #[rstest]
    #[tokio::test]
    /// Acme server should be configured with wire-server public key to verify the access tokens
    /// issued by wire-server.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_not_signed_by_wire_server(test_env: TestEnvironment) {
        let default = E2eTest::new(test_env);
        let wrong_backend_kp = Ed25519KeyPair::generate();
        let test = E2eTest {
            ca_cfg: CaCfg {
                sign_key: wrong_backend_kp.public_key().to_pem(),
                ..default.ca_cfg
            },
            ..default
        };
        let test = test.start().await;
        assert!(matches!(
            test.nominal_enrollment().await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// The access token has a 'chal' claim which should match the Acme challenge 'token'. This is verified by the acme
    /// server
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_challenge_claim_is_not_current_challenge_one(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(
                |mut test, (dpop_chall, backend_nonce, handle, team, display_name, expiry)| {
                    Box::pin(async move {
                        // alter the 'token' of the valid challenge
                        let wrong_dpop_chall = AcmeChallenge {
                            token: rand_base64_str(32),
                            ..dpop_chall
                        };
                        let client_dpop_token = test
                            .create_dpop_token(&wrong_dpop_chall, backend_nonce, handle, team, display_name, expiry)
                            .await?;
                        Ok((test, client_dpop_token))
                    })
                },
            ),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// We first set a clientId for the enrollment process when we create the acme order. This same
    /// clientId must be used and sealed in the accessToken which is verified by the acme server in
    /// the oidc challenge. The challenge should be invalid if they differ
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_client_id_mismatches(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            new_order: Box::new(|mut test, (directory, account, previous_nonce)| {
                Box::pin(async move {
                    // just alter the clientId for the order creation...
                    let sub = test.sub.clone();
                    test.sub = rand_client_id(Some(sub.device_id));
                    let (order, order_url, previous_nonce) =
                        test.new_order(&directory, &account, previous_nonce).await?;
                    // ...then resume to the regular one to create the client dpop token & access token
                    test.sub = sub;
                    Ok((test, (order, order_url, previous_nonce)))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// In order to tie DPoP challenge verification on the acme server, the latter is configured
    /// with the accepted wire-server host which is present in the DPoP "htu" claim and in the access token
    /// "iss" claim.
    /// The challenge should fail if any of those does not match the expected value
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_iss_mismatches_target(test_env: TestEnvironment) {
        // "iss" in access token mismatches expected target
        let test = E2eTest::new(test_env).start().await;

        let nonce_arc = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (nonce_w, nonce_r) = (nonce_arc.clone(), nonce_arc.clone());

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(|mut test, (dpop_chall, nonce, handle, team, display_name, expiry)| {
                Box::pin(async move {
                    *nonce_w.lock().unwrap() = Some(nonce.clone());
                    let client_dpop_token = test
                        .create_dpop_token(&dpop_chall, nonce, handle, team, display_name, expiry)
                        .await?;
                    Ok((test, client_dpop_token))
                })
            }),
            get_access_token: Box::new(|test, (dpop_chall, _)| {
                Box::pin(async move {
                    let client_id = test.sub.clone();
                    let display_name = test.display_name.clone();
                    let htu: Htu = "https://unknown.io".try_into().unwrap();
                    let backend_nonce: BackendNonce = nonce_r.lock().unwrap().clone().unwrap();
                    let acme_nonce: AcmeNonce = dpop_chall.token.as_str().into();
                    let handle = Handle::from(test.handle.as_str())
                        .try_to_qualified(&client_id.domain)
                        .unwrap();
                    let audience = dpop_chall.url.clone();

                    let client_dpop_token = RustyJwtTools::generate_dpop_token(
                        Dpop {
                            htm: Htm::Post,
                            display_name: display_name.clone(),
                            htu: htu.clone(),
                            challenge: acme_nonce,
                            handle: handle.clone(),
                            team: test.team.clone().into(),
                            extra_claims: None,
                        },
                        &client_id,
                        backend_nonce.clone(),
                        audience,
                        core::time::Duration::from_secs(3600),
                        test.alg,
                        &test.acme_kp,
                    )
                    .unwrap();

                    let backend_kp: Pem = test.backend_kp.clone();
                    let access_token = RustyJwtTools::generate_access_token(
                        &client_dpop_token,
                        &client_id,
                        handle,
                        &display_name,
                        test.team.clone().into(),
                        backend_nonce,
                        htu,
                        Htm::Post,
                        360,
                        2136351646,
                        backend_kp,
                        test.hash_alg,
                        5,
                        core::time::Duration::from_secs(360),
                    )
                    .unwrap();
                    Ok((test, access_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// see [should_fail_when_access_token_iss_mismatches_target]
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_device_id_mismatches_target(test_env: TestEnvironment) {
        // "iss" deviceId mismatches the actual deviceId
        let test = E2eTest::new(test_env).start().await;

        let nonce_arc = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (nonce_w, nonce_r) = (nonce_arc.clone(), nonce_arc.clone());

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(|mut test, (dpop_chall, nonce, handle, team, display_name, expiry)| {
                Box::pin(async move {
                    *nonce_w.lock().unwrap() = Some(nonce.clone());
                    let client_dpop_token = test
                        .create_dpop_token(&dpop_chall, nonce, handle, team, display_name, expiry)
                        .await?;
                    Ok((test, client_dpop_token))
                })
            }),
            get_access_token: Box::new(|test, (dpop_chall, _)| {
                Box::pin(async move {
                    // here the DeviceId will be different in "sub" than in "iss" (in the access token)
                    let client_id = ClientId {
                        device_id: 42,
                        ..test.sub.clone()
                    };
                    let htu: Htu = dpop_chall.target.into();
                    let backend_nonce: BackendNonce = nonce_r.lock().unwrap().clone().unwrap();
                    let acme_nonce: AcmeNonce = dpop_chall.token.as_str().into();
                    let handle = Handle::from(test.handle.as_str())
                        .try_to_qualified(&client_id.domain)
                        .unwrap();
                    let audience = dpop_chall.url.clone();
                    let display_name = test.display_name.clone();

                    let client_dpop_token = RustyJwtTools::generate_dpop_token(
                        Dpop {
                            htm: Htm::Post,
                            htu: htu.clone(),
                            challenge: acme_nonce,
                            handle: handle.clone(),
                            team: test.team.clone().into(),
                            display_name: display_name.clone(),
                            extra_claims: None,
                        },
                        &client_id,
                        backend_nonce.clone(),
                        audience,
                        core::time::Duration::from_secs(3600),
                        test.alg,
                        &test.acme_kp,
                    )
                    .unwrap();

                    let backend_kp: Pem = test.backend_kp.clone();
                    let access_token = RustyJwtTools::generate_access_token(
                        &client_dpop_token,
                        &client_id,
                        handle,
                        &display_name,
                        test.team.clone().into(),
                        backend_nonce,
                        htu,
                        Htm::Post,
                        360,
                        2136351646,
                        backend_kp,
                        test.hash_alg,
                        5,
                        core::time::Duration::from_secs(360),
                    )
                    .unwrap();
                    Ok((test, access_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// Demonstrates that the client possesses the handle. This handle is included in the DPoP token,
    /// then verified and sealed in the access token which is finally verified by the ACME server
    /// as part of the DPoP challenge.
    /// Here we make the acme-server fail.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn acme_should_fail_when_client_dpop_token_has_wrong_handle(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(
                |mut test, (dpop_chall, backend_nonce, _handle, team, display_name, expiry)| {
                    Box::pin(async move {
                        let wrong_handle = Handle::from("other_wire").try_to_qualified("wire.com").unwrap();
                        let client_dpop_token = test
                            .create_dpop_token(&dpop_chall, backend_nonce, wrong_handle, team, display_name, expiry)
                            .await?;
                        Ok((test, client_dpop_token))
                    })
                },
            ),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::WireServerError
        ));
    }

    #[rstest]
    #[tokio::test]
    /// The access token (forged by wire-server) contains a 'kid' claim which is the JWK thumbprint of the public part
    /// of the keypair used in the ACME account. This constrains the ACME client to be the issuer of the DPoP token.
    /// In this attack, a malicious server forges an access token with a forged proof (the client DPoP token). Since it
    /// does not know the keypair used by the client it will use a random one. This should fail since the acme-server
    /// will verify the 'cnf.kid' and verify that it is indeed the JWK thumbprint of the ACME client.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn acme_should_fail_when_client_dpop_token_has_wrong_kid(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let nonce_arc = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (nonce_w, nonce_r) = (nonce_arc.clone(), nonce_arc.clone());

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(|mut test, (dpop_chall, nonce, handle, team, display_name, expiry)| {
                Box::pin(async move {
                    *nonce_w.lock().unwrap() = Some(nonce.clone());
                    let client_dpop_token = test
                        .create_dpop_token(&dpop_chall, nonce, handle, team, display_name, expiry)
                        .await?;
                    Ok((test, client_dpop_token))
                })
            }),
            get_access_token: Box::new(|test, (dpop_chall, _)| {
                Box::pin(async move {
                    let client_id = test.sub.clone();
                    let htu: Htu = dpop_chall.target.into();
                    let backend_nonce: BackendNonce = nonce_r.lock().unwrap().clone().unwrap();
                    let handle = Handle::from(test.handle.as_str())
                        .try_to_qualified(&client_id.domain)
                        .unwrap();
                    let acme_nonce: AcmeNonce = dpop_chall.token.as_str().into();
                    let audience = dpop_chall.url.clone();
                    let display_name = test.display_name.clone();

                    // use the MLS keypair instead of the ACME one, should make the validation fail on the acme-server
                    let keypair = test.client_kp.clone();
                    let client_dpop_token = RustyJwtTools::generate_dpop_token(
                        Dpop {
                            htm: Htm::Post,
                            htu: htu.clone(),
                            challenge: acme_nonce,
                            handle: handle.clone(),
                            team: test.team.clone().into(),
                            display_name: display_name.clone(),
                            extra_claims: None,
                        },
                        &test.sub,
                        backend_nonce.clone(),
                        audience,
                        core::time::Duration::from_secs(3600),
                        test.alg,
                        &keypair,
                    )
                    .unwrap();

                    let backend_kp: Pem = test.backend_kp.clone();
                    let access_token = RustyJwtTools::generate_access_token(
                        &client_dpop_token,
                        &client_id,
                        handle,
                        &display_name,
                        test.team.clone().into(),
                        backend_nonce,
                        htu,
                        Htm::Post,
                        360,
                        2136351646,
                        backend_kp,
                        test.hash_alg,
                        5,
                        core::time::Duration::from_secs(360),
                    )
                    .unwrap();
                    Ok((test, access_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// We bind the DPoP challenge "uri" to the access token. It is then validated by the ACME server
    // @SF.PROVISIONING @TSFI.ACME @S8
    #[allow(unused_assignments)]
    async fn should_fail_when_invalid_dpop_audience(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;
        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(
                |mut test, (mut dpop_chall, backend_nonce, handle, team, display_name, expiry)| {
                    Box::pin(async move {
                        // change the url in the DPoP challenge to alter what's in the DPoP token, then restore it at
                        // the end
                        let dpop_challenge_url = dpop_chall.url.clone();
                        dpop_chall.url = "http://unknown.com".parse().unwrap();

                        let client_dpop_token = test
                            .create_dpop_token(&dpop_chall, backend_nonce, handle, team, display_name, expiry)
                            .await?;

                        dpop_chall.url = dpop_challenge_url;
                        Ok((test, client_dpop_token))
                    })
                },
            ),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// The DPoP token holds the "display name" of the client which is compared by the acme server against the
    /// display name in the acme identifier as part of the acme order
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn acme_should_fail_when_client_dpop_token_has_wrong_display_name(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;

        let real_dn = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (dn_write, dn_read) = (real_dn.clone(), real_dn.clone());

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(
                |mut test, (dpop_chall, backend_nonce, handle, team, _display_name, expiry)| {
                    Box::pin(async move {
                        *dn_write.lock().unwrap() = Some(test.display_name.clone());

                        let wrong_display_name = "Unknown".to_string();
                        test.display_name = wrong_display_name.clone();

                        let client_dpop_token = test
                            .create_dpop_token(&dpop_chall, backend_nonce, handle, team, wrong_display_name, expiry)
                            .await?;
                        Ok((test, client_dpop_token))
                    })
                },
            ),
            get_access_token: Box::new(|mut test, (dpop_challenge, dpop_token)| {
                Box::pin(async move {
                    let access_token = test.get_access_token(&dpop_challenge, dpop_token).await?;
                    test.display_name = dn_read.lock().unwrap().clone().unwrap();
                    Ok((test, access_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }
}

mod oidc_challenge {
    use super::*;

    #[rstest]
    #[tokio::test]
    /// Authorization Server exposes an endpoint for clients to fetch its public
    /// keys (it gets from the OAuth discovery endpoint of hte IdP).
    /// It is used to validate the signature of the id token we supply to this challenge.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_oidc_provider_discovery_uri_unavailable(test_env: TestEnvironment) {
        let mut test = E2eTest::new(test_env);
        // invalid discovery uri
        let mut discovery_uri: url::Url = test.ca_cfg.discovery_base_url.parse().unwrap();
        discovery_uri.set_port(Some(discovery_uri.port().unwrap() + 1)).unwrap();
        test.ca_cfg.discovery_base_url = discovery_uri.to_string();
        let test = test.start().await;

        // cannot validate the OIDC challenge
        assert!(matches!(
            test.nominal_enrollment().await.unwrap_err(),
            TestError::OidcChallengeError
        ));
    }

    #[rstest]
    #[tokio::test]
    /// We use the "keyauth": '{oidc-challenge-token}.{acme-key-thumbprint}' to bind the acme client to the id token
    /// we validate in the acme server. This prevents id token being stolen or OAuth authorization performed outside of
    /// the current ACME session.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_invalid_keyauth(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;
        let flow = EnrollmentFlow {
            fetch_id_token: Box::new(|mut test, (oidc_chall, _keyauth)| {
                Box::pin(async move {
                    let keyauth = rand_base64_str(32); // a random 'keyauth'
                    let id_token = test.fetch_id_token(&oidc_chall, keyauth).await?;
                    Ok((test, id_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    #[rstest]
    #[tokio::test]
    /// We add an "acme_aud" in the idToken which must match the OIDC challenge url
    // @SF.PROVISIONING @TSFI.ACME @S8
    #[allow(unused_assignments)]
    async fn should_fail_when_invalid_audience(test_env: TestEnvironment) {
        let test = E2eTest::new(test_env).start().await;
        let flow = EnrollmentFlow {
            fetch_id_token: Box::new(|mut test, (mut oidc_chall, keyauth)| {
                Box::pin(async move {
                    // alter the challenge url to alter the idToken audience, then restore the challenge url
                    let backup_oidc_challenge_url = oidc_chall.url.clone();
                    oidc_chall.url = "http://unknown.com".parse().unwrap();

                    let id_token = test.fetch_id_token(&oidc_chall, keyauth).await?;
                    oidc_chall.url = backup_oidc_challenge_url;
                    Ok((test, id_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }
}
