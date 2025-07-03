// This file contains test mappings to automatically generate various reports for Zulu.
// They are marked with @SF and similar.
// DO NOT REMOVE OR CHANGE THESE OR THE TESTS WITHOUT TALKING TO SECURITY FIRST!

#![cfg(not(target_family = "wasm"))]

use jwt_simple::prelude::*;
use serde_json::{Value, json};

use rusty_acme::prelude::*;
use rusty_jwt_tools::prelude::*;
use utils::{
    TestError,
    cfg::{E2eTest, EnrollmentFlow, OidcProvider},
    docker::{stepca::CaCfg, wiremock::WiremockImage},
    id_token::resign_id_token,
    rand_base64_str, rand_client_id,
};

#[path = "utils/mod.rs"]
mod utils;

/// Tests the nominal case and prints the pretty output with the mermaid chart in this crate README.
#[cfg(not(ci))]
#[tokio::test]
async fn demo_should_succeed() {
    let test = E2eTest::new_demo().start().await;
    test.nominal_enrollment().await.unwrap();
}

/// Tests using the custom SPI Provider to be able to use the refreshToken to get a new idToken with the current ACME challenges
#[tokio::test]
async fn refresh_token_can_be_used_to_renew() {
    let test = E2eTest::new_demo().start().await;

    // first enrollment
    let test = test.nominal_enrollment().await.unwrap();

    let refresh_token = test.refresh_token.clone().unwrap().secret().to_string();
    assert!(!refresh_token.is_empty());
    let refresh_token = oauth2::RefreshToken::new(refresh_token);

    // second enrollment
    let flow = EnrollmentFlow {
        fetch_id_token: Box::new(|mut test, (oidc_chall, keyauth)| {
            Box::pin(async move {
                let id_token = test
                    .fetch_id_token_from_refresh_token(&oidc_chall, keyauth, refresh_token)
                    .await?;
                Ok((test, id_token))
            })
        }),
        ..Default::default()
    };
    test.enrollment(flow).await.unwrap();
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
    #[tokio::test]
    async fn ed25519_should_succeed() {
        let test = E2eTest::new_internal(false, JwsAlgorithm::Ed25519, OidcProvider::Keycloak)
            .start()
            .await;
        assert!(test.nominal_enrollment().await.is_ok());
    }

    // @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
    #[tokio::test]
    async fn p256_should_succeed() {
        let test = E2eTest::new_internal(false, JwsAlgorithm::P256, OidcProvider::Keycloak)
            .start()
            .await;
        assert!(test.nominal_enrollment().await.is_ok());
    }

    // @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
    #[tokio::test]
    async fn p384_should_succeed() {
        let test = E2eTest::new_internal(false, JwsAlgorithm::P384, OidcProvider::Keycloak)
            .start()
            .await;
        assert!(test.nominal_enrollment().await.is_ok());
    }

    // @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
    #[tokio::test]
    async fn p521_should_succeed() {
        let test = E2eTest::new_internal(false, JwsAlgorithm::P521, OidcProvider::Keycloak)
            .start()
            .await;
        assert!(test.nominal_enrollment().await.is_ok());
    }
}

/// Since the acme server is a fork, verify its invariants are respected
mod acme_server {
    use super::*;
    use rusty_acme::prelude::x509::RustyX509CheckError;
    use rusty_acme::prelude::x509::reexports::certval;
    use rusty_acme::prelude::x509::reexports::certval::PathValidationStatus;
    use rusty_acme::prelude::x509::revocation::{PkiEnvironment, PkiEnvironmentParams};
    use x509_cert::der::Decode;

    #[tokio::test]
    /// Acme server has been man-in-middle:ed and returns untrusted certificates
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_certificate_path_doesnt_contain_trust_anchor() {
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// Challenges returned by ACME server are mixed up
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_no_replay_nonce_requested() {
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// Replay nonce is reused by the client
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_replay_nonce_reused() {
        let test = E2eTest::new().start().await;

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
    #[tokio::test]
    /// This verifies the DPoP challenge verification method on the acme server
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_dpop_challenge_signed_by_a_different_key() {
        let test = E2eTest::new().start().await;

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
    #[tokio::test]
    /// This verifies the DPoP challenge verification method on the acme server
    // @SF.PROVISIONING @TSFI.ACME
    async fn should_fail_when_oidc_challenge_signed_by_a_different_key() {
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// Demonstrates that the client possesses the clientId. Client makes an authenticated request
    /// to wire-server, it delivers a nonce which the client seals in a signed DPoP JWT.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_client_dpop_token_has_wrong_backend_nonce() {
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// Acme server should be configured with wire-server public key to verify the access tokens
    /// issued by wire-server.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_not_signed_by_wire_server() {
        let default = E2eTest::new();
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

    #[tokio::test]
    /// The access token has a 'chal' claim which should match the Acme challenge 'token'. This is verified by the acme server
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_challenge_claim_is_not_current_challenge_one() {
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// We first set a clientId for the enrollment process when we create the acme order. This same
    /// clientId must be used and sealed in the accessToken which is verified by the acme server in
    /// the oidc challenge. The challenge should be invalid if they differ
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_client_id_mismatches() {
        let test = E2eTest::new().start().await;

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

    // TODO: not testable in practice because leeway of 360s is hardcoded in acme server
    #[ignore]
    #[should_panic]
    #[tokio::test]
    /// Client DPoP token is nested within access token. The former should not be expired when
    /// acme server verifies the DPoP challenge
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_expired_client_dpop_token() {
        let test = E2eTest::new().start().await;

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(
                |mut test, (dpop_chall, backend_nonce, handle, team, display_name, _expiry)| {
                    Box::pin(async move {
                        let leeway = 360;
                        let expiry = core::time::Duration::from_secs(0);
                        let client_dpop_token = test
                            .create_dpop_token(&dpop_chall, backend_nonce, handle, team, display_name, expiry)
                            .await?;
                        tokio::time::sleep(core::time::Duration::from_secs(leeway + 1)).await;
                        Ok((test, client_dpop_token))
                    })
                },
            ),
            ..Default::default()
        };
        test.enrollment(flow).await.unwrap();
    }

    #[tokio::test]
    /// In order to tie DPoP challenge verification on the acme server, the latter is configured
    /// with the accepted wire-server host which is present in the DPoP "htu" claim and in the access token
    /// "iss" claim.
    /// The challenge should fail if any of those does not match the expected value
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_iss_mismatches_target() {
        // "iss" in access token mismatches expected target
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// see [should_fail_when_access_token_iss_mismatches_target]
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_access_token_device_id_mismatches_target() {
        // "iss" deviceId mismatches the actual deviceId
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// Demonstrates that the client possesses the handle. This handle is included in the DPoP token,
    /// then verified and sealed in the access token which is finally verified by the ACME server
    /// as part of the DPoP challenge.
    /// Here we make the acme-server fail.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn acme_should_fail_when_client_dpop_token_has_wrong_handle() {
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// The access token (forged by wire-server) contains a 'kid' claim which is the JWK thumbprint of the public part
    /// of the keypair used in the ACME account. This constrains the ACME client to be the issuer of the DPoP token.
    /// In this attack, a malicious server forges an access token with a forged proof (the client DPoP token). Since it
    /// does not know the keypair used by the client it will use a random one. This should fail since the acme-server
    /// will verify the 'cnf.kid' and verify that it is indeed the JWK thumbprint of the ACME client.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn acme_should_fail_when_client_dpop_token_has_wrong_kid() {
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// We bind the DPoP challenge "uri" to the access token. It is then validated by the ACME server
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_invalid_dpop_audience() {
        let test = E2eTest::new().start().await;
        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(
                |mut test, (mut dpop_chall, backend_nonce, handle, team, display_name, expiry)| {
                    Box::pin(async move {
                        // change the url in the DPoP challenge to alter what's in the DPoP token, then restore it at the end
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

    #[tokio::test]
    /// The DPoP token holds the "display name" of the client which is compared by the acme server against the
    /// display name in the acme identifier as part of the acme order
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn acme_should_fail_when_client_dpop_token_has_wrong_display_name() {
        let test = E2eTest::new().start().await;

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

    #[tokio::test]
    /// Authorization Server exposes an endpoint for clients to fetch its public
    /// keys (it gets from the OAuth discovery endpoint of hte IdP).
    /// It is used to validate the signature of the id token we supply to this challenge.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_oidc_provider_discovery_uri_unavailable() {
        let mut test = E2eTest::new();
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

    #[tokio::test]
    #[ignore] // FIXME: adapt with Keycloak
    /// An id token with an invalid name is supplied to ACME server. It should verify that the handle
    /// is the same as the one used in the order.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_invalid_handle() {
        let test = E2eTest::new();

        // setup fake jwks_uri to be able to resign the id token
        let (jwks_stub, new_kp, kid) = test.new_jwks_uri_mock();
        let attacker_host = "attacker-keycloak";
        let _attacker_keycloak = WiremockImage::run(attacker_host, vec![jwks_stub]);

        let test = test.start().await;

        let flow = EnrollmentFlow {
            fetch_id_token: Box::new(|mut test, (oidc_chall, keyauth)| {
                Box::pin(async move {
                    let idp_pk = test.fetch_idp_public_key().await;
                    let dex_pk = RS256PublicKey::from_pem(&idp_pk).unwrap();
                    let id_token = test.fetch_id_token(&oidc_chall, keyauth).await?;

                    let change_handle = |mut claims: JWTClaims<Value>| {
                        let wrong_handle = format!("{}john.doe.qa@wire.com", ClientId::URI_SCHEME);
                        *claims.custom.get_mut("name").unwrap() = json!(wrong_handle);
                        claims
                    };
                    let modified_id_token = resign_id_token(&id_token, dex_pk, kid, new_kp, change_handle);
                    Ok((test, modified_id_token))
                })
            }),
            ..Default::default()
        };

        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. It must either be 'valid' or 'processing'."
            ))
        ));
    }

    #[tokio::test]
    #[ignore] // FIXME: adapt with Keycloak
    /// An id token with an invalid name is supplied to ACME server. It should verify that the display name
    /// is the same as the one used in the order.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_invalid_display_name() {
        let test = E2eTest::new();

        // setup fake jwks_uri to be able to resign the id token
        let (jwks_stub, new_kp, kid) = test.new_jwks_uri_mock();
        let attacker_host = "attacker-dex";
        let _attacker_dex = WiremockImage::run(attacker_host, vec![jwks_stub]);

        let test = test.start().await;

        let flow = EnrollmentFlow {
            fetch_id_token: Box::new(|mut test, (oidc_chall, keyauth)| {
                Box::pin(async move {
                    let dex_pk = test.fetch_idp_public_key().await;
                    let dex_pk = RS256PublicKey::from_pem(&dex_pk).unwrap();
                    let id_token = test.fetch_id_token(&oidc_chall, keyauth).await?;

                    let change_handle = |mut claims: JWTClaims<Value>| {
                        let wrong_handle = "Doe, John (QA)";
                        *claims.custom.get_mut("preferred_username").unwrap() = json!(wrong_handle);
                        claims
                    };
                    let modified_id_token = resign_id_token(&id_token, dex_pk, kid, new_kp, change_handle);
                    Ok((test, modified_id_token))
                })
            }),
            ..Default::default()
        };

        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. It must either be 'valid' or 'processing'."
            ))
        ));
    }

    #[tokio::test]
    /// We use the "keyauth": '{oidc-challenge-token}.{acme-key-thumbprint}' to bind the acme client to the id token
    /// we validate in the acme server. This prevents id token being stolen or OAuth authorization performed outside of
    /// the current ACME session.
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_invalid_keyauth() {
        let test = E2eTest::new().start().await;
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

    #[tokio::test]
    /// We add an "acme_aud" in the idToken which must match the OIDC challenge url
    // @SF.PROVISIONING @TSFI.ACME @S8
    async fn should_fail_when_invalid_audience() {
        let test = E2eTest::new().start().await;
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
