#![cfg(not(target_family = "wasm"))]

use asserhttp::*;
use jwt_simple::prelude::*;
use rand::random;
use rusty_acme::prelude::{wiremock::WiremockImage, *};
use rusty_jwt_tools::prelude::*;
use serde_json::Value;
use testcontainers::{clients::Cli, Container};
use utils::{display::Actor::*, display::*, fake_wire_server::*, helpers::*, keys::keys, oidc::id_token};

#[path = "utils/mod.rs"]
mod utils;

pub const WIRE_HOST: &str = "example.com";
pub const IDP_HOST: &str = "idp";

// TODO: make it pass on CI
#[ignore]
#[tokio::test]
async fn e2e_identity() {
    let FakeWireServer {
        url: wire_server_url,
        http_client: wire_server_client,
    } = FakeWireServer::run().await;

    TestDisplay::clear();

    for (alg, client_kp, client_jwk, backend_kp, backend_pk, hash_alg, idp_kp, idp_jwk) in keys() {
        // does not work for elliptic curves yet
        if matches!(alg, JwsAlgorithm::Ed25519) {
            let title = format!("{alg:?} - {hash_alg:?}");
            let mut d = TestDisplay::new(title);

            let docker = Cli::docker();

            let (idp_url, _idp) = mock_idp(&docker, IDP_HOST, &idp_jwk);

            let issuer = idp_url.clone();
            let audience = idp_url.clone();

            let ca_cfg = StepCaConfig {
                sign_key: backend_pk.to_string(),
                issuer: issuer.clone(),
                audience: audience.clone(),
                jwks_uri: format!("http://{IDP_HOST}/oauth2/jwks"),
            };
            let (acme_port, acme_client, _node) = StepCaImage::run(&docker, ca_cfg);

            // GET http://acme-server/directory
            let (directory, directory_link) = {
                let ca_url = format!("https://localhost:{acme_port}");
                d.chapter("Initial setup with ACME server");
                // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
                d.step("fetch acme directory for hyperlinks");
                let directory_url = format!("{ca_url}/acme/{}/directory", StepCaImage::ACME_PROVISIONER);
                let directory_link = format!("<{directory_url}>;rel=\"index\"");
                let req = acme_client.get(&directory_url).build().unwrap();
                d.req(WireClient, AcmeBe, Some(&req));

                d.step("get the ACME directory with links for newNonce, newAccount & newOrder");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                resp.expect_status_ok().expect_content_type_json();
                let resp = RustyAcme::acme_directory_response(resp.json::<Value>().await.unwrap());
                assert!(resp.is_ok());
                let directory = resp.unwrap();
                d.body(&directory);
                (directory, directory_link)
            };

            // GET http://acme-server/new-nonce
            let previous_nonce = {
                // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.2
                d.step("fetch a new nonce for the very first request");
                let new_nonce_url = directory.new_nonce.as_str();
                let req = acme_client.head(new_nonce_url).build().unwrap();
                d.req(WireClient, AcmeBe, Some(&req));

                d.step("get a nonce for creating an account");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                resp.expect_status_ok()
                    .expect_header("cache-control", "no-store")
                    .has_replay_nonce()
                    .has_directory_link(&directory_link);
                let previous_nonce = resp.replay_nonce();
                d.body(&previous_nonce);
                previous_nonce
            };

            // POST http://acme-server/new-account
            let (account, previous_nonce) = {
                // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
                d.step("create a new account");
                let account_req = RustyAcme::new_account_request(&directory, alg, &client_kp, previous_nonce).unwrap();
                let req = acme_client.acme_req(&directory.new_account, &account_req);
                d.req(WireClient, AcmeBe, Some(&req));
                d.body(&account_req);

                d.step("account created");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                resp.expect_status_created()
                    .has_replay_nonce()
                    .has_location()
                    .has_directory_link(&directory_link)
                    .expect_content_type_json();
                let previous_nonce = resp.replay_nonce();
                let resp = RustyAcme::new_account_response(resp.json().await.unwrap());
                assert!(resp.is_ok());
                let account = resp.unwrap();
                d.body(&account);
                (account, previous_nonce)
            };

            // POST http://acme-server/new-order
            let (order, order_url, display_name, domain, client_id, handle, qualified_handle, previous_nonce) = {
                // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
                d.chapter("Request a certificate with relevant identifiers");
                d.step("create a new order");
                let display_name = "Smith, Alice M (QA)".to_string();
                let domain = WIRE_HOST.to_string();
                let handle = uuid::Uuid::new_v4();
                let client_id = random::<u64>();
                let qualified_client_id =
                    ClientId::try_from_raw_parts(handle.as_bytes(), client_id, domain.as_bytes()).unwrap();
                let qualified_handle = "impp:wireapp=alice.smith.qa@example.com".to_string();
                let expiry = core::time::Duration::from_secs(3600); // 1h
                let order_request = RustyAcme::new_order_request(
                    display_name.clone(),
                    domain.clone(),
                    qualified_client_id,
                    qualified_handle.clone(),
                    expiry,
                    &directory,
                    &account,
                    alg,
                    &client_kp,
                    previous_nonce,
                )
                .unwrap();
                let req = acme_client.acme_req(&directory.new_order, &order_request);
                d.req(WireClient, AcmeBe, Some(&req));
                d.body(&order_request);

                d.step("get new order with authorization URLS and finalize URL");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                let previous_nonce = resp.replay_nonce();
                let order_url = resp.location_url();
                resp.expect_status_created()
                    .has_replay_nonce()
                    .has_location()
                    .has_directory_link(&directory_link)
                    .expect_content_type_json();
                let resp = resp.json().await.unwrap();
                let resp = RustyAcme::new_order_response(resp);
                assert!(resp.is_ok());
                let new_order = resp.unwrap();
                d.body(&new_order);
                (
                    new_order,
                    order_url,
                    display_name,
                    domain,
                    client_id,
                    handle.to_string(),
                    qualified_handle,
                    previous_nonce,
                )
            };

            // POST http://acme-server/authz
            let (authz, previous_nonce) = {
                d.chapter("Display-name and handle already authorized");
                d.step("fetch challenge");
                let authz_url = order.authorizations.get(0).unwrap();
                let authz_req =
                    RustyAcme::new_authz_request(authz_url, &account, alg, &client_kp, previous_nonce).unwrap();
                let req = acme_client.acme_req(authz_url, &authz_req);
                d.req(WireClient, AcmeBe, Some(&req));
                d.body(&authz_req);

                d.step("get back challenge");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                let previous_nonce = resp.replay_nonce();
                resp.expect_status_ok()
                    .has_replay_nonce()
                    .has_location()
                    .has_directory_link(&directory_link)
                    .expect_content_type_json();
                let resp = resp.json().await.unwrap();
                let resp = RustyAcme::new_authz_response(resp);
                assert!(resp.is_ok());
                let authz = resp.unwrap();
                d.body(&authz);
                (authz, previous_nonce)
            };

            // extract challenges
            let (dpop_chall, oidc_chall) = {
                (
                    authz.wire_dpop_challenge().cloned().unwrap(),
                    authz.wire_oidc_challenge().cloned().unwrap(),
                )
            };

            // HEAD http://wire-server/nonce
            let backend_nonce = {
                d.chapter("Client fetches JWT DPoP access token (with wire-server)");
                d.step("fetch a nonce from wire-server");
                let nonce_url = format!("{wire_server_url}/clients/token/nonce");
                let req = wire_server_client.get(nonce_url).build().unwrap();
                d.req(WireClient, WireBe, Some(&req));

                d.step("get wire-server nonce");
                let mut resp = wire_server_client.execute(req).await.unwrap();
                d.resp(WireBe, WireClient, Some(&resp));
                resp.expect_status_ok();
                let backend_nonce: BackendNonce = resp.text().await.unwrap().into();
                d.body(&backend_nonce);
                backend_nonce
            };

            // POST http://wire-server/client-dpop-token
            let (access_token, sub) = {
                d.step("create the client Dpop token with both nonces");
                let alice = ClientId::try_new(&handle, client_id, &domain).unwrap();
                let dpop_url = format!("{wire_server_url}/clients/{client_id}/access-token");
                let issuer = wire_server_url.clone();
                let htu: Htu = issuer.as_str().try_into().unwrap();
                let acme_nonce: AcmeNonce = dpop_chall.token.as_str().into();
                let dpop = Dpop {
                    challenge: acme_nonce.clone(),
                    htm: Htm::Post,
                    htu,
                    extra_claims: None,
                };
                let expiry = Duration::from_days(1).into();
                let client_dpop_token =
                    RustyJwtTools::generate_dpop_token(dpop, alice, backend_nonce, expiry, alg, &client_kp).unwrap();
                d.token("Dpop token", &client_dpop_token);
                let b64 = |v: &str| base64::encode_config(v, base64::URL_SAFE_NO_PAD);
                let req = wire_server_client
                    .post(&dpop_url)
                    .header("dpop", b64(&client_dpop_token))
                    // cheat to share test context
                    .header("client-id", b64(&alice.to_subject()))
                    .header("backend-kp", b64(backend_kp.as_str()))
                    .header("hash-alg", b64(&hash_alg.to_string()))
                    .header("wire-server-uri", b64(&issuer))
                    .build()
                    .unwrap();
                d.req(WireClient, WireBe, Some(&req));

                d.step("get a Dpop access token from wire-server");
                let mut resp = wire_server_client.execute(req).await.unwrap();
                d.resp(WireBe, WireClient, Some(&resp));
                resp.expect_status_ok();
                let resp = resp.json::<Value>().await.unwrap();
                let access_token = resp
                    .as_object()
                    .and_then(|o| o.get("token"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap();
                d.token("Access token", &access_token);
                (access_token, alice)
            };

            // client id (dpop) challenge
            // POST http://acme-server/challenge
            let previous_nonce = {
                // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
                d.chapter("Client provides access token");
                d.step("validate Dpop challenge (clientId)");
                let dpop_chall_url = dpop_chall.url.clone();
                let dpop_chall_req = RustyAcme::dpop_chall_request(
                    access_token.clone(),
                    dpop_chall,
                    &account,
                    alg,
                    &client_kp,
                    previous_nonce,
                )
                .unwrap();
                let req = acme_client.acme_req(&dpop_chall_url, &dpop_chall_req);
                d.req(WireClient, AcmeBe, Some(&req));
                d.body(&dpop_chall_req);

                d.step("client id challenge is valid");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                let previous_nonce = resp.replay_nonce();
                resp.expect_status_ok()
                    .has_replay_nonce()
                    .has_location()
                    .has_directory_link(&directory_link)
                    .expect_content_type_json();
                let resp = resp.json().await.unwrap();
                let resp = RustyAcme::new_chall_response(resp).unwrap();
                d.body(&resp);
                previous_nonce
            };

            // handle (oidc) challenge
            // POST http://acme-server/challenge
            let previous_nonce = {
                // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
                d.step("validate oidc challenge (userId + displayName)");

                let oidc_chall_url = oidc_chall.url.clone();
                let id_token = id_token(
                    alg,
                    idp_kp,
                    issuer,
                    sub.to_subject(),
                    audience,
                    client_jwk,
                    oidc_chall.token.clone(),
                    display_name.clone(),
                    qualified_handle,
                );
                d.token("Id token", &id_token);
                let oidc_chall_req =
                    RustyAcme::oidc_chall_request(id_token, oidc_chall, &account, alg, &client_kp, previous_nonce)
                        .unwrap();
                let req = acme_client.acme_req(&oidc_chall_url, &oidc_chall_req);
                d.req(WireClient, AcmeBe, Some(&req));
                d.body(&oidc_chall_req);

                d.step("handle challenge is valid");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                let previous_nonce = resp.replay_nonce();
                resp.expect_status_ok()
                    .has_replay_nonce()
                    .has_location()
                    .has_directory_link(&directory_link)
                    .expect_content_type_json();
                let resp = resp.json().await.unwrap();
                let resp = RustyAcme::new_chall_response(resp).unwrap();
                d.body(&resp);
                previous_nonce
            };

            // POST http://acme-server/order (verify status)
            let (order, previous_nonce) = {
                d.chapter("Client presents a CSR and gets its certificate");
                d.step("verify the status of the order");
                let order_req_url = order_url.clone();
                let get_order_req =
                    RustyAcme::check_order_request(order_url, &account, alg, &client_kp, previous_nonce).unwrap();
                let req = acme_client.acme_req(&order_req_url, &get_order_req);
                d.req(WireClient, AcmeBe, Some(&req));
                d.body(&get_order_req);

                d.step("loop (with exponential backoff) until order is ready");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                let previous_nonce = resp.replay_nonce();
                resp.expect_status_ok()
                    .has_replay_nonce()
                    .has_location()
                    .has_directory_link(&directory_link)
                    .expect_content_type_json();
                let resp = resp.json().await.unwrap();
                let order = RustyAcme::check_order_response(resp).unwrap();
                d.body(&order);
                (order, previous_nonce)
            };

            // POST http://acme-server/finalize
            let (finalize, previous_nonce) = {
                d.step("create a CSR and call finalize url");
                let finalize_url = order.finalize.clone();
                let finalize_req = RustyAcme::finalize_req(order, &account, alg, &client_kp, previous_nonce).unwrap();
                let req = acme_client.acme_req(&finalize_url, &finalize_req);
                d.req(WireClient, AcmeBe, Some(&req));
                d.body(&finalize_req);

                d.step("get back a url for fetching the certificate");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                let previous_nonce = resp.replay_nonce();
                resp.expect_status_ok()
                    .has_replay_nonce()
                    .has_location()
                    .has_directory_link(&directory_link)
                    .expect_content_type_json();
                let resp = resp.json().await.unwrap();
                let finalize = RustyAcme::finalize_response(resp).unwrap();
                d.body(&finalize);
                (finalize, previous_nonce)
            };

            // GET http://acme-server/certificate
            let _certificates = {
                d.step("fetch the certificate");
                let certificate_url = finalize.certificate.clone();
                let certificate_req =
                    RustyAcme::certificate_req(finalize, account, alg, &client_kp, previous_nonce).unwrap();
                let req = acme_client.acme_req(&certificate_url, &certificate_req);
                d.req(WireClient, AcmeBe, Some(&req));
                d.body(&certificate_req);

                d.step("get the certificate chain");
                let mut resp = acme_client.execute(req).await.unwrap();
                d.resp(AcmeBe, WireClient, Some(&resp));
                resp.expect_status_ok()
                    .has_replay_nonce()
                    .expect_header_absent("location")
                    .has_directory_link(&directory_link)
                    .expect_header("content-type", "application/pem-certificate-chain");
                let resp = resp.text().await.unwrap();
                let certificates = RustyAcme::certificate_response(resp).unwrap();
                d.body(&certificates);
                for (i, cert) in certificates.iter().enumerate() {
                    d.cert(&format!("Certificate #{i}"), cert);
                }
                certificates
            };

            d.display();
        }
    }
}

fn mock_idp<'a>(docker: &'a Cli, host: &str, jwk: &Jwk) -> (String, Container<'a, WiremockImage>) {
    let jwks_mock = serde_json::json!({
        "request": {
            "method": "GET",
            "urlPath": "/oauth2/jwks"
        },
        "response": {
            "jsonBody": {
                "keys": [jwk]
            }
        }
    });
    let stubs = vec![jwks_mock];
    let node = WiremockImage::run(docker, host, stubs);
    let url = format!("http://{IDP_HOST}/");
    (url, node)
}
