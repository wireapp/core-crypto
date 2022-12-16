#![cfg(not(target_family = "wasm"))]

use asserhttp::*;
use jwt_simple::prelude::*;
use rand::random;
use rusty_acme::prelude::*;
use rusty_jwt_tools::jwk_thumbprint::JwkThumbprint;
use rusty_jwt_tools::prelude::*;
use serde_json::Value;
use testcontainers::clients::Cli;
use testcontainers::Container;
use utils::{display::Actor::*, display::*, fake_wire_server::*, helpers::*, keys::keys};

#[path = "utils/mod.rs"]
mod utils;

pub const IDP_HOST: &str = "idp.example.com";
pub const WIRE_HOST: &str = "wire.example.com";

// TODO: make it pass on CI
#[ignore]
#[tokio::test]
async fn e2e_identity() {
    let docker = Cli::docker();
    let (acme_port, acme_client, _node) = StepCaImage::run(&docker);

    let FakeWireServer {
        url: wire_server_url,
        http_client: wire_server_client,
    } = FakeWireServer::run().await;

    TestDisplay::clear();

    for (alg, client_kp, client_jwk, backend_kp, hash_alg) in keys() {
        let title = format!("{alg:?} - {hash_alg:?}");
        let mut d = TestDisplay::new(title);

        // GET http://acme-server/directory
        let (directory, directory_link) = {
            let ca_url = format!("https://localhost:{acme_port}");
            d.chapter("Initial setup with ACME server");
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
            d.step("fetch acme directory for hyperlinks");
            let provisioner_name = StepCaImage::ACME_PROVISIONER_NAME;
            let directory_url = format!("{ca_url}/acme/{provisioner_name}/directory");
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
        let (order, order_url, previous_nonce) = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
            d.chapter("Request a certificate with relevant identifiers");
            d.step("create a new order");
            let wire_handle = IDP_HOST.to_string();
            let wire_client_id = WIRE_HOST.to_string();
            let expiry = core::time::Duration::from_secs(3600); // 1h
            let order_request = RustyAcme::new_order_request(
                wire_handle,
                wire_client_id,
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
            (new_order, order_url, previous_nonce)
        };

        // POST http://acme-server/authz1
        let (authz1, previous_nonce) = {
            d.chapter("Display-name and handle already authorized");
            d.step("fetch first challenge");
            let authz_url_1 = order.authorizations.get(0).unwrap();
            let authz_req_1 =
                RustyAcme::new_authz_request(authz_url_1, &account, alg, &client_kp, previous_nonce).unwrap();
            let req = acme_client.acme_req(authz_url_1, &authz_req_1);
            d.req(WireClient, AcmeBe, Some(&req));
            d.body(&authz_req_1);

            d.step("get back first challenge");
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
            let authz1 = resp.unwrap();
            d.body(&authz1);
            (authz1, previous_nonce)
        };

        // POST http://acme-server/authz2
        let (authz2, previous_nonce) = {
            d.chapter("ACME provides a Wire client ID challenge");
            d.step("fetch second challenge");
            let authz_url_2 = order.authorizations.get(1).unwrap();
            let authz_req_2 =
                RustyAcme::new_authz_request(authz_url_2, &account, alg, &client_kp, previous_nonce).unwrap();
            let req = acme_client.acme_req(authz_url_2, &authz_req_2);
            d.req(WireClient, AcmeBe, Some(&req));
            d.body(&authz_req_2);

            d.step("get back second challenge");
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
            let authz2 = resp.unwrap();
            d.body(&authz2);
            (authz2, previous_nonce)
        };

        // extract challenges
        let (client_id_chall, handle_chall) = {
            // final implementation
            /*match (authz1.identifier.value(), authz2.identifier.value()) {
                (client_id, handle) if (client_id, handle) == (WIRE_HOST, IDP_HOST) => (
                    authz1.wire_http_challenge().cloned().unwrap(),
                    authz2.wire_oidc_challenge().cloned().unwrap(),
                ),
                (handle, client_id) if (client_id, handle) == (WIRE_HOST, IDP_HOST) => (
                    authz1.wire_oidc_challenge().cloned().unwrap(),
                    authz2.wire_http_challenge().cloned().unwrap(),
                ),
                _ => panic!(""),
            }*/

            let client_id_chall = authz1.http_challenge().cloned().unwrap();
            let handle_chall = authz2.http_challenge().cloned().unwrap();
            (client_id_chall, handle_chall)
        };

        // HEAD http://wire-server/nonce
        let backend_nonce = {
            d.chapter("Client fetches JWT DPoP access token (with wire-server)");
            d.step("fetch a nonce from wire-server");
            let nonce_url = format!("{}/clients/token/nonce", wire_server_url);
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
        let _access_token = {
            d.step("create the client Dpop token with both nonces");
            let user = uuid::Uuid::new_v4().to_string();
            let client_id = random::<u64>();
            let domain = "wire.com";
            let alice = ClientId::try_new(&user, client_id, domain).unwrap();
            let dpop_url = format!("{wire_server_url}/clients/{client_id}/access-token");
            let htu: Htu = dpop_url.as_str().try_into().unwrap();
            let acme_challenge: AcmeNonce = client_id_chall.token.as_str().into();
            let dpop = Dpop {
                challenge: acme_challenge.clone(),
                htm: Htm::Post,
                htu,
                extra_claims: None,
            };
            let expiry = Duration::from_days(1).into();
            let client_dpop_token =
                RustyJwtTools::generate_dpop_token(dpop, alice, backend_nonce, expiry, alg, &client_kp).unwrap();
            d.token(&client_dpop_token);
            let b64 = |v: &str| base64::encode_config(v, base64::URL_SAFE_NO_PAD);
            let req = wire_server_client
            .post(&dpop_url)
            .header("dpop", b64(&client_dpop_token))
            // cheat to share test context
            .header("client-id", b64(&alice.to_subject()))
            .header("backend-kp", b64(backend_kp.as_str()))
            .header("hash-alg", b64(&hash_alg.to_string()))
            .header("wire-server-uri", b64(&dpop_url))
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
                .unwrap()
                .get("token")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            d.token(&access_token);
            access_token
        };

        // POST http://acme-server/challenge
        let (previous_nonce, _wiremock_node_1, _wiremock_node_2) = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
            d.chapter("Client provides access token");
            d.step("send DPoP access token to acme server to have it validated");
            // take ownership so that docker container is not stopped
            let _wiremock_node_1 = fake_challenge_response(&docker, IDP_HOST, &client_id_chall.token, &client_jwk);

            let client_id_chall_url = client_id_chall.url.clone();
            let client_id_chall_token = client_id_chall.token.clone();
            let client_id_chall_req =
                RustyAcme::new_chall_request(client_id_chall, &account, alg, &client_kp, previous_nonce).unwrap();
            let req = acme_client.acme_req(&client_id_chall_url, &client_id_chall_req);
            d.req(WireClient, AcmeBe, Some(&req));
            d.body(&client_id_chall_req);

            d.step("acme server verifies client-id with an http challenge");
            // acme server will call /.well-known/acme-challenge/{token} on wire-server
            let client_id_challenge_url = format!("http://wire.com/.well-known/acme-challenge/{client_id_chall_token}");
            let acme_req = acme_client.get(&client_id_challenge_url).build().unwrap();
            d.req(AcmeBe, WireBe, Some(&acme_req));
            d.resp(WireBe, AcmeBe, None);

            d.step("acme server verifies handle + display-name with an OIDC challenge");
            let handle_challenge_url = format!("http://wire.com/.well-known/acme-challenge/{}", handle_chall.token);
            let acme_req = acme_client.get(&handle_challenge_url).build().unwrap();
            d.req(AcmeBe, WireBe, Some(&acme_req));
            d.resp(WireBe, AcmeBe, None);

            d.step("both challenges are valid");
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

            // will also for now fake the validation of the second challenge (handle + display name)
            // but ultimately this will be handled in our acme server fork
            let _wiremock_node_2 = fake_challenge_response(&docker, WIRE_HOST, &handle_chall.token, &client_jwk);
            let handle_chall_url = handle_chall.url.clone();
            let handle_chall_req =
                RustyAcme::new_chall_request(handle_chall, &account, alg, &client_kp, previous_nonce).unwrap();
            let req = acme_client.acme_req(&handle_chall_url, &handle_chall_req);
            let mut resp = acme_client.execute(req).await.unwrap();
            let previous_nonce = resp.replay_nonce();
            resp.expect_status_ok()
                .has_replay_nonce()
                .has_location()
                .has_directory_link(&directory_link)
                .expect_content_type_json();
            let resp = resp.json().await.unwrap();
            let _resp = RustyAcme::new_chall_response(resp);
            (previous_nonce, _wiremock_node_1, _wiremock_node_2)
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
            let domains = vec![WIRE_HOST.to_string(), IDP_HOST.to_string()];
            let finalize_url = order.finalize.clone();
            let finalize_req =
                RustyAcme::finalize_req(domains, order, &account, alg, &client_kp, previous_nonce).unwrap();
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
            certificates
        };

        d.display();
    }
}

fn fake_challenge_response<'a>(
    docker: &'a Cli,
    host: &str,
    challenge: &str,
    jwk: &Jwk,
) -> Container<'a, WiremockImage> {
    let url = format!("/.well-known/acme-challenge/{challenge}");
    // FIXME: step-ca does not support SHA-384 for the moment
    let hash_alg = HashAlgorithm::SHA256;
    let thumbprint = JwkThumbprint::generate(jwk, hash_alg).unwrap().kid;
    let key_auth = format!("{challenge}.{thumbprint}");
    let stub = serde_json::json!({
        "request": {
            "method": "GET",
            "urlPath": url
        },
        "response": {
            "body": key_auth
        }
    });
    let stubs = vec![stub];
    WiremockImage::run(docker, host, stubs)
}
