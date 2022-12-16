use jwt_simple::prelude::*;
use rand::random;
use rusty_acme::prelude::*;
use rusty_jwt_tools::prelude::*;
use serde_json::json;
use utils::keys::keys;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[path = "utils/mod.rs"]
mod utils;

pub const IDP_HOST: &str = "example.org";
pub const WIRE_HOST: &str = "www.example.org";

#[test]
#[wasm_bindgen_test]
fn e2e_api() {
    let prev_nonce = || utils::rand_base64_str(32);
    for (alg, client_kp, _client_jwk, backend_kp, hash_alg) in keys() {
        // GET http://acme-server/directory
        let directory = {
            let resp = json!({
                "newNonce": "https://example.com/acme/new-nonce",
                "newAccount": "https://example.com/acme/new-account",
                "newOrder": "https://example.com/acme/new-order",
                "newAuthz": "https://example.com/acme/new-authz",
                "revokeCert": "https://example.com/acme/revoke-cert",
                "keyChange": "https://example.com/acme/key-change",
                "meta": {
                    "termsOfService": "https://example.com/acme/terms/2017-5-30",
                    "website": "https://www.example.com/",
                    "caaIdentities": ["example.com"],
                    "externalAccountRequired": false
                }
            });
            let directory = RustyAcme::acme_directory_response(resp);
            assert!(directory.is_ok());
            directory.unwrap()
        };

        // GET http://acme-server/new-nonce
        let previous_nonce = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.2
            prev_nonce()
        };

        // POST http://acme-server/new-account
        let (account, previous_nonce) = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
            let _account_req = RustyAcme::new_account_request(&directory, alg, &client_kp, previous_nonce).unwrap();

            let resp = json!({
                "status": "valid",
                "contact": [
                    "mailto:cert-admin@example.org",
                    "mailto:admin@example.org"
                ],
                "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
            });
            let account = RustyAcme::new_account_response(resp);
            assert!(account.is_ok());
            (account.unwrap(), prev_nonce())
        };

        // POST http://acme-server/new-order
        let (order, order_url, previous_nonce) = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
            let wire_handle = IDP_HOST.to_string();
            let wire_client_id = WIRE_HOST.to_string();
            let expiry = core::time::Duration::from_secs(3600); // 1h
            let _order_request = RustyAcme::new_order_request(
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

            let resp = json!({
                "status": "pending",
                "expires": "2037-01-05T14:09:07.99Z",
                "notBefore": "2016-01-01T00:00:00Z",
                "notAfter": "2037-01-08T00:00:00Z",
                "identifiers": [
                    { "type": "dns", "value": "www.example.org" },
                    { "type": "dns", "value": "example.org" }
                ],
                "authorizations": [
                    "https://example.com/acme/authz/PAniVnsZcis",
                    "https://example.com/acme/authz/r4HqLzrSrpI"
                ],
                "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
            });

            let order_url = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth"
                .parse()
                .unwrap();

            let new_order = RustyAcme::new_order_response(resp);
            assert!(new_order.is_ok());
            (new_order.unwrap(), order_url, prev_nonce())
        };

        // POST http://acme-server/authz1
        let (authz1, previous_nonce) = {
            let authz1_url = order.authorizations.get(0).unwrap();
            let _authz1_req =
                RustyAcme::new_authz_request(authz1_url, &account, alg, &client_kp, previous_nonce).unwrap();

            let resp = json!({
                "status": "pending",
                "expires": "2016-01-02T14:09:30Z",
                "identifier": {
                  "type": "dns",
                  "value": "www.example.org"
                },
                "challenges": [
                  {
                    "type": "wire-http-01",
                    "url": "https://example.com/acme/chall/prV_B7yEyA4",
                    "token": "DGyRejmCefe7v4NfDGDKfA"
                  }
                ]
            });
            let authz1 = RustyAcme::new_authz_response(resp);
            assert!(authz1.is_ok());
            (authz1.unwrap(), prev_nonce())
        };

        // POST http://acme-server/authz2
        let (authz2, previous_nonce) = {
            let authz2_url = order.authorizations.get(1).unwrap();
            let _authz2_req =
                RustyAcme::new_authz_request(authz2_url, &account, alg, &client_kp, previous_nonce).unwrap();

            let resp = json!({
                "status": "pending",
                "expires": "2016-01-02T14:09:30Z",
                "identifier": {
                  "type": "dns",
                  "value": "example.org"
                },
                "challenges": [
                  {
                    "type": "wire-oidc-01",
                    "url": "https://example.com/acme/chall/prV_B7yEyA4",
                    "token": "DGyRejmCefe7v4NfDGDKfA"
                  }
                ]
            });
            let authz2 = RustyAcme::new_authz_response(resp);
            assert!(authz2.is_ok());
            (authz2.unwrap(), prev_nonce())
        };

        // extract challenges
        let (client_id_chall, handle_chall) = {
            match (authz1.identifier.value(), authz2.identifier.value()) {
                (client_id, handle) if (client_id, handle) == (WIRE_HOST, IDP_HOST) => (
                    authz1.wire_http_challenge().cloned().unwrap(),
                    authz2.wire_oidc_challenge().cloned().unwrap(),
                ),
                (handle, client_id) if (client_id, handle) == (WIRE_HOST, IDP_HOST) => (
                    authz1.wire_oidc_challenge().cloned().unwrap(),
                    authz2.wire_http_challenge().cloned().unwrap(),
                ),
                _ => panic!(""),
            }
        };

        // HEAD http://wire-server/nonce
        let backend_nonce = { BackendNonce::from(utils::rand_base64_str(32)) };

        // POST http://wire-server/client-dpop-token
        let _access_token = {
            let user = uuid::Uuid::new_v4().to_string();
            let client_id = random::<u64>();
            let domain = "example.org";
            let alice = ClientId::try_new(&user, client_id, domain).unwrap();
            let dpop_url = format!("https://example.org/clients/{client_id}/access-token");
            let htu: Htu = dpop_url.as_str().try_into().unwrap();
            let htm = Htm::Post;
            let acme_challenge: AcmeNonce = client_id_chall.token.as_str().into();
            let dpop = Dpop {
                challenge: acme_challenge.clone(),
                htm,
                htu: htu.clone(),
                extra_claims: None,
            };
            let expiry = Duration::from_days(1).into();
            let client_dpop_token =
                RustyJwtTools::generate_dpop_token(dpop, alice, backend_nonce.clone(), expiry, alg, &client_kp)
                    .unwrap();

            // this is done by wire-server
            let leeway: u16 = 5;
            let max_expiration: u64 = 2136351646; // somewhere in 2037
            let access_token = RustyJwtTools::generate_access_token(
                client_dpop_token.as_str(),
                alice,
                backend_nonce,
                htu,
                htm,
                leeway,
                max_expiration,
                backend_kp,
                hash_alg,
            )
            .unwrap();
            access_token
        };

        // POST http://acme-server/challenge
        let previous_nonce = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
            let _handle_chall_req =
                RustyAcme::new_chall_request(handle_chall, &account, alg, &client_kp, previous_nonce).unwrap();
            let resp = json!({
                "type": "wire-oidc-01",
                "url": "https://example.com/acme/chall/prV_B7yEyA4",
                "status": "valid",
                "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
            });
            let _resp = RustyAcme::new_chall_response(resp).unwrap();
            prev_nonce()
        };

        // POST http://acme-server/order (verify status)
        let (order, previous_nonce) = {
            let _get_order_req =
                RustyAcme::check_order_request(order_url, &account, alg, &client_kp, previous_nonce).unwrap();

            let resp = json!({
                "status": "ready",
                "expires": "2037-01-05T14:09:07.99Z",
                "notBefore": "2016-01-01T00:00:00Z",
                "notAfter": "2037-01-08T00:00:00Z",
                "identifiers": [
                    { "type": "dns", "value": "www.example.org" },
                    { "type": "dns", "value": "example.org" }
                ],
                "authorizations": [
                    "https://example.com/acme/authz/PAniVnsZcis",
                    "https://example.com/acme/authz/r4HqLzrSrpI"
                ],
                "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
            });
            let order = RustyAcme::check_order_response(resp).unwrap();
            // verify ready
            (order, prev_nonce())
        };

        // POST http://acme-server/finalize
        let (finalize, previous_nonce) = {
            let domains = vec![WIRE_HOST.to_string(), IDP_HOST.to_string()];
            let _finalize_req =
                RustyAcme::finalize_req(domains, order, &account, alg, &client_kp, previous_nonce).unwrap();

            let resp = json!({
                "status": "valid",
                "expires": "2016-01-20T14:09:07.99Z",
                "notBefore": "2016-01-01T00:00:00Z",
                "notAfter": "2016-01-08T00:00:00Z",
                "identifiers": [
                    { "type": "dns", "value": "www.example.org" },
                    { "type": "dns", "value": "example.org" }
                ],
                "authorizations": [
                    "https://example.com/acme/authz/PAniVnsZcis",
                    "https://example.com/acme/authz/r4HqLzrSrpI"
                ],
                "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",
                "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
            });
            let finalize = RustyAcme::finalize_response(resp).unwrap();
            (finalize, prev_nonce())
        };

        // GET http://acme-server/certificate
        let _certificates = {
            let _certificate_req =
                RustyAcme::certificate_req(finalize, account, alg, &client_kp, previous_nonce).unwrap();

            let resp = r#"-----BEGIN CERTIFICATE-----
MIIB7DCCAZKgAwIBAgIRAIErw6bhWUQXxeS0xsdMvyEwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwMTA1MjAwMDQxWhcNMjMwMTA2MjAwMTQxWjAAMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEq9rybsGxEBLpn6Tx5LHladF6jw3Vuc5Yr27NKRLwFWbCUXUmwApv
arn35O3u+w1CnwTyCA2tt605GhvbL039AKOBvjCBuzAOBgNVHQ8BAf8EBAMCB4Aw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBTlxc6/odBa
eTAlHYZcoCeFyn0BCjAfBgNVHSMEGDAWgBRsNCwlQHq5dXTxxfhhKHYOFQtlXzAm
BgNVHREBAf8EHDAagg5sb2dpbi53aXJlLmNvbYIId2lyZS5jb20wIgYMKwYBBAGC
pGTGKEABBBIwEAIBBgQJd2lyZS1hY21lBAAwCgYIKoZIzj0EAwIDSAAwRQIgAwhX
Jvnc7hOUOT41I35ZZi5rgJKF4FtMyImvCFY1UQ0CIQC2k+k7uqwgMRp10z3xzWHE
3sMuOBJG/UAR+VtFvCmGSA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAOzPGCzghRSFfL08VAXS/DQwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDEwNTIw
MDEzOFoXDTMzMDEwMjIwMDEzOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARc
LwmNj175LF1Wd+CC7lVGVUzr/ys+mR7XbN0csRx3okfJKZFxx0PGs6JO+pTUG0C3
27GSfNQU+2tz5fnrmahxo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUbDQsJUB6uXV08cX4YSh2DhULZV8wHwYDVR0jBBgw
FoAUuL+rLbn8HEXbB6Pw5wzGhGjlE24wCgYIKoZIzj0EAwIDSAAwRQIgEltwd9QL
LdKVfvqnrQ/H3a4uIPgJz0+YQI1Y0eYuMB4CIQCYMrIYAqC7nqjqVXrROShrISO+
S26guHAMqXDlqqueOQ==
-----END CERTIFICATE-----"#;
            RustyAcme::certificate_response(resp.to_string()).unwrap()
        };
    }
}
