use jwt_simple::prelude::*;
use rusty_jwt_tools::prelude::*;
use serde_json::json;
use utils::keys::enrollments;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[path = "utils/mod.rs"]
mod utils;

#[test]
#[wasm_bindgen_test]
fn e2e_api() {
    let prev_nonce = || utils::rand_base64_str(32);
    for (enrollment, backend_kp) in enrollments() {
        let user_id = "T4Coy4vdRzianwfOgXpn6A";
        let device_id = "a338e9ea9e87fec";
        let domain = "wire.org";
        let qualified_client_id = format!("{user_id}:{device_id}@{domain}");

        let display_name = "Alice Smith".to_string();
        let qualified_handle = "alice_wire";

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
            enrollment.acme_directory_response(resp).unwrap()
        };

        // GET http://acme-server/new-nonce
        let previous_nonce = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.2
            prev_nonce()
        };

        // POST http://acme-server/new-account
        let (account, previous_nonce) = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
            let _account_req = enrollment.acme_new_account_request(&directory, previous_nonce).unwrap();

            let resp = json!({
                "status": "valid",
                "contact": [
                    "mailto:cert-admin@example.org",
                    "mailto:admin@example.org"
                ],
                "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
            });
            let account = enrollment.acme_new_account_response(resp).unwrap();
            (account, prev_nonce())
        };

        // POST http://acme-server/new-order
        let (order, order_url, previous_nonce) = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
            let expiry = core::time::Duration::from_secs(3600); // 1h
            let _order_request = enrollment
                .acme_new_order_request(
                    &display_name,
                    &qualified_client_id,
                    qualified_handle,
                    expiry,
                    &directory,
                    &account,
                    previous_nonce,
                )
                .unwrap();

            let resp = json!({
              "status": "pending",
              "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
              "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
                }
              ],
              "authorizations": [
                "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
              ],
              "expires": "2032-02-10T14:59:20Z",
              "notBefore": "2013-02-09T14:59:20.442908Z",
              "notAfter": "2032-02-09T15:59:20.442908Z"
            });

            let order_url = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth"
                .parse()
                .unwrap();

            let new_order = enrollment.acme_new_order_response(resp).unwrap();
            (new_order, order_url, prev_nonce())
        };

        // POST http://acme-server/authz
        let (authz, previous_nonce) = {
            let authz_url = order.authorizations.get(0).unwrap();
            let _authz_req = enrollment
                .acme_new_authz_request(authz_url, &account, previous_nonce)
                .unwrap();

            let resp = json!({
              "status": "pending",
              "expires": "2023-02-10T14:59:20Z",
              "challenges": [
                {
                  "type": "wire-oidc-01",
                  "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                  "status": "pending",
                  "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                  "target": "https://dex/dex"
                },
                {
                  "type": "wire-dpop-01",
                  "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                  "status": "pending",
                  "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                  "target": "https://wire.com/clients/a338e9ea9e87fec/access-token"
                }
              ],
              "identifier": {
                "type": "wireapp-id",
                "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
              }
            });
            let authz = enrollment.acme_new_authz_response(resp).unwrap();
            (authz, prev_nonce())
        };

        // extract challenges
        let (dpop_chall, oidc_chall) = {
            (
                authz.wire_dpop_challenge.clone().unwrap(),
                authz.wire_oidc_challenge.clone().unwrap(),
            )
        };

        // HEAD http://wire-server/nonce
        let backend_nonce = { BackendNonce::from(utils::rand_base64_str(32)) };

        // POST http://wire-server/client-dpop-token
        let access_token = {
            let expiry = Duration::from_days(1).into();
            let client_dpop_token = enrollment
                .new_dpop_token(
                    &qualified_client_id.clone(),
                    &dpop_chall,
                    backend_nonce.to_string(),
                    expiry,
                )
                .unwrap();

            // this is done by wire-server
            let leeway: u16 = 5;
            let max_expiration: u64 = 2136351646; // somewhere in 2037
            let htm = Htm::Post;
            let htu: Htu = dpop_chall.target.clone().into();
            let alice = ClientId::try_from_qualified(&qualified_client_id).unwrap();
            let access_token = RustyJwtTools::generate_access_token(
                client_dpop_token.as_str(),
                &alice,
                backend_nonce,
                htu,
                htm,
                leeway,
                max_expiration,
                backend_kp,
                enrollment.hash_alg,
                5,
            )
            .unwrap();
            access_token
        };

        // Dpop challenge POST http://acme-server/challenge
        let previous_nonce = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
            let _handle_chall_req = enrollment
                .acme_dpop_challenge_request(access_token, &dpop_chall, &account, previous_nonce)
                .unwrap();

            let resp = json!({
              "type": "wire-dpop-01",
              "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/xfEE0yEYAoce4yoTKg9HoNj9fGllbWhj",
              "status": "valid",
              "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
            });
            enrollment.acme_new_challenge_response(resp).unwrap();
            prev_nonce()
        };

        // Oidc challenge POST http://acme-server/challenge
        let previous_nonce = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
            let id_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU4NTMyODYsImV4cCI6MTY3NTkzOTY4NiwibmJmIjoxNjc1ODUzMjg2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6IndpcmVhcHAtaWQ6TlRReU1tTTNaVFEyTmpCa05HRmhOV0UxTnpsaVpXUmpZemRrTXpjeU5tVS9jZGQ5NWI5ODBlZWQ2NjIxQGV4YW1wbGUuY29tIiwiYXVkIjoiaHR0cDovL2lkcC8iLCJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSIsImhhbmRsZSI6IndpcmVhcHA6YWxpY2Uuc21pdGgucWFAZXhhbXBsZS5jb20iLCJrZXlhdXRoIjoiMkZwVE9tTlF2TmZXRGt0Tld0MW9JSm5qTEUzTWt5RmIubDN4N2h4N0dxYXprbXE3ZDJvRFRLMm4zZVVuMDZvS0lGMkx4VFRITlFIOCJ9.wm8jbM7X_RwJXMG3XVazVDTlw5gDaOkWGWK0cF0ZY3fwEfGsHhIUPCoEA20ztV7O8zKnUSTDL7xd3jejNZBsCw".to_string();
            let _handle_chall_req = enrollment
                .acme_oidc_challenge_request(id_token, &oidc_chall, &account, previous_nonce)
                .unwrap();

            let resp = json!({
              "type": "wire-oidc-01",
              "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
              "status": "valid",
              "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
            });
            enrollment.acme_new_challenge_response(resp).unwrap();
            prev_nonce()
        };

        // POST http://acme-server/order (verify status)
        let (order, previous_nonce) = {
            let _get_order_req = enrollment
                .acme_check_order_request(order_url, &account, previous_nonce)
                .unwrap();

            let resp = json!({
              "status": "ready",
              "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
              "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
                }
              ],
              "authorizations": [
                "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
              ],
              "expires": "2032-02-10T14:59:20Z",
              "notBefore": "2013-02-09T14:59:20.442908Z",
              "notAfter": "2032-02-09T15:59:20.442908Z"
            });
            let order = enrollment.acme_check_order_response(resp).unwrap();
            // verify ready
            (order, prev_nonce())
        };

        // POST http://acme-server/finalize
        let (finalize, previous_nonce) = {
            let _finalize_req = enrollment
                .acme_finalize_request(&order, &account, previous_nonce)
                .unwrap();

            let resp = json!({
              "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
              "status": "valid",
              "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
              "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
                }
              ],
              "authorizations": [
                "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
              ],
              "expires": "2032-02-10T14:59:20Z",
              "notBefore": "2013-02-09T14:59:20.442908Z",
              "notAfter": "2032-02-09T15:59:20.442908Z"
            });
            let finalize = enrollment.acme_finalize_response(resp).unwrap();
            (finalize, prev_nonce())
        };

        // GET http://acme-server/certificate
        let _certificates = {
            let _certificate_req = enrollment
                .acme_x509_certificate_request(finalize, account, previous_nonce)
                .unwrap();

            let resp = r#"-----BEGIN CERTIFICATE-----
MIICDDCCAbOgAwIBAgIRAPByYiuFhbbYasW+GKz5FBkwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwNzMxMTQwMjA4WhcNMzMwNzI4MTQwMjA4WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQAF/hZvvmRkWMzqZ5jU
LnGKO+y8G/Vz+olfTknk7c/8IqOB5TCB4jAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFGhAhRlgprn/FUxPfL+ehHvvAigpMB8G
A1UdIwQYMBaAFB81Yl+jcBh8rnCo9MJtkZ+2vq5YMFwGA1UdEQRVMFOGFWltOndp
cmVhcHA9YWxpY2Vfd2lyZYY6aW06d2lyZWFwcD1UNENveTR2ZFJ6aWFud2ZPZ1hw
bjZBL2EzMzhlOWVhOWU4N2ZlY0B3aXJlLmNvbTAdBgwrBgEEAYKkZMYoQAEEDTAL
AgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgCP+OnliYCy7PKs3rt+x4zUuF
e2grybnLl5fsak6lFPUCIE4T8ZMlKkOZ9xeYdTlrUPT67hc++ZRAtcU03Kqiz8sm
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBuTCCAV6gAwIBAgIQfYC2CCR4Uw9GPkJ2nSq8ATAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNzMxMTQw
MjA2WhcNMzMwNzI4MTQwMjA2WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCOc
sqiFG9+GHjqHP26inah0Vyxt8IoZykStaLLskp2IDB8/px2k6TbNV5areq09+g26
QTxTzlaBWUE/Y9rCoqmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQfNWJfo3AYfK5wqPTCbZGftr6uWDAfBgNVHSMEGDAW
gBQgDq04Td1mq9ala953Mito5QHARjAKBggqhkjOPQQDAgNJADBGAiEA+MIEAiG2
DxMYFdlfpS2zs/Ed+1Co/pkE3iTlbhcQK6ACIQD1Xhg2dteHl4bILtK0aVH1BRtD
jHdSVZh5wt4eD7IMag==
-----END CERTIFICATE-----"#;
            enrollment
                .acme_x509_certificate_response(resp.to_string(), order)
                .unwrap()
        };
    }
}
