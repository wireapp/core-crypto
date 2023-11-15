use jwt_simple::prelude::*;
use serde_json::json;
use wasm_bindgen_test::*;

use rusty_jwt_tools::prelude::*;
use utils::keys::enrollments;

wasm_bindgen_test_configure!(run_in_browser);

#[path = "utils/mod.rs"]
mod utils;

#[test]
#[wasm_bindgen_test]
fn e2e_api() {
    let prev_nonce = || utils::rand_base64_str(32);
    for (enrollment, backend_kp) in enrollments() {
        let user_id = "yl-8A_wZSfaS2uV8VuMEBw";
        let device_id = "7e79723a8bdc694f";
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
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
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
                  "target": "https://wire.com/clients/7e79723a8bdc694f/access-token"
                }
              ],
              "identifier": {
                "type": "wireapp-id",
                "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
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
                core::time::Duration::from_secs(360),
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
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
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
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
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
MIICGDCCAb+gAwIBAgIQHhoe3LLRoHP+EPY4KOTgATAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzExMTYxMDM3MjZaFw0zMzExMTMxMDM3MjZaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhANmHK7rIOLVhj/vmKmK1
qei8Dor8Lu/FPOnXmKLZGKrfo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUFlquvWRvc3MxFaLrNgzv+UdGoaswHwYD
VR0jBBgwFoAUz40pQ/qEp4eFDfctCF0jmJB+5xswaQYDVR0RBGIwYIYhaW06d2ly
ZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29thjtpbTp3aXJlYXBwPXlsLThBX3da
U2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgRqbsOAF7
OseMTgkjrKe3UO/UjDUGzW+jlDWOGLZsh5ECIDdNastqkvwOGfbWaeh+IuM6/oBz
flIOs9TQGOVc0YL1
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRALZ7S0CrN0AU7he5I5RE7kUwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMTExNjEw
MzcyNFoXDTMzMTExMzEwMzcyNFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARX
N+Bn/11sYUO48us2X+JrOBMXf/Gn9kV1D+fp1SQ3JzQl/KEwmtG3OJHB6ljtQiIF
QTKP2xV8Zu9vK1Z8zD43o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUz40pQ/qEp4eFDfctCF0jmJB+5xswHwYDVR0jBBgw
FoAUCseuIlZpBnsVzFcCJvAXBodYgo0wCgYIKoZIzj0EAwIDSAAwRQIgfR0sHfuG
N2EBypbVEz5g7zRMQsbKCUxUAW5cNiEc9IICIQDCDymSCXPFRw1QNv/7WQXATH1L
hQc4PK0oC9I4QpceyA==
-----END CERTIFICATE-----"#;
            enrollment
                .acme_x509_certificate_response(resp.to_string(), order)
                .unwrap()
        };
    }
}
