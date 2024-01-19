use jwt_simple::prelude::*;
use serde_json::json;
use wasm_bindgen_test::*;

use rusty_jwt_tools::prelude::*;
use utils::keys::enrollments;
use wire_e2e_identity::prelude::E2eiAcmeAuthorization;

wasm_bindgen_test_configure!(run_in_browser);

#[path = "utils/mod.rs"]
mod utils;

#[test]
#[wasm_bindgen_test]
fn e2e_api() {
    let prev_nonce = || utils::rand_base64_str(32);
    for (enrollment, backend_kp, backend_pk, hash_algorithm) in enrollments() {
        let (user_id, device_id) = ("obakjPOHQ2CkNb0rOrNM3A", "ba54e8ace8b4c90d");
        let domain = "wire.org";
        let qualified_client_id = format!("{user_id}:{device_id}@{domain}");

        let display_name = "Alice Smith";
        let handle = Handle::from("alice_wire");
        let qualified_handle = handle.try_to_qualified(domain).unwrap();
        let team = "wire";

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
                    display_name,
                    &qualified_client_id,
                    qualified_handle.as_str(),
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
                  "type": "wireapp-user",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                },
                {
                  "type": "wireapp-device",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://obakjPOHQ2CkNb0rOrNM3A!ba54e8ace8b4c90d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                }
              ],
              "authorizations": [
                "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw",
                "https://stepca:33016/acme/wire/authz/A0ThZnpZZBpO8quUcdjSMk77dpZVn9Fj"
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
        let dpop_challenge_token = "b1vGm3jV7dbKz84C1XpZTLQQKQWcFFmg";
        let (authz_user, authz_device, previous_nonce) = {
            let [ref authz_user_url, ref authz_device_url] = order.authorizations[..] else {
                unreachable!()
            };
            let _authz_req = enrollment
                .acme_new_authz_request(authz_user_url, &account, previous_nonce.clone())
                .unwrap();

            let resp = json!({
              "status": "pending",
              "expires": "2032-02-10T14:59:20Z",
              "challenges": [
                {
                  "type": "wire-oidc-01",
                  "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                  "status": "pending",
                  "token": "Fvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                  "target": "https://dex/dex"
                }
              ],
              "identifier": {
                "type": "wireapp-user",
                "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
              }
            });
            let authz_user = enrollment.acme_new_authz_response(resp).unwrap();

            let _authz_req = enrollment
                .acme_new_authz_request(authz_device_url, &account, previous_nonce)
                .unwrap();

            let resp = json!({
              "status": "pending",
              "expires": "2032-02-10T14:59:20Z",
              "challenges": [
                {
                  "type": "wire-dpop-01",
                  "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                  "status": "pending",
                  "token": dpop_challenge_token,
                  "target": "https://wire.com/clients/ba54e8ace8b4c90d/access-token"
                }
              ],
              "identifier": {
                "type": "wireapp-device",
                "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://obakjPOHQ2CkNb0rOrNM3A!ba54e8ace8b4c90d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
              }
            });
            let authz_device = enrollment.acme_new_authz_response(resp).unwrap();

            (authz_user, authz_device, prev_nonce())
        };

        // extract challenges
        let oidc_chall = match authz_user {
            E2eiAcmeAuthorization::User { challenge, .. } => challenge,
            _ => unreachable!(),
        };
        let dpop_chall = match authz_device {
            E2eiAcmeAuthorization::Device { challenge, .. } => challenge,
            _ => unreachable!(),
        };

        // HEAD http://wire-server/nonce
        let backend_nonce = { BackendNonce::from(utils::rand_base64_str(32)) };

        // POST http://wire-server/client-dpop-token
        let access_token = {
            let expiry = Duration::from_days(1).into();
            let handle = Handle::try_from(qualified_handle.clone()).unwrap();
            let client_dpop_token = enrollment
                .new_dpop_token(
                    &qualified_client_id.clone(),
                    &dpop_chall,
                    backend_nonce.to_string(),
                    handle.as_str(),
                    Some(team.to_string()),
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
                qualified_handle.clone(),
                team.into(),
                backend_nonce,
                htu,
                htm,
                leeway,
                max_expiration,
                backend_kp.clone(),
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
                .acme_dpop_challenge_request(access_token.clone(), &dpop_chall, &account, previous_nonce)
                .unwrap();

            #[cfg(not(target_family = "wasm"))]
            {
                let access_token_file = std::env::temp_dir().join("access-token.txt");
                std::fs::write(&access_token_file, &access_token).unwrap();

                let backend_pk_file = std::env::temp_dir().join("backend-pk.txt");
                std::fs::write(&backend_pk_file, backend_pk.as_str()).unwrap();

                let client_id = ClientId::try_from_qualified(&qualified_client_id).unwrap();
                let issuer = dpop_chall.target.to_string();

                let (leeway, max_expiry) = (3600, 2136351646);

                let kid = JwkThumbprint::generate(&enrollment.acme_jwk, hash_algorithm)
                    .unwrap()
                    .kid;

                rusty_jwt_cli::access_verify::AccessVerify {
                    access_token: Some(access_token_file),
                    client_id: client_id.to_uri(),
                    handle: qualified_handle.to_string(),
                    challenge: dpop_challenge_token.to_string(),
                    leeway,
                    max_expiry,
                    issuer,
                    hash_algorithm,
                    kid,
                    key: backend_pk_file,
                    api_version: 5,
                }
                .execute()
                .unwrap();
            }

            let resp = json!({
              "type": "wire-dpop-01",
              "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/xfEE0yEYAoce4yoTKg9HoNj9fGllbWhj",
              "status": "valid",
              "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb",
              "target": "http://example.com/target"
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
              "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb",
              "target": "http://example.com/target"
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
                  "type": "wireapp-user",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                },
                {
                  "type": "wireapp-device",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://obakjPOHQ2CkNb0rOrNM3A!ba54e8ace8b4c90d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                }
              ],
              "authorizations": [
                "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw",
                "https://stepca:33016/acme/wire/authz/A0ThZnpZZBpO8quUcdjSMk77dpZVn9Fj"
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
                  "type": "wireapp-user",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                },
                {
                  "type": "wireapp-device",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://obakjPOHQ2CkNb0rOrNM3A!ba54e8ace8b4c90d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                }
              ],
              "authorizations": [
                "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw",
                "https://stepca:33016/acme/wire/authz/A0ThZnpZZBpO8quUcdjSMk77dpZVn9Fj"
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
MIICGjCCAcCgAwIBAgIRAJaZdl+hZDl9qSSju5kmWNAwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMTA1MTQ1MzAyWhcNMzQwMTAyMTQ1MzAyWjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQChy/GdWnVyNKWvsB+D
BoxYb+qpVN9QIBXeYdmp1hobOqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFOM5yRKA3dHSlYnjEzcuWoiMWm+TMB8G
A1UdIwQYMBaAFBP7HtkE3WdbqzE6Ll4aIB2jFM2LMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vb2Jha2pQT0hR
MkNrTmIwck9yTk0zQSUyMWJhNTRlOGFjZThiNGM5MGRAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIDRaadkt
pPSLrZ+qy07VJOhE/ypOS6oDItpaq/HPxoTUAiEA7EKzmAFv+/zIEA7lAZjNJ+x4
dHnOydGcC6TZ9zo0pIM=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAJw/A4JJsAkUUg7yNCc/JW0wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDEwNTE0
NTMwMVoXDTM0MDEwMjE0NTMwMVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQW
Tnwl7P5cet1ZJFi2IE9tWytcRYihWMIa9qMYE/a2155RWGcQ7Svxx3j4wOHktnfY
XFGFhJoLUX12uiyHICzio2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUE/se2QTdZ1urMTouXhogHaMUzYswHwYDVR0jBBgw
FoAUya+rFyef/ata3yF3TknFEeyqFGgwCgYIKoZIzj0EAwIDSAAwRQIgQcCFklhN
VkihH+lXehb6MJ3nbsiyRpbekCwYmUB9vykCIQCkIi/orr5qTGgs/YZlC6uofDFj
ySz3I+2cUu+6ShJhdQ==
-----END CERTIFICATE-----"#;
            enrollment
                .acme_x509_certificate_response(resp.to_string(), order)
                .unwrap()
        };
    }
}
