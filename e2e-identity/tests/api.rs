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

pub const WIRE_HOST: &str = "example.org";

#[test]
#[wasm_bindgen_test]
fn e2e_api() {
    let prev_nonce = || utils::rand_base64_str(32);
    for (alg, client_kp, _, backend_kp, _, hash_alg, ..) in keys() {
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
            let display_name = "Smith, Alice M (QA)".to_string();
            let domain = WIRE_HOST.to_string();
            let handle = uuid::Uuid::new_v4();
            let client_id = random::<u64>();
            let qualified_client_id =
                ClientId::try_from_raw_parts(handle.as_bytes(), client_id, domain.as_bytes()).unwrap();
            let qualified_handle = "impp:wireapp=alice.smith.qa@example.com".to_string();
            let expiry = core::time::Duration::from_secs(3600); // 1h
            let _order_request = RustyAcme::new_order_request(
                display_name,
                domain.clone(),
                qualified_client_id,
                qualified_handle,
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
              "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
              "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
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

            let new_order = RustyAcme::new_order_response(resp);
            assert!(new_order.is_ok());
            (new_order.unwrap(), order_url, prev_nonce())
        };

        // POST http://acme-server/authz
        let (authz, previous_nonce) = {
            let authz_url = order.authorizations.get(0).unwrap();
            let _authz_req =
                RustyAcme::new_authz_request(authz_url, &account, alg, &client_kp, previous_nonce).unwrap();
            let resp = json!({
              "status": "pending",
              "expires": "2023-02-10T14:59:20Z",
              "challenges": [
                {
                  "type": "wire-oidc-01",
                  "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                  "status": "pending",
                  "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY"
                },
                {
                  "type": "wire-dpop-01",
                  "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                  "status": "pending",
                  "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY"
                }
              ],
              "identifier": {
                "type": "wireapp-id",
                "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
              }
            });
            let authz = RustyAcme::new_authz_response(resp);
            assert!(authz.is_ok());
            (authz.unwrap(), prev_nonce())
        };

        // extract challenges
        let (dpop_chall, oidc_chall) = {
            (
                authz.wire_dpop_challenge().cloned().unwrap(),
                authz.wire_oidc_challenge().cloned().unwrap(),
            )
        };

        // HEAD http://wire-server/nonce
        let backend_nonce = { BackendNonce::from(utils::rand_base64_str(32)) };

        // POST http://wire-server/client-dpop-token
        let access_token = {
            let user = uuid::Uuid::new_v4().to_string();
            let client_id = random::<u64>();
            let domain = WIRE_HOST;
            let alice = ClientId::try_new(&user, client_id, domain).unwrap();
            let dpop_url = format!("https://{WIRE_HOST}/clients/{client_id}/access-token");
            let htu: Htu = dpop_url.as_str().try_into().unwrap();
            let htm = Htm::Post;
            let acme_challenge: AcmeNonce = dpop_chall.token.as_str().into();
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

        // Dpop challenge POST http://acme-server/challenge
        let previous_nonce = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
            let _handle_chall_req =
                RustyAcme::dpop_chall_request(access_token, dpop_chall, &account, alg, &client_kp, previous_nonce)
                    .unwrap();
            let resp = json!({
              "type": "wire-dpop-01",
              "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/xfEE0yEYAoce4yoTKg9HoNj9fGllbWhj",
              "status": "valid",
              "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
            });
            let _resp = RustyAcme::new_chall_response(resp).unwrap();
            prev_nonce()
        };

        // Oidc challenge POST http://acme-server/challenge
        let previous_nonce = {
            // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
            let id_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU4NTMyODYsImV4cCI6MTY3NTkzOTY4NiwibmJmIjoxNjc1ODUzMjg2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6IndpcmVhcHAtaWQ6TlRReU1tTTNaVFEyTmpCa05HRmhOV0UxTnpsaVpXUmpZemRrTXpjeU5tVS9jZGQ5NWI5ODBlZWQ2NjIxQGV4YW1wbGUuY29tIiwiYXVkIjoiaHR0cDovL2lkcC8iLCJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSIsImhhbmRsZSI6IndpcmVhcHA6YWxpY2Uuc21pdGgucWFAZXhhbXBsZS5jb20iLCJrZXlhdXRoIjoiMkZwVE9tTlF2TmZXRGt0Tld0MW9JSm5qTEUzTWt5RmIubDN4N2h4N0dxYXprbXE3ZDJvRFRLMm4zZVVuMDZvS0lGMkx4VFRITlFIOCJ9.wm8jbM7X_RwJXMG3XVazVDTlw5gDaOkWGWK0cF0ZY3fwEfGsHhIUPCoEA20ztV7O8zKnUSTDL7xd3jejNZBsCw".to_string();
            let _handle_chall_req =
                RustyAcme::oidc_chall_request(id_token, oidc_chall, &account, alg, &client_kp, previous_nonce).unwrap();
            let resp = json!({
              "type": "wire-oidc-01",
              "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
              "status": "valid",
              "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
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
              "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
              "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
                }
              ],
              "authorizations": [
                "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
              ],
              "expires": "2032-02-10T14:59:20Z",
              "notBefore": "2013-02-09T14:59:20.442908Z",
              "notAfter": "2032-02-09T15:59:20.442908Z"
            });
            let order = RustyAcme::check_order_response(resp).unwrap();
            // verify ready
            (order, prev_nonce())
        };

        // POST http://acme-server/finalize
        let (finalize, previous_nonce) = {
            let _finalize_req = RustyAcme::finalize_req(order, &account, alg, &client_kp, previous_nonce).unwrap();

            let resp = json!({
              "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
              "status": "valid",
              "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
              "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
                }
              ],
              "authorizations": [
                "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
              ],
              "expires": "2032-02-10T14:59:20Z",
              "notBefore": "2013-02-09T14:59:20.442908Z",
              "notAfter": "2032-02-09T15:59:20.442908Z"
            });
            let finalize = RustyAcme::finalize_response(resp).unwrap();
            (finalize, prev_nonce())
        };

        // GET http://acme-server/certificate
        let _certificates = {
            let _certificate_req =
                RustyAcme::certificate_req(finalize, account, alg, &client_kp, previous_nonce).unwrap();

            let resp = r#"-----BEGIN CERTIFICATE-----
MIICaDCCAg6gAwIBAgIQH3CanUzXJpP+pbXNUVpp7TAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzAyMDkxNDU5MjBaFw0yMzAyMDkxNTU5MjBaMDQxFDASBgNVBAoTC2V4YW1wbGUu
Y29tMRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAVCw/
lxGMV2Zx723yhVv94Fb+LCARV0h1F1/zmvRZGy6jggE1MIIBMTAOBgNVHQ8BAf8E
BAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSr
zp+ejXBydYcjmBr4cTp931ceUTAfBgNVHSMEGDAWgBS04sLODR52O3cPNlNdK3f6
tinkIzCBoAYDVR0RBIGYMIGVghNzbWl0aCwgYWxpY2UgbSAocWEphidpbXBwOndp
cmVhcHA9YWxpY2Uuc21pdGgucWFAZXhhbXBsZS5jb22GVWltcHA6d2lyZWFwcD1u
amppeXRyam10aXlvZGpqbmR5NXltZTVuZ3ptbWpoaG5qZmtvZGEwbmprL2QyYmEy
YzFhNTc1ODhlZTRAZXhhbXBsZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQE
YWNtZQQAMAoGCCqGSM49BAMCA0gAMEUCIG6cfFB2En9YKVPuQhEZcoELtZbkFsTJ
PeWa6zTkrI47AiEApQP8piMQWhofGLL6oTWoks3+6JfPRWZP9Z7JkhdiBmY=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQP5i/9/vpRPXels/aSa5lZTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMjA5MTQ1
OTE4WhcNMzMwMjA2MTQ1OTE4WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFNd
5wbJjtVSmXxftBSmHgTJS3F1LGMlb789KtcSTjjJVO//VNdg3XDYvhHyitHx/Bz+
5yxkrPaRzeGeJkZfkuejZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBS04sLODR52O3cPNlNdK3f6tinkIzAfBgNVHSMEGDAW
gBTqNi9/bemraZjLYA8TGat3ianEizAKBggqhkjOPQQDAgNIADBFAiEAuo8JLvys
IvUCvPUJi1++80IgPeRxxRvn5zlHDh3qKZECIHONc1xx1ixlIyp9mOtdeTvG5Dql
RheWYpDHRiLax1Id
-----END CERTIFICATE-----"#;
            RustyAcme::certificate_response(resp.to_string()).unwrap()
        };
    }
}
