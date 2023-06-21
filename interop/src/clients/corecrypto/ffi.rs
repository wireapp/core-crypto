// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use color_eyre::eyre::Result;
use core_crypto::prelude::MlsCiphersuite;
use serde_json::json;

use core_crypto_ffi::{CiphersuiteName, CoreCrypto, CustomConfiguration, Invitee, MlsCredentialType};

use crate::clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient};

#[derive(Debug)]
pub struct CoreCryptoFfiClient<'a> {
    cc: CoreCrypto<'a>,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: u16,
}

impl<'a> CoreCryptoFfiClient<'a> {
    pub async fn new() -> Result<CoreCryptoFfiClient<'a>> {
        let client_id = uuid::Uuid::new_v4();
        let ciphersuite = CiphersuiteName::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let cc = CoreCrypto::new(
            "path",
            "key",
            &client_id.as_bytes().to_vec().into(),
            vec![ciphersuite],
            None,
        )?;
        Ok(Self {
            cc,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: 0,
        })
    }

    pub async fn new_deferred() -> Result<CoreCryptoFfiClient<'a>> {
        let client_id = uuid::Uuid::new_v4();
        let ciphersuite = CiphersuiteName::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let cc = CoreCrypto::deferred_init("path", "key", vec![ciphersuite], None)?;
        Ok(Self {
            cc,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: 0,
        })
    }
}

#[async_trait::async_trait(?Send)]
impl<'a> EmulatedClient for CoreCryptoFfiClient<'a> {
    fn client_name(&self) -> &str {
        "CoreCrypto::native"
    }

    fn client_type(&self) -> EmulatedClientType {
        EmulatedClientType::Native
    }

    fn client_id(&self) -> &[u8] {
        self.client_id.as_slice()
    }

    fn client_protocol(&self) -> EmulatedClientProtocol {
        EmulatedClientProtocol::MLS | EmulatedClientProtocol::PROTEUS
    }

    async fn wipe(mut self) -> Result<()> {
        Ok(self.cc.wipe()?)
    }
}

#[async_trait::async_trait(?Send)]
impl<'a> EmulatedMlsClient for CoreCryptoFfiClient<'a> {
    async fn get_keypackage(&mut self) -> Result<Vec<u8>> {
        let ciphersuite = CiphersuiteName::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let credential_type = MlsCredentialType::Basic;
        let mut kps = self.cc.client_keypackages(ciphersuite, credential_type, 1)?;
        Ok(kps.remove(0))
    }

    async fn add_client(&mut self, conversation_id: &[u8], client_id: &[u8], kp: &[u8]) -> Result<Vec<u8>> {
        if !self.cc.conversation_exists(conversation_id.to_vec()) {
            let cfg = core_crypto_ffi::ConversationConfiguration {
                ciphersuite: Some(CiphersuiteName::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
                external_senders: vec![],
                custom: CustomConfiguration {
                    key_rotation_span: None,
                    wire_policy: None,
                },
            };
            self.cc.create_conversation(conversation_id.to_vec(), cfg)?;
        }

        let invitee = Invitee {
            id: client_id.into(),
            kp: kp.to_vec(),
        };
        let welcome = self
            .cc
            .add_clients_to_conversation(conversation_id.to_vec(), vec![invitee])?;

        Ok(welcome.welcome)
    }

    async fn kick_client(&mut self, conversation_id: &[u8], client_id: &[u8]) -> Result<Vec<u8>> {
        let commit = self
            .cc
            .remove_clients_from_conversation(conversation_id.to_vec(), vec![client_id.into()])?;

        Ok(commit.commit)
    }

    async fn process_welcome(&mut self, welcome: &[u8]) -> Result<Vec<u8>> {
        let cfg = CustomConfiguration {
            key_rotation_span: None,
            wire_policy: None,
        };
        Ok(self.cc.process_welcome_message(welcome, cfg)?)
    }

    async fn encrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cc.encrypt_message(conversation_id.to_vec(), message)?)
    }

    async fn decrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.cc.decrypt_message(conversation_id.to_vec(), message)?.message)
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl<'a> crate::clients::EmulatedProteusClient for CoreCryptoFfiClient<'a> {
    async fn init(&mut self) -> Result<()> {
        Ok(self.cc.proteus_init()?)
    }

    async fn get_prekey(&mut self) -> Result<Vec<u8>> {
        self.prekey_last_id += 1;
        Ok(self.cc.proteus_new_prekey(self.prekey_last_id)?)
    }

    async fn session_from_prekey(&mut self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let _ = self.cc.proteus_session_from_prekey(session_id, prekey)?;
        Ok(())
    }

    async fn session_from_message(&mut self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cc.proteus_session_from_message(session_id, message)?)
    }

    async fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cc.proteus_encrypt(session_id, plaintext)?)
    }

    async fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cc.proteus_decrypt(session_id, ciphertext)?)
    }

    async fn fingerprint(&self) -> Result<String> {
        Ok(self.cc.proteus_fingerprint()?)
    }
}

#[async_trait::async_trait(?Send)]
impl<'a> crate::clients::EmulatedE2eIdentityClient for CoreCryptoFfiClient<'a> {
    async fn e2ei_new_enrollment(&mut self, ciphersuite: MlsCiphersuite) -> Result<()> {
        let display_name = "Alice Smith".to_string();
        let domain = "wire.com";
        let client_id = format!("NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg:6c1866f567616f31@{domain}");
        let handle = "alice_wire".to_string();
        let expiry = 90;
        let ciphersuite = ciphersuite.into();

        let enrollment = self
            .cc
            .e2ei_new_enrollment(client_id, display_name, handle, expiry, ciphersuite)?;
        let directory = json!({
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order"
        });
        let directory = serde_json::to_vec(&directory)?;
        enrollment.directory_response(directory)?;

        let previous_nonce = "dmVQallIV29ZZkcwVkNLQTRKbG9HcVdyTWU5WEszdTE";

        enrollment.new_account_request(previous_nonce.to_string())?;
        let account_resp = json!({
            "status": "valid",
            "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
        });
        let account_resp = serde_json::to_vec(&account_resp)?;
        enrollment.new_account_response(account_resp)?;

        let _order_req = enrollment.new_order_request(previous_nonce.to_string())?;

        let order_resp = json!({
            "status": "pending",
            "expires": "2037-01-05T14:09:07.99Z",
            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2037-01-08T00:00:00Z",
            "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
                }
            ],
            "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis",
            ],
            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        });
        let order_resp = serde_json::to_vec(&order_resp)?;
        let new_order = enrollment.new_order_response(order_resp)?;

        let order_url = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";

        let authz_url = new_order.authorizations.get(0).unwrap();
        let _authz_req = enrollment.new_authz_request(authz_url.to_string(), previous_nonce.to_string())?;

        let authz_resp = json!({
            "status": "pending",
            "expires": "2016-01-02T14:09:30Z",
            "identifier": {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            },
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
                "target": "https://wire.com/clients/6c1866f567616f31/access-token"
              }
            ]
        });
        let authz_resp = serde_json::to_vec(&authz_resp)?;
        enrollment.new_authz_response(authz_resp)?;

        let backend_nonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
        let _dpop_token = enrollment.create_dpop_token(3600, backend_nonce.to_string())?;

        let access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA".to_string();
        let _dpop_chall_req = enrollment.new_dpop_challenge_request(access_token, previous_nonce.to_string())?;
        let dpop_chall_resp = json!({
            "type": "wire-dpop-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "valid",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
        });
        let dpop_chall_resp = serde_json::to_vec(&dpop_chall_resp)?;
        enrollment.new_challenge_response(dpop_chall_resp)?;

        let id_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ".to_string();
        let _oidc_chall_req = enrollment.new_oidc_challenge_request(id_token, previous_nonce.to_string())?;
        let oidc_chall_resp = json!({
            "type": "wire-oidc-01",
            "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
            "status": "valid",
            "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
        });
        let oidc_chall_resp = serde_json::to_vec(&oidc_chall_resp)?;
        enrollment.new_challenge_response(oidc_chall_resp)?;

        let _get_order_req = enrollment.check_order_request(order_url.to_string(), previous_nonce.to_string())?;

        let order_resp = json!({
          "status": "ready",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            }
          ],
          "authorizations": [
            "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        });
        let order_resp = serde_json::to_vec(&order_resp)?;
        enrollment.check_order_response(order_resp)?;

        let _finalize_req = enrollment.finalize_request(previous_nonce.to_string())?;
        let finalize_resp = json!({
          "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
          "status": "valid",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            }
          ],
          "authorizations": [
            "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        });
        let finalize_resp = serde_json::to_vec(&finalize_resp)?;
        enrollment.finalize_response(finalize_resp)?;

        let _certificate_req = enrollment.certificate_request(previous_nonce.to_string())?;

        let certificate_resp = r#"-----BEGIN CERTIFICATE-----
MIICLjCCAdSgAwIBAgIQIi6jHWSEF/LHAkiyoiSHbjAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzA0MDUwOTI2NThaFw0yMzA0MDUxMDI2NThaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGzbFXHk2ngUGpBYzabE
AtDJIefbX1/wDUSDJbEL/nJNo4IBBjCCAQIwDgYDVR0PAQH/BAQDAgeAMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUhifYTPG7M3pyQMrz
HYmakvfDG80wHwYDVR0jBBgwFoAUHPSH1n7X87LAYJnc+cFG2a3ZAQ4wcgYDVR0R
BGswaYZQaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lqazBaR0ZoWkRB
Mk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb22GFWltOndpcmVh
cHA9YWxpY2Vfd2lyZTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYI
KoZIzj0EAwIDSAAwRQIhAKY0Zs8SYwS7mFFenPDoCDHPQbCbV9VdvYpBQncOFD5K
AiAisX68Di4B0dN059YsVDXpM0drnkrVTRKHV+F+ipDjZQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtzCCAV6gAwIBAgIQPbElEJQ58HlbQf7bqrJjXTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNDA1MDky
NjUzWhcNMzMwNDAyMDkyNjUzWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGbM
rA1eqJE9xlGOwO+sYbexThtlU/to9jJj5SBoKPx7Q8QMBlmPTjqDVumXhUvSe+xY
JE7M+lBXfVZCywzIIPWjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQc9IfWftfzssBgmdz5wUbZrdkBDjAfBgNVHSMEGDAW
gBQY+1rDw64QLm/weFQC1mo9y29ddTAKBggqhkjOPQQDAgNHADBEAiARvd7RBuuv
OhUy7ncjd/nzoN5Qs0p6D+ujdSLDqLlNIAIgfkwAAgsQMDF3ClqVM/p9cmS95B0g
CAdIObqPoNL5MJo=
-----END CERTIFICATE-----"#;
        self.cc.e2ei_mls_init(enrollment, certificate_resp.to_string())?;
        Ok(())
    }
}
