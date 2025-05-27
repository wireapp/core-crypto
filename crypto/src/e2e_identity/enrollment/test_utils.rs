#[cfg(not(target_family = "wasm"))]
use crate::{KeystoreError, e2e_identity::Error, e2e_identity::refresh_token::RefreshToken};
use crate::{
    RecursiveError,
    e2e_identity::{E2eiEnrollment, Result, id::QualifiedE2eiClientId},
    prelude::{CertificateBundle, MlsCredentialType},
    test_utils::{SessionContext, TestContext, context::TEAM, x509::X509TestChain},
    transaction_context::TransactionContext,
};
use itertools::Itertools as _;
use mls_crypto_provider::PkiKeypair;
#[cfg(not(target_family = "wasm"))]
use openmls_traits::OpenMlsCryptoProvider as _;
use serde_json::json;

pub(crate) const E2EI_DISPLAY_NAME: &str = "Alice Smith";
pub(crate) const E2EI_HANDLE: &str = "alice_wire";
pub(crate) const E2EI_CLIENT_ID: &str = "bd4c7053-1c5a-4020-9559-cd7bf7961954:4959bc6ab12f2846@world.com";
pub(crate) const E2EI_CLIENT_ID_URI: &str = "vUxwUxxaQCCVWc1795YZVA!4959bc6ab12f2846@world.com";
pub(crate) const E2EI_EXPIRY: u32 = 90 * 24 * 3600;
pub(crate) const NEW_HANDLE: &str = "new_alice_wire";
pub(crate) const NEW_DISPLAY_NAME: &str = "New Alice Smith";

impl E2eiEnrollment {
    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }

    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }

    pub(crate) fn handle(&self) -> &str {
        &self.handle
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn team(&self) -> Option<&str> {
        self.team.as_deref()
    }
}

pub(crate) fn init_enrollment(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
    Box::pin(async move {
        let E2eiInitWrapper { context: cc, case } = wrapper;
        let cs = case.ciphersuite();
        cc.e2ei_new_enrollment(
            E2EI_CLIENT_ID.into(),
            E2EI_DISPLAY_NAME.to_string(),
            E2EI_HANDLE.to_string(),
            Some(TEAM.to_string()),
            E2EI_EXPIRY,
            cs,
        )
        .await
        .map_err(RecursiveError::transaction("creating new enrollment"))
        .map_err(Into::into)
    })
}

pub(crate) fn init_activation_or_rotation(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
    Box::pin(async move {
        let E2eiInitWrapper { context: cc, case } = wrapper;
        let cs = case.ciphersuite();
        match case.credential_type {
            MlsCredentialType::Basic => {
                cc.e2ei_new_activation_enrollment(
                    NEW_DISPLAY_NAME.to_string(),
                    NEW_HANDLE.to_string(),
                    Some(TEAM.to_string()),
                    E2EI_EXPIRY,
                    cs,
                )
                .await
            }
            MlsCredentialType::X509 => {
                cc.e2ei_new_rotate_enrollment(
                    Some(NEW_DISPLAY_NAME.to_string()),
                    Some(NEW_HANDLE.to_string()),
                    Some(TEAM.to_string()),
                    E2EI_EXPIRY,
                    cs,
                )
                .await
            }
        }
        .map_err(RecursiveError::transaction("creating new enrollment"))
        .map_err(Into::into)
    })
}

pub(crate) type RestoreFnReturn<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = E2eiEnrollment> + 'a>>;

pub(crate) fn noop_restore(e: E2eiEnrollment, _cc: &TransactionContext) -> RestoreFnReturn<'_> {
    Box::pin(async move { e })
}

pub(crate) type InitFnReturn<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<E2eiEnrollment>> + 'a>>;

/// Helps the compiler with its lifetime inference rules while passing async closures
pub(crate) struct E2eiInitWrapper<'a> {
    pub(crate) context: &'a TransactionContext,
    pub(crate) case: &'a TestContext,
}

pub(crate) async fn e2ei_enrollment<'a>(
    ctx: &'a SessionContext,
    case: &TestContext,
    x509_test_chain: &X509TestChain,
    client_id: Option<&str>,
    #[cfg(not(target_family = "wasm"))] is_renewal: bool,
    #[cfg(target_family = "wasm")] _is_renewal: bool,
    init: impl Fn(E2eiInitWrapper) -> InitFnReturn<'_>,
    // used to verify persisting the instance actually does restore it entirely
    restore: impl Fn(E2eiEnrollment, &'a TransactionContext) -> RestoreFnReturn<'a>,
) -> Result<(E2eiEnrollment, String)> {
    x509_test_chain.register_with_central(&ctx.transaction).await;
    #[cfg(not(target_family = "wasm"))]
    {
        let backend = ctx
            .transaction
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        let keystore = backend.key_store();
        if is_renewal {
            let initial_refresh_token =
                crate::e2e_identity::refresh_token::RefreshToken::from("initial-refresh-token".to_string());
            let initial_refresh_token = core_crypto_keystore::entities::E2eiRefreshToken::from(initial_refresh_token);
            keystore
                .save(initial_refresh_token)
                .await
                .map_err(KeystoreError::wrap("saving refresh token"))?;
        }
    }

    let wrapper = E2eiInitWrapper {
        context: &ctx.transaction,
        case,
    };
    let mut enrollment = init(wrapper).await?;

    #[cfg(not(target_family = "wasm"))]
    {
        let backend = ctx
            .transaction
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        let keystore = backend.key_store();
        if is_renewal {
            assert!(enrollment.refresh_token().is_some());
            assert!(RefreshToken::find(keystore).await.is_ok());
        } else {
            assert!(matches!(
                enrollment.get_refresh_token().unwrap_err(),
                Error::OutOfOrderEnrollment(_)
            ));
            assert!(RefreshToken::find(keystore).await.is_err());
        }
    }

    let (display_name, handle) = (enrollment.display_name.clone(), enrollment.handle.clone());

    let directory = json!({
        "newNonce": "https://example.com/acme/new-nonce",
        "newAccount": "https://example.com/acme/new-account",
        "newOrder": "https://example.com/acme/new-order",
        "revokeCert": "https://example.com/acme/revoke-cert"
    });
    let directory = serde_json::to_vec(&directory)?;
    enrollment.directory_response(directory)?;

    let mut enrollment = restore(enrollment, &ctx.transaction).await;

    let previous_nonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
    let _account_req = enrollment.new_account_request(previous_nonce.to_string())?;

    let account_resp = json!({
        "status": "valid",
        "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
    });
    let account_resp = serde_json::to_vec(&account_resp)?;
    enrollment.new_account_response(account_resp)?;

    let enrollment = restore(enrollment, &ctx.transaction).await;

    let _order_req = enrollment.new_order_request(previous_nonce.to_string()).unwrap();
    let client_id = match client_id {
        None => ctx.get_e2ei_client_id().await.to_uri(),
        Some(client_id) => format!("{}{client_id}", wire_e2e_identity::prelude::E2eiClientId::URI_SCHEME),
    };
    let device_identifier = format!(
        "{{\"name\":\"{display_name}\",\"domain\":\"world.com\",\"client-id\":\"{client_id}\",\"handle\":\"wireapp://%40{handle}@world.com\"}}"
    );
    let user_identifier = format!(
        "{{\"name\":\"{display_name}\",\"domain\":\"world.com\",\"handle\":\"wireapp://%40{handle}@world.com\"}}"
    );
    let order_resp = json!({
        "status": "pending",
        "expires": "2037-01-05T14:09:07.99Z",
        "notBefore": "2016-01-01T00:00:00Z",
        "notAfter": "2037-01-08T00:00:00Z",
        "identifiers": [
            {
              "type": "wireapp-user",
              "value": user_identifier
            },
            {
              "type": "wireapp-device",
              "value": device_identifier
            }
        ],
        "authorizations": [
            "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
            "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
        ],
        "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
    });
    let order_resp = serde_json::to_vec(&order_resp)?;
    let new_order = enrollment.new_order_response(order_resp)?;

    let mut enrollment = restore(enrollment, &ctx.transaction).await;

    let order_url = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";

    let [user_authz_url, device_authz_url] = new_order.authorizations.as_slice() else {
        unreachable!()
    };

    let _user_authz_req = enrollment.new_authz_request(user_authz_url.to_string(), previous_nonce.to_string())?;

    let user_authz_resp = json!({
        "status": "pending",
        "expires": "2037-01-02T14:09:30Z",
        "identifier": {
          "type": "wireapp-user",
          "value": user_identifier
        },
        "challenges": [
          {
            "type": "wire-oidc-01",
            "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
            "status": "pending",
            "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
            "target": "http://example.com/target"
          }
        ]
    });
    let user_authz_resp = serde_json::to_vec(&user_authz_resp)?;
    enrollment.new_authz_response(user_authz_resp)?;

    let _device_authz_req = enrollment.new_authz_request(device_authz_url.to_string(), previous_nonce.to_string())?;

    let device_authz_resp = json!({
        "status": "pending",
        "expires": "2037-01-02T14:09:30Z",
        "identifier": {
          "type": "wireapp-device",
          "value": device_identifier
        },
        "challenges": [
          {
            "type": "wire-dpop-01",
            "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
            "status": "pending",
            "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
            "target": "https://wire.com/clients/4959bc6ab12f2846/access-token"
          }
        ]
    });
    let device_authz_resp = serde_json::to_vec(&device_authz_resp)?;
    enrollment.new_authz_response(device_authz_resp)?;

    let enrollment = restore(enrollment, &ctx.transaction).await;

    let backend_nonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
    let _dpop_token = enrollment.create_dpop_token(3600, backend_nonce.to_string())?;

    let access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA".to_string();
    let _dpop_chall_req = enrollment.new_dpop_challenge_request(access_token, previous_nonce.to_string())?;
    let dpop_chall_resp = json!({
        "type": "wire-dpop-01",
        "url": "https://example.com/acme/chall/prV_B7yEyA4",
        "status": "valid",
        "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
        "target": "http://example.com/target"
    });
    let dpop_chall_resp = serde_json::to_vec(&dpop_chall_resp)?;
    enrollment.new_dpop_challenge_response(dpop_chall_resp)?;

    let mut enrollment = restore(enrollment, &ctx.transaction).await;

    let id_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ".to_string();
    #[cfg(not(target_family = "wasm"))]
    let new_refresh_token = "new-refresh-token";
    let _oidc_chall_req = enrollment.new_oidc_challenge_request(
        id_token,
        #[cfg(not(target_family = "wasm"))]
        new_refresh_token.to_string(),
        previous_nonce.to_string(),
    )?;

    #[cfg(not(target_family = "wasm"))]
    assert!(enrollment.get_refresh_token().is_ok());

    let oidc_chall_resp = json!({
        "type": "wire-oidc-01",
        "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
        "status": "valid",
        "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb",
        "target": "http://example.com/target"
    });
    let oidc_chall_resp = serde_json::to_vec(&oidc_chall_resp)?;

    #[cfg(not(target_family = "wasm"))]
    {
        let backend = ctx
            .transaction
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        let keystore = backend.key_store();
        enrollment
            .new_oidc_challenge_response(&ctx.transaction.mls_provider().await.unwrap(), oidc_chall_resp)
            .await?;
        // Now Refresh token is persisted in the keystore
        assert_eq!(RefreshToken::find(keystore).await?.as_str(), new_refresh_token);
        // No reason at this point to have the refresh token in memory
        assert!(enrollment.get_refresh_token().is_err());
    }

    #[cfg(target_family = "wasm")]
    enrollment.new_oidc_challenge_response(oidc_chall_resp).await?;

    let mut enrollment = restore(enrollment, &ctx.transaction).await;

    let _get_order_req = enrollment.check_order_request(order_url.to_string(), previous_nonce.to_string())?;

    let order_resp = json!({
      "status": "ready",
      "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
      "identifiers": [
        {
          "type": "wireapp-user",
          "value": user_identifier
        },
        {
          "type": "wireapp-device",
          "value": device_identifier
        }
      ],
      "authorizations": [
        "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
        "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
      ],
      "expires": "2037-02-10T14:59:20Z",
      "notBefore": "2013-02-09T14:59:20.442908Z",
      "notAfter": "2037-02-09T15:59:20.442908Z"
    });
    let order_resp = serde_json::to_vec(&order_resp)?;
    enrollment.check_order_response(order_resp)?;

    let mut enrollment = restore(enrollment, &ctx.transaction).await;

    let _finalize_req = enrollment.finalize_request(previous_nonce.to_string())?;
    let finalize_resp = json!({
      "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
      "status": "valid",
      "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
      "identifiers": [
        {
          "type": "wireapp-user",
          "value": user_identifier
        },
        {
          "type": "wireapp-device",
          "value": device_identifier
        }
      ],
      "authorizations": [
        "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
        "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
      ],
      "expires": "2037-02-10T14:59:20Z",
      "notBefore": "2013-02-09T14:59:20.442908Z",
      "notAfter": "2037-02-09T15:59:20.442908Z"
    });
    let finalize_resp = serde_json::to_vec(&finalize_resp)?;
    enrollment.finalize_response(finalize_resp)?;

    let mut enrollment = restore(enrollment, &ctx.transaction).await;

    let _certificate_req = enrollment.certificate_request(previous_nonce.to_string())?;

    let existing_keypair = PkiKeypair::new(case.signature_scheme(), enrollment.sign_sk.to_vec()).unwrap();

    let client_id = QualifiedE2eiClientId::from_str_unchecked(enrollment.client_id());
    let cert = CertificateBundle::new(
        &handle,
        &display_name,
        Some(&client_id),
        Some(existing_keypair),
        x509_test_chain.find_local_intermediate_ca(),
    );

    let cert_chain = cert
        .certificate_chain
        .into_iter()
        .map(|c| pem::Pem::new("CERTIFICATE", c).to_string())
        .join("");

    Ok((enrollment, cert_chain))
}
