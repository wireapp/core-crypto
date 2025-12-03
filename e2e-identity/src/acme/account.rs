use rusty_jwt_tools::prelude::*;

use crate::prelude::*;

impl RustyAcme {
    /// 5. Create a new acme account see [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3)
    pub fn new_account_request(
        directory: &AcmeDirectory,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        const DEFAULT_CONTACT: &str = "anonymous@anonymous.invalid";

        // explicitly set an invalid email so that if someday it is required to set one we do not
        // set it by accident
        let contact = vec![DEFAULT_CONTACT.to_string()];
        let payload = AcmeAccountRequest {
            terms_of_service_agreed: Some(true),
            contact,
            only_return_existing: Some(false),
        };
        let req = AcmeJws::new(alg, previous_nonce, &directory.new_account, None, Some(payload), kp)?;
        Ok(req)
    }

    /// 6. parse the response from `POST /acme/new-account` see [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3)
    pub fn new_account_response(response: serde_json::Value) -> RustyAcmeResult<AcmeAccount> {
        let account = serde_json::from_value::<AcmeAccount>(response)
            .map_err(|_| RustyAcmeError::SmallstepImplementationError("Invalid account response"))?;
        account.verify()?;
        Ok(account)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeAccountError {
    /// step-ca flagged this order as invalid
    #[error("Created account is not valid")]
    Invalid,
    /// step-ca revoked this account
    #[error("Account was revoked by the server")]
    Revoked,
    /// A client deactivated this account
    #[error("A client deactivated this account")]
    Deactivated,
}

/// For creating an account
/// see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
#[derive(Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone))]
#[serde(rename_all = "camelCase")]
struct AcmeAccountRequest {
    /// Including this field in a newAccount request, with a value of true, indicates the client's
    /// agreement with the terms of service. This field cannot be updated by the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,
    /// An array of URLs that the server can use to contact the client for issues related to this
    /// account. For example, the server may wish to notify the client about server-initiated
    /// revocation or certificate expiration
    pub contact: Vec<String>,
    /// If this field is present with the value "true", then the server MUST NOT create a new
    /// account if one does not already exist. This allows a client to look up an account URL
    /// based on an account key.
    /// see [Section 7.3.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.1) for more details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,
}

/// Account creation response
/// see [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3)
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeAccount {
    pub status: AcmeAccountStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orders: Option<url::Url>,
}

impl AcmeAccount {
    /// Infers the account url used in almost all [AcmeJws] kid.
    /// To do so, trims the last segment from the 'orders' URL
    pub fn acct_url(&self) -> RustyAcmeResult<url::Url> {
        let orders = self
            .orders
            .as_ref()
            .ok_or(RustyAcmeError::SmallstepImplementationError(
                "Account should have 'orders' url",
            ))?;
        let mut orders = orders.clone();
        if orders.path_segments().and_then(|mut paths| paths.next_back()) == Some("orders") {
            orders
                .path_segments_mut()
                .map_err(|_| RustyAcmeError::ImplementationError)?
                .pop();
            Ok(orders)
        } else {
            Err(RustyAcmeError::SmallstepImplementationError(
                "Invalid 'orders' URL in account",
            ))
        }
    }

    /// Verifies the account status and the presence of an 'orders' URL
    fn verify(&self) -> RustyAcmeResult<()> {
        self.orders
            .as_ref()
            .ok_or(RustyAcmeError::SmallstepImplementationError(
                "Newly created account should have 'orders' url",
            ))?;
        match self.status {
            AcmeAccountStatus::Valid => Ok(()),
            AcmeAccountStatus::Deactivated => Err(AcmeAccountError::Deactivated)?,
            AcmeAccountStatus::Revoked => Err(AcmeAccountError::Revoked)?,
        }
    }
}

#[cfg(test)]
impl Default for AcmeAccount {
    fn default() -> Self {
        Self {
            status: AcmeAccountStatus::Valid,
            orders: Some(
                "https://acme-server/acme/account/muYiJmuJRn9u2L0tdI5bu11T7QqqPR1u/orders"
                    .parse()
                    .unwrap(),
            ),
        }
    }
}

/// see [RFC 8555 Section 7.1.6](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.6)
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeAccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod json {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn can_deserialize_rfc_sample_request() {
            let rfc_sample = json!({
                "termsOfServiceAgreed": true,
                "contact": [
                  "mailto:cert-admin@example.org",
                  "mailto:admin@example.org"
                ]
            });
            assert!(serde_json::from_value::<AcmeAccountRequest>(rfc_sample).is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn can_deserialize_rfc_sample_response() {
            let rfc_sample = json!({
                "status": "valid",
                "contact": [
                    "mailto:cert-admin@example.org",
                    "mailto:admin@example.org"
                ],
                "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
            });
            assert!(serde_json::from_value::<AcmeAccount>(rfc_sample).is_ok());
        }
    }

    mod verify {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_succeed_when_status_valid() {
            let account = AcmeAccount {
                status: AcmeAccountStatus::Valid,
                ..Default::default()
            };
            assert!(account.verify().is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_status_deactivated() {
            let account = AcmeAccount {
                status: AcmeAccountStatus::Deactivated,
                ..Default::default()
            };
            assert!(matches!(
                account.verify().unwrap_err(),
                RustyAcmeError::AccountError(AcmeAccountError::Deactivated)
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_status_revoked() {
            let account = AcmeAccount {
                status: AcmeAccountStatus::Revoked,
                ..Default::default()
            };
            assert!(matches!(
                account.verify().unwrap_err(),
                RustyAcmeError::AccountError(AcmeAccountError::Revoked)
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_orders_absent() {
            let account = AcmeAccount {
                orders: None,
                ..Default::default()
            };
            assert!(matches!(
                account.verify().unwrap_err(),
                RustyAcmeError::SmallstepImplementationError("Newly created account should have 'orders' url")
            ));
        }
    }

    mod acct_url {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_trim_last_orders_segment() {
            let base = "https://acme-server/acme/wire-acme/account/muYiJmuJRn9u2L0tdI5bu11T7QqqPR1u";
            let orders_url = format!("{base}/orders");
            let account = AcmeAccount {
                orders: Some(orders_url.parse().unwrap()),
                ..Default::default()
            };
            assert_eq!(account.acct_url().unwrap().as_str(), base);
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_orders_absent() {
            let account = AcmeAccount {
                orders: None,
                ..Default::default()
            };
            assert!(matches!(
                account.acct_url().unwrap_err(),
                RustyAcmeError::SmallstepImplementationError("Account should have 'orders' url")
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_orders_url_doesnt_end_with_orders() {
            let base = "https://acme-server/acme/wire-acme/account/muYiJmuJRn9u2L0tdI5bu11T7QqqPR1u";
            let orders_url = format!("{base}/error");
            let account = AcmeAccount {
                orders: Some(orders_url.parse().unwrap()),
                ..Default::default()
            };
            assert!(matches!(
                account.acct_url().unwrap_err(),
                RustyAcmeError::SmallstepImplementationError("Invalid 'orders' URL in account")
            ));
        }
    }
}
