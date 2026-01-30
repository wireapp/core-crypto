use std::collections::HashSet;

use rusty_jwt_tools::prelude::*;

use crate::acme::{identifier::CanonicalIdentifier, *};

// Order creation
impl RustyAcme {
    /// create a new order
    /// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    #[allow(clippy::too_many_arguments)]
    pub fn new_order_request(
        display_name: &str,
        client_id: ClientId,
        handle: &Handle,
        expiry: core::time::Duration,
        directory: &AcmeDirectory,
        account: &AcmeAccount,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        // Extract the account URL from previous response which created a new account
        let acct_url = account.acct_url()?;

        let domain = client_id.domain.clone();
        let handle = handle.try_to_qualified(&domain)?;
        let device_identifier =
            AcmeIdentifier::try_new_device(client_id, handle.clone(), display_name.to_string(), domain.clone())?;
        let user_identifier = AcmeIdentifier::try_new_user(handle, display_name.to_string(), domain)?;

        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + expiry;
        let payload = AcmeOrderRequest {
            identifiers: vec![device_identifier, user_identifier],
            not_before: Some(not_before),
            not_after: Some(not_after),
        };
        let req = AcmeJws::new(
            alg,
            previous_nonce,
            &directory.new_order,
            Some(&acct_url),
            Some(payload),
            kp,
        )?;
        Ok(req)
    }

    /// parse response from order creation
    /// [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
    pub fn new_order_response(response: serde_json::Value) -> RustyAcmeResult<AcmeOrder> {
        let order = serde_json::from_value::<AcmeOrder>(response)?;
        match order.status {
            AcmeOrderStatus::Pending => {}
            AcmeOrderStatus::Processing | AcmeOrderStatus::Valid | AcmeOrderStatus::Ready => {
                return Err(RustyAcmeError::ClientImplementationError(
                    "an order is not supposed to be 'processing | valid | ready' at this point. \
                    You should only be using this method after account creation, not after finalize",
                ));
            }
            AcmeOrderStatus::Invalid => return Err(AcmeOrderError::Invalid)?,
        }
        order.verify()?;
        Ok(order)
    }
}

// Long poll order until ready
impl RustyAcme {
    /// check an order status until it becomes ready
    /// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
    pub fn check_order_request(
        order_url: url::Url,
        account: &AcmeAccount,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        // Extract the account URL from previous response which created a new account
        let acct_url = account.acct_url()?;

        // No payload required for authz
        let payload = None::<serde_json::Value>;
        let req = AcmeJws::new(alg, previous_nonce, &order_url, Some(&acct_url), payload, kp)?;
        Ok(req)
    }

    /// parse response from order check
    /// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
    pub fn check_order_response(response: serde_json::Value) -> RustyAcmeResult<AcmeOrder> {
        let order = serde_json::from_value::<AcmeOrder>(response)?;
        match order.status {
            AcmeOrderStatus::Ready => {}
            AcmeOrderStatus::Pending => {
                return Err(RustyAcmeError::ClientImplementationError(
                    "an order is not supposed to be 'pending' at this point. \
                    It means you have forgotten to create authorizations",
                ));
            }
            AcmeOrderStatus::Processing => {
                return Err(RustyAcmeError::ClientImplementationError(
                    "an order is not supposed to be 'processing' at this point. \
                    You should not have called finalize yet ; in fact, you should only call finalize \
                    once this order turns 'ready'",
                ));
            }
            AcmeOrderStatus::Valid => {
                return Err(RustyAcmeError::ClientImplementationError(
                    "an order is not supposed to be 'valid' at this point. \
                    It means a certificate has already been delivered which defeats the purpose \
                    of using this method",
                ));
            }
            AcmeOrderStatus::Invalid => return Err(AcmeOrderError::Invalid)?,
        }
        order.verify()?;
        Ok(order)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeOrderError {
    /// step-ca flagged this order as invalid
    #[error("Created order is not valid")]
    Invalid,
    /// This order 'not_before' is in future
    #[error("This order 'not_before' is in future")]
    NotYetValid,
    /// This order is expired
    #[error("This order is expired")]
    Expired,
    /// This order should only have the 2 Wire identifiers
    #[error("This order should only have the 2 Wire identifiers")]
    WrongIdentifiers,
}

/// For creating an order
/// see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone))]
#[serde(rename_all = "camelCase")]
struct AcmeOrderRequest {
    /// An array of identifier objects that the client wishes to submit an order for
    pub identifiers: Vec<AcmeIdentifier>,
    /// The requested value of the notBefore field in the certificate, in the date format defined
    /// in [RFC3339](https://www.rfc-editor.org/rfc/rfc3339)
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub not_before: Option<time::OffsetDateTime>,
    /// The requested value of the notAfter field in the certificate, in the date format defined in
    /// [RFC3339](https://www.rfc-editor.org/rfc/rfc3339)
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub not_after: Option<time::OffsetDateTime>,
}

/// Result of an order creation
/// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeOrder {
    pub status: AcmeOrderStatus,
    pub finalize: url::Url,
    pub identifiers: [AcmeIdentifier; 2],
    pub authorizations: [url::Url; 2],
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub expires: Option<time::OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub not_before: Option<time::OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub not_after: Option<time::OffsetDateTime>,
}

impl AcmeOrder {
    pub fn verify(&self) -> RustyAcmeResult<()> {
        let [ref a, ref b] = self
            .identifiers
            .iter()
            .collect::<HashSet<_>>() // ensures uniqueness
            .iter()
            .map(|i| i.to_wire_identifier())
            .collect::<RustyAcmeResult<Vec<_>>>()?[..]
        else {
            return Err(AcmeOrderError::WrongIdentifiers)?;
        };

        let same_handle = a.handle == b.handle;
        let same_display_name = a.display_name == b.display_name;
        let same_domain = a.domain == b.domain;
        if !(same_handle && same_display_name && same_domain) {
            return Err(AcmeOrderError::WrongIdentifiers)?;
        }

        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let is_expired = self
            .expires
            .map(time::OffsetDateTime::unix_timestamp)
            .map(|expires| expires < now)
            .unwrap_or_default();
        if is_expired {
            return Err(AcmeOrderError::Expired)?;
        }

        let is_after = self
            .not_after
            .map(time::OffsetDateTime::unix_timestamp)
            .map(|not_after| not_after < now)
            .unwrap_or_default();
        if is_after {
            return Err(AcmeOrderError::Expired)?;
        }

        let is_before = self
            .not_before
            .map(time::OffsetDateTime::unix_timestamp)
            .map(|not_before| now < not_before)
            .unwrap_or_default();
        if is_before {
            return Err(AcmeOrderError::NotYetValid)?;
        }

        Ok(())
    }

    /// A Wire Order has 2 identifiers. For simplification purposes, since they share most of their fields together we
    /// merge them to access the fields
    pub fn try_get_coalesce_identifier(&self) -> RustyAcmeResult<CanonicalIdentifier> {
        self.identifiers
            .iter()
            .find_map(|i| match i {
                AcmeIdentifier::WireappDevice(_) => Some(i.to_wire_identifier()),
                _ => None,
            })
            .transpose()?
            .ok_or(RustyAcmeError::OrderError(AcmeOrderError::WrongIdentifiers))?
            .try_into()
    }

    pub fn try_get_user_authorization(&self) -> RustyAcmeResult<AcmeAuthz> {
        todo!()
    }
}

#[cfg(test)]
impl Default for AcmeOrder {
    fn default() -> Self {
        let now = time::OffsetDateTime::now_utc();
        let tomorrow = now + time::Duration::days(1);
        Self {
            status: AcmeOrderStatus::Ready,
            finalize: "https://acme-server/acme/order/n8LovurSfUFeeGSzD8nuGQwOUeIfSjhs/finalize"
                .parse()
                .unwrap(),
            identifiers: [AcmeIdentifier::new_user(), AcmeIdentifier::new_device()],
            authorizations: [
                "https://acme-server/acme/wire/authz/0DpEeMVjTpOk615lIRvihqEyZLW8CsMH"
                    .parse()
                    .unwrap(),
                "https://acme-server/acme/wire/authz/0hKeQhgRIpQKynZ8qGQo2Y0EXqEVSQ4j"
                    .parse()
                    .unwrap(),
            ],
            expires: Some(tomorrow),
            not_before: Some(now),
            not_after: Some(tomorrow),
        }
    }
}

/// see [RFC 8555 Section 7.1.6](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.6)
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeOrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
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
        fn can_deserialize_sample_request() {
            let rfc_sample = json!({
                "identifiers": [
                  { "type": "wireapp-user", "value": "www.example.org" },
                  { "type": "wireapp-device", "value": "example.org" }
                ],
                "notBefore": "2016-01-01T00:04:00+04:00",
                "notAfter": "2016-01-08T00:04:00+04:00"
            });
            assert!(serde_json::from_value::<AcmeOrderRequest>(rfc_sample).is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn can_deserialize_rfc_sample_response() {
            let rfc_sample = json!({
                "status": "pending",
                "expires": "2016-01-05T14:09:07.99Z",
                "notBefore": "2016-01-01T00:00:00Z",
                "notAfter": "2016-01-08T00:00:00Z",
                "identifiers": [
                  { "type": "wireapp-user", "value": "www.example.org" },
                  { "type": "wireapp-device", "value": "example.org" }
                ],
                "authorizations": [
                  "https://example.com/acme/authz/PAniVnsZcis",
                  "https://example.com/acme/authz/r4HqLzrSrpI"
                ],
                "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
            });
            assert!(serde_json::from_value::<AcmeOrderRequest>(rfc_sample).is_ok());
        }
    }

    mod verify {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_succeed_when_valid() {
            let now = time::OffsetDateTime::now_utc();
            let tomorrow = now + time::Duration::days(1);
            let order = AcmeOrder {
                expires: Some(tomorrow),
                not_before: Some(now),
                not_after: Some(tomorrow),
                ..Default::default()
            };
            assert!(order.verify().is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_not_before_in_future() {
            let tomorrow = time::OffsetDateTime::now_utc() + time::Duration::days(1);
            let order = AcmeOrder {
                not_before: Some(tomorrow),
                ..Default::default()
            };
            assert!(matches!(
                order.verify().unwrap_err(),
                RustyAcmeError::OrderError(AcmeOrderError::NotYetValid)
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_not_after_in_past() {
            let yesterday = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            let order = AcmeOrder {
                not_after: Some(yesterday),
                ..Default::default()
            };
            assert!(matches!(
                order.verify().unwrap_err(),
                RustyAcmeError::OrderError(AcmeOrderError::Expired)
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_expires_in_past() {
            let yesterday = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            let order = AcmeOrder {
                expires: Some(yesterday),
                ..Default::default()
            };
            assert!(matches!(
                order.verify().unwrap_err(),
                RustyAcmeError::OrderError(AcmeOrderError::Expired)
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_wrong_number_identifiers() {
            let now = time::OffsetDateTime::now_utc();
            let tomorrow = now + time::Duration::days(1);
            let default_order = AcmeOrder {
                expires: Some(tomorrow),
                not_before: Some(now),
                not_after: Some(tomorrow),
                ..Default::default()
            };

            // homogeneous identifiers
            let order = AcmeOrder {
                identifiers: [AcmeIdentifier::new_user(), AcmeIdentifier::new_user()],
                ..default_order.clone()
            };
            assert!(matches!(
                order.verify().unwrap_err(),
                RustyAcmeError::OrderError(AcmeOrderError::WrongIdentifiers)
            ));

            // homogeneous identifiers
            let order = AcmeOrder {
                identifiers: [AcmeIdentifier::new_device(), AcmeIdentifier::new_device()],
                ..default_order.clone()
            };
            assert!(matches!(
                order.verify().unwrap_err(),
                RustyAcmeError::OrderError(AcmeOrderError::WrongIdentifiers)
            ));
        }
    }

    mod creation {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_succeed_when_pending() {
            let order = AcmeOrder {
                status: AcmeOrderStatus::Pending,
                ..Default::default()
            };
            let order = serde_json::to_value(order).unwrap();
            assert!(RustyAcme::new_order_response(order).is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_not_pending() {
            let order = AcmeOrder {
                status: AcmeOrderStatus::Ready,
                ..Default::default()
            };
            let order = serde_json::to_value(order).unwrap();
            assert!(matches!(
                RustyAcme::new_order_response(order).unwrap_err(),
                RustyAcmeError::ClientImplementationError(_)
            ));

            let order = AcmeOrder {
                status: AcmeOrderStatus::Processing,
                ..Default::default()
            };
            let order = serde_json::to_value(order).unwrap();
            assert!(matches!(
                RustyAcme::new_order_response(order).unwrap_err(),
                RustyAcmeError::ClientImplementationError(_)
            ));

            let order = AcmeOrder {
                status: AcmeOrderStatus::Valid,
                ..Default::default()
            };
            let order = serde_json::to_value(order).unwrap();
            assert!(matches!(
                RustyAcme::new_order_response(order).unwrap_err(),
                RustyAcmeError::ClientImplementationError(_)
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_invalid() {
            let order = AcmeOrder {
                status: AcmeOrderStatus::Invalid,
                ..Default::default()
            };
            let order = serde_json::to_value(order).unwrap();
            assert!(matches!(
                RustyAcme::new_order_response(order).unwrap_err(),
                RustyAcmeError::OrderError(AcmeOrderError::Invalid)
            ));
        }
    }

    mod check {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_succeed_when_ready() {
            let order = AcmeOrder {
                status: AcmeOrderStatus::Ready,
                ..Default::default()
            };
            let order = serde_json::to_value(order).unwrap();
            assert!(RustyAcme::check_order_response(order).is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_not_pending() {
            for status in [
                AcmeOrderStatus::Pending,
                AcmeOrderStatus::Processing,
                AcmeOrderStatus::Valid,
            ] {
                let order = AcmeOrder {
                    status,
                    ..Default::default()
                };
                let order = serde_json::to_value(&order).unwrap();
                assert!(matches!(
                    RustyAcme::check_order_response(order).unwrap_err(),
                    RustyAcmeError::ClientImplementationError(_)
                ));
            }
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_invalid() {
            let order = AcmeOrder {
                status: AcmeOrderStatus::Invalid,
                ..Default::default()
            };
            let order = serde_json::to_value(order).unwrap();
            assert!(matches!(
                RustyAcme::check_order_response(order).unwrap_err(),
                RustyAcmeError::OrderError(AcmeOrderError::Invalid)
            ));
        }
    }
}
