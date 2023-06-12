//! We only expose byte arrays through the FFI so we do all the conversions here

use super::error::{E2eIdentityError, E2eIdentityResult};

/// See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeDirectory {
    /// For fetching a new nonce used in [crate::prelude::E2eiEnrollment::new_account_request]
    pub new_nonce: String,
    /// URL to call with [crate::prelude::E2eiEnrollment::new_account_request]
    pub new_account: String,
    /// URL to call with [crate::prelude::E2eiEnrollment::new_order_request]
    pub new_order: String,
}

impl From<wire_e2e_identity::prelude::AcmeDirectory> for E2eiAcmeDirectory {
    fn from(directory: wire_e2e_identity::prelude::AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce.to_string(),
            new_account: directory.new_account.to_string(),
            new_order: directory.new_order.to_string(),
        }
    }
}

impl TryFrom<&E2eiAcmeDirectory> for wire_e2e_identity::prelude::AcmeDirectory {
    type Error = E2eIdentityError;

    fn try_from(directory: &E2eiAcmeDirectory) -> E2eIdentityResult<Self> {
        Ok(Self {
            new_nonce: directory.new_nonce.parse()?,
            new_account: directory.new_account.parse()?,
            new_order: directory.new_order.parse()?,
        })
    }
}

/// Result of an order creation
/// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeOrder {
    /// Opaque raw json value
    pub delegate: super::Json,
    /// Authorizations to create with [crate::prelude::E2eiEnrollment::new_authz_request]
    pub authorizations: Vec<String>,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiNewAcmeOrder> for E2eiNewAcmeOrder {
    type Error = E2eIdentityError;

    fn try_from(new_order: wire_e2e_identity::prelude::E2eiNewAcmeOrder) -> E2eIdentityResult<Self> {
        Ok(Self {
            authorizations: new_order.authorizations.iter().map(url::Url::to_string).collect(),
            delegate: serde_json::to_vec(&new_order.delegate)?,
        })
    }
}

impl TryFrom<E2eiNewAcmeOrder> for wire_e2e_identity::prelude::E2eiNewAcmeOrder {
    type Error = E2eIdentityError;

    fn try_from(new_order: E2eiNewAcmeOrder) -> E2eIdentityResult<Self> {
        Ok(Self {
            authorizations: new_order.authorizations.iter().try_fold(
                vec![],
                |mut acc, u| -> E2eIdentityResult<Vec<url::Url>> {
                    acc.push(u.parse()?);
                    Ok(acc)
                },
            )?,
            delegate: serde_json::to_value(new_order.delegate)?,
        })
    }
}

/// Result of an authorization creation
/// see [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeAuthz {
    /// DNS entry associated with those challenge
    pub identifier: String,
    /// Challenge for the clientId
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_dpop_challenge: Option<E2eiAcmeChallenge>,
    /// Challenge for the handle + display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_oidc_challenge: Option<E2eiAcmeChallenge>,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiNewAcmeAuthz> for E2eiNewAcmeAuthz {
    type Error = E2eIdentityError;

    fn try_from(authz: wire_e2e_identity::prelude::E2eiNewAcmeAuthz) -> E2eIdentityResult<Self> {
        Ok(Self {
            identifier: authz.identifier,
            wire_dpop_challenge: authz.wire_dpop_challenge.map(TryFrom::try_from).transpose()?,
            wire_oidc_challenge: authz.wire_oidc_challenge.map(TryFrom::try_from).transpose()?,
        })
    }
}

impl TryFrom<&E2eiNewAcmeAuthz> for wire_e2e_identity::prelude::E2eiNewAcmeAuthz {
    type Error = E2eIdentityError;

    fn try_from(authz: &E2eiNewAcmeAuthz) -> E2eIdentityResult<Self> {
        Ok(Self {
            identifier: authz.identifier.clone(),
            wire_dpop_challenge: authz.wire_dpop_challenge.as_ref().map(TryFrom::try_from).transpose()?,
            wire_oidc_challenge: authz.wire_oidc_challenge.as_ref().map(TryFrom::try_from).transpose()?,
        })
    }
}

/// For creating a challenge
/// see [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeChallenge {
    /// Opaque raw json value
    pub delegate: super::Json,
    /// URL to call for the acme server to complete the challenge
    pub url: String,
    /// Non-standard, Wire specific claim. Indicates the consumer from where it should get the challenge
    /// proof. Either from wire-server "/access-token" endpoint in case of a DPoP challenge, or from
    /// an OAuth token endpoint for an OIDC challenge
    pub target: String,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiAcmeChall> for E2eiAcmeChallenge {
    type Error = E2eIdentityError;

    fn try_from(chall: wire_e2e_identity::prelude::E2eiAcmeChall) -> E2eIdentityResult<Self> {
        Ok(Self {
            delegate: serde_json::to_vec(&chall.delegate)?,
            url: chall.url.to_string(),
            target: chall.target.to_string(),
        })
    }
}

impl TryFrom<&E2eiAcmeChallenge> for wire_e2e_identity::prelude::E2eiAcmeChall {
    type Error = E2eIdentityError;

    fn try_from(chall: &E2eiAcmeChallenge) -> E2eIdentityResult<Self> {
        Ok(Self {
            delegate: serde_json::from_slice(&chall.delegate[..])?,
            url: chall.url.parse()?,
            target: chall.target.parse()?,
        })
    }
}
