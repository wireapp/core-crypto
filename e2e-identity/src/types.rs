use rusty_acme::prelude::{AcmeChallenge, RustyAcmeError};

use crate::prelude::{E2eIdentityError, E2eIdentityResult};

use super::Json;

#[derive(
    Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent, rename_all = "camelCase")]
pub struct E2eiAcmeAccount(Json);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeOrder {
    pub new_order: Json,
    pub authorizations: Vec<url::Url>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeAuthz {
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_dpop_challenge: Option<E2eiAcmeChall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_oidc_challenge: Option<E2eiAcmeChall>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeChall {
    pub chall: Json,
    pub url: url::Url,
    pub target: url::Url,
}

impl TryFrom<AcmeChallenge> for E2eiAcmeChall {
    type Error = E2eIdentityError;

    fn try_from(challenge: AcmeChallenge) -> E2eIdentityResult<Self> {
        let chall = serde_json::to_value(&challenge)?;
        let target = challenge.target.ok_or(E2eIdentityError::AcmeError(
            RustyAcmeError::SmallstepImplementationError(
                "Wire's fork of smallstep ACME server is supposed to always add a 'target' field to challenges",
            ),
        ))?;
        Ok(Self {
            chall,
            url: challenge.url,
            target,
        })
    }
}

#[derive(
    Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent, rename_all = "camelCase")]
pub struct E2eiAcmeOrder(Json);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeFinalize {
    pub certificate_url: url::Url,
    pub finalize: Json,
}
