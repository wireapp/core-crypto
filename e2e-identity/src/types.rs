use rusty_acme::prelude::{AcmeChallenge, RustyAcmeError};

use crate::prelude::{E2eIdentityError, E2eIdentityResult};

use super::Json;

#[derive(
    Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent, rename_all = "camelCase")]
pub struct E2eiAcmeAccount(Json);

impl TryFrom<E2eiAcmeAccount> for rusty_acme::prelude::AcmeAccount {
    type Error = E2eIdentityError;

    fn try_from(account: E2eiAcmeAccount) -> E2eIdentityResult<Self> {
        Ok(serde_json::from_value(account.into())?)
    }
}

impl TryFrom<rusty_acme::prelude::AcmeAccount> for E2eiAcmeAccount {
    type Error = E2eIdentityError;

    fn try_from(account: rusty_acme::prelude::AcmeAccount) -> E2eIdentityResult<Self> {
        Ok(serde_json::to_value(account)?.into())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeOrder {
    pub delegate: Json,
    pub authorizations: Vec<url::Url>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeAuthz {
    pub identifier: String,
    pub keyauth: String,
    pub wire_dpop_challenge: E2eiAcmeChall,
    pub wire_oidc_challenge: E2eiAcmeChall,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeChall {
    pub delegate: Json,
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
            delegate: chall,
            url: challenge.url,
            target,
        })
    }
}

impl TryFrom<E2eiAcmeChall> for AcmeChallenge {
    type Error = E2eIdentityError;

    fn try_from(chall: E2eiAcmeChall) -> E2eIdentityResult<Self> {
        Ok(serde_json::from_value(chall.delegate)?)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeOrder {
    pub delegate: Json,
    pub finalize_url: url::Url,
}

impl TryFrom<rusty_acme::prelude::AcmeOrder> for E2eiAcmeOrder {
    type Error = E2eIdentityError;

    fn try_from(order: rusty_acme::prelude::AcmeOrder) -> E2eIdentityResult<Self> {
        Ok(E2eiAcmeOrder {
            delegate: serde_json::to_value(&order)?,
            finalize_url: order.finalize,
        })
    }
}

impl TryFrom<E2eiAcmeOrder> for rusty_acme::prelude::AcmeOrder {
    type Error = E2eIdentityError;

    fn try_from(order: E2eiAcmeOrder) -> E2eIdentityResult<Self> {
        Ok(serde_json::from_value(order.delegate)?)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeFinalize {
    pub delegate: Json,
    pub certificate_url: url::Url,
}

impl TryFrom<E2eiAcmeFinalize> for rusty_acme::prelude::AcmeFinalize {
    type Error = E2eIdentityError;

    fn try_from(finalize: E2eiAcmeFinalize) -> E2eIdentityResult<Self> {
        Ok(serde_json::from_value(finalize.delegate)?)
    }
}

impl TryFrom<rusty_acme::prelude::AcmeFinalize> for E2eiAcmeFinalize {
    type Error = E2eIdentityError;

    fn try_from(finalize: rusty_acme::prelude::AcmeFinalize) -> E2eIdentityResult<Self> {
        Ok(E2eiAcmeFinalize {
            delegate: serde_json::to_value(&finalize)?,
            certificate_url: finalize.certificate,
        })
    }
}
