use crate::{
    acme::AcmeChallenge,
    prelude::{E2eIdentityError, E2eIdentityResult},
};

pub(crate) type Json = serde_json::Value;

#[derive(
    Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent, rename_all = "camelCase")]
pub struct E2eiAcmeAccount(Json);

impl TryFrom<E2eiAcmeAccount> for crate::acme::AcmeAccount {
    type Error = E2eIdentityError;

    fn try_from(account: E2eiAcmeAccount) -> E2eIdentityResult<Self> {
        Ok(serde_json::from_value(account.into())?)
    }
}

impl TryFrom<crate::acme::AcmeAccount> for E2eiAcmeAccount {
    type Error = E2eIdentityError;

    fn try_from(account: crate::acme::AcmeAccount) -> E2eIdentityResult<Self> {
        Ok(serde_json::to_value(account)?.into())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeOrder {
    pub delegate: Json,
    pub authorizations: [url::Url; 2],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum E2eiAcmeAuthorization {
    User {
        identifier: String,
        keyauth: String,
        challenge: E2eiAcmeChallenge,
    },
    Device {
        identifier: String,
        challenge: E2eiAcmeChallenge,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeChallenge {
    pub delegate: Json,
    pub url: url::Url,
    pub target: url::Url,
}

impl TryFrom<AcmeChallenge> for E2eiAcmeChallenge {
    type Error = E2eIdentityError;

    fn try_from(challenge: AcmeChallenge) -> E2eIdentityResult<Self> {
        let chall = serde_json::to_value(&challenge)?;
        Ok(Self {
            delegate: chall,
            url: challenge.url,
            target: challenge.target,
        })
    }
}

impl TryFrom<E2eiAcmeChallenge> for AcmeChallenge {
    type Error = E2eIdentityError;

    fn try_from(chall: E2eiAcmeChallenge) -> E2eIdentityResult<Self> {
        Ok(serde_json::from_value(chall.delegate)?)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeOrder {
    pub delegate: Json,
    pub finalize_url: url::Url,
}

impl TryFrom<crate::acme::AcmeOrder> for E2eiAcmeOrder {
    type Error = E2eIdentityError;

    fn try_from(order: crate::acme::AcmeOrder) -> E2eIdentityResult<Self> {
        Ok(E2eiAcmeOrder {
            delegate: serde_json::to_value(&order)?,
            finalize_url: order.finalize,
        })
    }
}

impl TryFrom<E2eiAcmeOrder> for crate::acme::AcmeOrder {
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

impl TryFrom<E2eiAcmeFinalize> for crate::acme::AcmeFinalize {
    type Error = E2eIdentityError;

    fn try_from(finalize: E2eiAcmeFinalize) -> E2eIdentityResult<Self> {
        Ok(serde_json::from_value(finalize.delegate)?)
    }
}

impl TryFrom<crate::acme::AcmeFinalize> for E2eiAcmeFinalize {
    type Error = E2eIdentityError;

    fn try_from(finalize: crate::acme::AcmeFinalize) -> E2eIdentityResult<Self> {
        Ok(E2eiAcmeFinalize {
            delegate: serde_json::to_value(&finalize)?,
            certificate_url: finalize.certificate,
        })
    }
}
