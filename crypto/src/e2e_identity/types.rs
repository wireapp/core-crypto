//! We only expose byte arrays through the FFI so we do all the conversions here

use super::error::{E2eIdentityError, E2eIdentityResult};

/// TODO
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct E2eiAcmeDirectory {
    /// TODO
    pub new_nonce: String,
    /// TODO
    pub new_account: String,
    /// TODO
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

impl TryFrom<E2eiAcmeDirectory> for wire_e2e_identity::prelude::AcmeDirectory {
    type Error = E2eIdentityError;

    fn try_from(directory: E2eiAcmeDirectory) -> E2eIdentityResult<Self> {
        Ok(Self {
            new_nonce: directory.new_nonce.parse()?,
            new_account: directory.new_account.parse()?,
            new_order: directory.new_order.parse()?,
        })
    }
}

/// TODO
#[derive(Debug, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct E2eiAcmeAccount(super::Json);

impl TryFrom<wire_e2e_identity::prelude::E2eiAcmeAccount> for E2eiAcmeAccount {
    type Error = E2eIdentityError;

    fn try_from(from: wire_e2e_identity::prelude::E2eiAcmeAccount) -> E2eIdentityResult<Self> {
        Ok(serde_json::to_vec(&from)?.into())
    }
}

impl TryFrom<E2eiAcmeAccount> for wire_e2e_identity::prelude::E2eiAcmeAccount {
    type Error = E2eIdentityError;

    fn try_from(from: E2eiAcmeAccount) -> E2eIdentityResult<Self> {
        Ok(serde_json::to_value(from)?.into())
    }
}

/// TODO
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct E2eiNewAcmeOrder {
    /// TODO
    pub delegate: super::Json,
    /// TODO
    pub authorizations: Vec<String>,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiNewAcmeOrder> for E2eiNewAcmeOrder {
    type Error = E2eIdentityError;

    fn try_from(new_order: wire_e2e_identity::prelude::E2eiNewAcmeOrder) -> E2eIdentityResult<Self> {
        Ok(Self {
            authorizations: new_order.authorizations.iter().map(url::Url::to_string).collect(),
            delegate: serde_json::to_vec(&new_order.new_order)?,
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
            new_order: serde_json::to_value(new_order.delegate)?,
        })
    }
}

/// TODO
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct E2eiNewAcmeAuthz {
    /// TODO
    pub identifier: String,
    /// TODO
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_http_challenge: Option<E2eiAcmeChall>,
    /// TODO
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_oidc_challenge: Option<E2eiAcmeChall>,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiNewAcmeAuthz> for E2eiNewAcmeAuthz {
    type Error = E2eIdentityError;

    fn try_from(authz: wire_e2e_identity::prelude::E2eiNewAcmeAuthz) -> E2eIdentityResult<Self> {
        Ok(Self {
            identifier: authz.identifier,
            wire_http_challenge: authz.wire_http_challenge.map(TryFrom::try_from).transpose()?,
            wire_oidc_challenge: authz.wire_oidc_challenge.map(TryFrom::try_from).transpose()?,
        })
    }
}

impl TryFrom<E2eiNewAcmeAuthz> for wire_e2e_identity::prelude::E2eiNewAcmeAuthz {
    type Error = E2eIdentityError;

    fn try_from(authz: E2eiNewAcmeAuthz) -> E2eIdentityResult<Self> {
        Ok(Self {
            identifier: authz.identifier,
            wire_http_challenge: authz.wire_http_challenge.map(TryFrom::try_from).transpose()?,
            wire_oidc_challenge: authz.wire_oidc_challenge.map(TryFrom::try_from).transpose()?,
        })
    }
}

/// TODO
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct E2eiAcmeChall {
    /// TODO
    pub delegate: super::Json,
    /// TODO
    pub url: String,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiAcmeChall> for E2eiAcmeChall {
    type Error = E2eIdentityError;

    fn try_from(chall: wire_e2e_identity::prelude::E2eiAcmeChall) -> E2eIdentityResult<Self> {
        Ok(Self {
            delegate: serde_json::to_vec(&chall.chall)?,
            url: chall.url.to_string(),
        })
    }
}

impl TryFrom<E2eiAcmeChall> for wire_e2e_identity::prelude::E2eiAcmeChall {
    type Error = E2eIdentityError;

    fn try_from(chall: E2eiAcmeChall) -> E2eIdentityResult<Self> {
        Ok(Self {
            chall: serde_json::to_value(chall.delegate)?,
            url: chall.url.parse()?,
        })
    }
}

/// TODO
#[derive(Debug, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct E2eiAcmeOrder(super::Json);

impl TryFrom<wire_e2e_identity::prelude::E2eiAcmeOrder> for E2eiAcmeOrder {
    type Error = E2eIdentityError;

    fn try_from(from: wire_e2e_identity::prelude::E2eiAcmeOrder) -> E2eIdentityResult<Self> {
        Ok(serde_json::to_vec(&from)?.into())
    }
}

impl TryFrom<E2eiAcmeOrder> for wire_e2e_identity::prelude::E2eiAcmeOrder {
    type Error = E2eIdentityError;

    fn try_from(from: E2eiAcmeOrder) -> E2eIdentityResult<Self> {
        Ok(serde_json::to_value(from)?.into())
    }
}

/// TODO
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct E2eiAcmeFinalize {
    /// TODO
    pub certificate_url: String,
    /// TODO
    pub delegate: super::Json,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiAcmeFinalize> for E2eiAcmeFinalize {
    type Error = E2eIdentityError;

    fn try_from(finalize: wire_e2e_identity::prelude::E2eiAcmeFinalize) -> E2eIdentityResult<Self> {
        Ok(Self {
            certificate_url: finalize.certificate_url.to_string(),
            delegate: serde_json::to_vec(&finalize.finalize)?,
        })
    }
}

impl TryFrom<E2eiAcmeFinalize> for wire_e2e_identity::prelude::E2eiAcmeFinalize {
    type Error = E2eIdentityError;

    fn try_from(finalize: E2eiAcmeFinalize) -> E2eIdentityResult<Self> {
        Ok(Self {
            certificate_url: finalize.certificate_url.parse()?,
            finalize: serde_json::to_value(finalize.delegate)?,
        })
    }
}
