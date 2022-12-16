use super::Json;

#[derive(
    Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct E2eiAcmeAccount(Json);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct E2eiNewAcmeOrder {
    pub new_order: Json,
    pub authorizations: Vec<url::Url>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct E2eiNewAcmeAuthz {
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_http_challenge: Option<E2eiAcmeChall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_oidc_challenge: Option<E2eiAcmeChall>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct E2eiAcmeChall {
    pub chall: Json,
    pub url: url::Url,
}

#[derive(
    Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct E2eiAcmeOrder(Json);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct E2eiAcmeFinalize {
    pub certificate_url: url::Url,
    pub finalize: Json,
}
