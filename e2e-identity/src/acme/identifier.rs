use rusty_jwt_tools::prelude::*;

use crate::acme::prelude::*;

/// Represent an identifier in an ACME Order
#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum AcmeIdentifier {
    WireappUser(String),
    WireappDevice(String),
}

impl AcmeIdentifier {
    pub fn try_new_device(
        client_id: ClientId,
        handle: QualifiedHandle,
        display_name: String,
        domain: String,
    ) -> RustyAcmeResult<Self> {
        let client_id = client_id.to_uri();
        let identifier = WireIdentifier {
            display_name,
            handle,
            domain,
            client_id: Some(client_id),
        };
        let identifier = serde_json::to_string(&identifier)?;
        Ok(Self::WireappDevice(identifier))
    }

    pub fn try_new_user(handle: QualifiedHandle, display_name: String, domain: String) -> RustyAcmeResult<Self> {
        let identifier = WireIdentifier {
            display_name,
            handle,
            domain,
            client_id: None,
        };
        let identifier = serde_json::to_string(&identifier)?;
        Ok(Self::WireappUser(identifier))
    }

    pub fn to_wire_identifier(&self) -> RustyAcmeResult<WireIdentifier> {
        Ok(match self {
            AcmeIdentifier::WireappDevice(id) => serde_json::from_str(id)?,
            AcmeIdentifier::WireappUser(id) => serde_json::from_str(id)?,
        })
    }

    /// ACME protocol imposes this to be a json string while we need it to be a json object so
    /// we serialize it to json like this which is simpler than implementing a serde Visitor
    pub fn to_json(&self) -> RustyAcmeResult<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
impl AcmeIdentifier {
    pub fn new_device() -> Self {
        Self::try_new_device(
            ClientId::default(),
            QualifiedHandle::default(),
            "Alice Smith".to_string(),
            "wire.com".to_string(),
        )
        .unwrap()
    }

    pub fn new_user() -> Self {
        Self::try_new_user(
            QualifiedHandle::default(),
            "Alice Smith".to_string(),
            "wire.com".to_string(),
        )
        .unwrap()
    }
}

/// Structure of the ACME identifier
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WireIdentifier {
    /// Wire ClientId. Absent on [AcmeIdentifier::WireappUser]
    #[serde(rename = "client-id", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Wire client handle
    #[serde(rename = "handle")]
    pub handle: QualifiedHandle,
    /// Wire display name
    #[serde(rename = "name")]
    pub display_name: String,
    /// Wire domain of the federated backend
    #[serde(rename = "domain")]
    pub domain: String,
}

/// Internal view of 2 merged [WireIdentifier], one of type [AcmeIdentifier::WireappUser] and one of
/// [AcmeIdentifier::WireappDevice]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalIdentifier {
    pub client_id: String,
    pub handle: QualifiedHandle,
    pub display_name: String,
    pub domain: String,
}

impl TryFrom<WireIdentifier> for CanonicalIdentifier {
    type Error = RustyAcmeError;

    fn try_from(i: WireIdentifier) -> RustyAcmeResult<Self> {
        Ok(Self {
            client_id: i.client_id.ok_or(RustyAcmeError::ImplementationError)?,
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
        })
    }
}
