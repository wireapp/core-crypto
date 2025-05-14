use super::error::Error;

/// A Client identifier
///
/// A unique identifier for clients. A client is an identifier for each App a user is using, such as desktop,
/// mobile, etc. Users can have multiple clients.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients)
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::Deref, serde::Serialize, serde::Deserialize)]
pub struct ClientId(pub(crate) Vec<u8>);

impl From<&[u8]> for ClientId {
    fn from(value: &[u8]) -> Self {
        Self(value.into())
    }
}

impl From<Vec<u8>> for ClientId {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Box<[u8]>> for ClientId {
    fn from(value: Box<[u8]>) -> Self {
        Self(value.into())
    }
}

impl From<ClientId> for Box<[u8]> {
    fn from(value: ClientId) -> Self {
        value.0.into_boxed_slice()
    }
}

#[cfg(test)]
impl From<&str> for ClientId {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().into())
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for ClientId {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_slice()))
    }
}

impl std::str::FromStr for ClientId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            hex::decode(s).map_or_else(|_| s.as_bytes().to_vec(), std::convert::identity),
        ))
    }
}

#[cfg(test)]
impl ClientId {
    pub(crate) fn to_user_id(&self) -> String {
        let self_bytes: &[u8] = &self.0;
        crate::e2e_identity::id::WireQualifiedClientId::try_from(self_bytes)
            .unwrap()
            .get_user_id()
    }

    pub(crate) fn to_string_triple(&self) -> [String; 3] {
        let qualified_id = crate::e2e_identity::id::QualifiedE2eiClientId::from(self.clone());
        let id_string: String = qualified_id.try_into().unwrap();
        [id_string, "".into(), self.to_user_id()]
    }
}
