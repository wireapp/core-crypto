use wire_e2e_identity::E2eiClientId;

use crate::{
    ClientId,
    mls::session::{Error, Result},
};

/// This type wraps [ClientId] and verifies upon instantiation that it conforms to the `<userid>-<device-id>@<domain>`
/// format.
///
/// [E2eiClientId] would have been antoher natural canditate to wrap, since it holds the triple data internally.
/// However, this type is intended to be used as a [ClientId] more often than it is to be used as [E2eiClientId], so it
/// should deref to the former.
#[derive(
    core_crypto_macros::Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct QualifiedClientId(ClientId);

impl TryFrom<ClientId> for QualifiedClientId {
    type Error = Error;

    /// Ensure that parsing to an [E2eiClientId] succeeds.
    fn try_from(value: ClientId) -> Result<Self> {
        let _client_id = Self::try_parse(&value)?;
        Ok(Self(value))
    }
}

impl QualifiedClientId {
    /// Try cloning a [ClientId] into an [E2eiClientId].
    pub fn try_parse(value: &ClientId) -> Result<E2eiClientId> {
        let client_id = std::str::from_utf8(value.as_ref()).map_err(|_| Error::InvalidQualifiedClientId)?;
        wire_e2e_identity::E2eiClientId::try_from_qualified(client_id).map_err(|_| Error::InvalidQualifiedClientId)
    }

    /// Clone the data into an [E2eiClientId].
    pub fn as_e2ei_client_id(&self) -> E2eiClientId {
        Self::try_parse(&self.0).expect("We verified that this succeeds on instantiation")
    }
}
