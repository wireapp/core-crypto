use std::sync::Arc;

use core_crypto::RecursiveError;
use wire_e2e_identity::E2eiClientId;

use crate::{ClientId, CoreCryptoResult};

/// This type wraps `ClientId` and verifies upon instantiation that it conforms to the `<userid>-<device-id>@<domain>`
/// format.
/// Instantiate via [ClientId::parse_qualified].
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
    derive_more::DerefMut,
    uniffi::Object,
)]
#[uniffi::export(Eq, Hash)]
pub struct QualifiedClientId(Arc<ClientId>);

impl QualifiedClientId {
    pub(crate) fn new(client_id: ClientId) -> CoreCryptoResult<Self> {
        let _triple = core_crypto::QualifiedClientId::try_parse(&client_id)
            .map_err(RecursiveError::mls_client("parsing client id triple"))?;
        Ok(Self(Arc::new(client_id)))
    }

    pub(crate) fn as_e2ei_client_id(&self) -> E2eiClientId {
        core_crypto::QualifiedClientId::try_parse(&self.0).expect("We verified that this works on instatiation")
    }
}

#[uniffi::export]
impl QualifiedClientId {
    /// Get the base client id which this was instantiated from.
    pub fn client_id(&self) -> Arc<ClientId> {
        self.0.clone()
    }
}
