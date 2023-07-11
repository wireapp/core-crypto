use crate::prelude::CiphersuiteName;
use crate::{CryptoError, CryptoResult};
use openmls_traits::types::Ciphersuite;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, derive_more::Deref, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
/// A wrapper for the OpenMLS Ciphersuite, so that we are able to provide a default value.
pub struct MlsCiphersuite(pub(crate) Ciphersuite);

impl Default for MlsCiphersuite {
    fn default() -> Self {
        Self(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    fn from(value: Ciphersuite) -> Self {
        Self(value)
    }
}

impl From<MlsCiphersuite> for Ciphersuite {
    fn from(ciphersuite: MlsCiphersuite) -> Self {
        ciphersuite.0
    }
}

impl From<MlsCiphersuite> for u16 {
    fn from(cs: MlsCiphersuite) -> Self {
        (&cs.0).into()
    }
}

impl TryFrom<u16> for MlsCiphersuite {
    type Error = CryptoError;

    fn try_from(c: u16) -> CryptoResult<Self> {
        Ok(CiphersuiteName::try_from(c)
            .map_err(|_| CryptoError::ImplementationError)?
            .into())
    }
}
