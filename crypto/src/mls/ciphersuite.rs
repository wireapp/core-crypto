use super::{Error, Result};
use crate::prelude::CiphersuiteName;
use openmls_traits::types::{Ciphersuite, HashType};
use wire_e2e_identity::prelude::HashAlgorithm;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, derive_more::Deref, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
/// A wrapper for the OpenMLS Ciphersuite, so that we are able to provide a default value.
pub struct MlsCiphersuite(pub(crate) Ciphersuite);

impl MlsCiphersuite {
    pub(crate) fn e2ei_hash_alg(&self) -> HashAlgorithm {
        match self.0.hash_algorithm() {
            HashType::Sha2_256 => HashAlgorithm::SHA256,
            HashType::Sha2_384 => HashAlgorithm::SHA384,
            HashType::Sha2_512 => HashAlgorithm::SHA512,
        }
    }
}

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
    type Error = Error;

    fn try_from(c: u16) -> Result<Self> {
        Ok(CiphersuiteName::try_from(c)
            .map_err(|_| Error::UnknownCiphersuite)?
            .into())
    }
}
