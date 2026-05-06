use openmls_traits::types::HashType;
use wire_e2e_identity::HashAlgorithm;

use super::{Error, Result};
use crate::MlsCiphersuite;

#[derive(
    Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, derive_more::Deref, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
/// A wrapper for the OpenMLS Ciphersuite, so that we are able to provide a default value.
pub struct CipherSuite(pub(crate) MlsCiphersuite);

impl CipherSuite {
    pub(crate) fn e2ei_hash_alg(&self) -> HashAlgorithm {
        match self.0.hash_algorithm() {
            HashType::Sha2_256 => HashAlgorithm::SHA256,
            HashType::Sha2_384 => HashAlgorithm::SHA384,
            HashType::Sha2_512 => HashAlgorithm::SHA512,
        }
    }
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self(MlsCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    }
}

impl From<MlsCiphersuite> for CipherSuite {
    fn from(value: MlsCiphersuite) -> Self {
        Self(value)
    }
}

impl From<CipherSuite> for MlsCiphersuite {
    fn from(ciphersuite: CipherSuite) -> Self {
        ciphersuite.0
    }
}

impl From<CipherSuite> for u16 {
    fn from(cs: CipherSuite) -> Self {
        (&cs.0).into()
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = Error;

    fn try_from(c: u16) -> Result<Self> {
        Ok(MlsCiphersuite::try_from(c)
            .map_err(|_| Error::UnknownCiphersuite)?
            .into())
    }
}

impl PartialEq<MlsCiphersuite> for CipherSuite {
    fn eq(&self, other: &MlsCiphersuite) -> bool {
        self.0 == *other
    }
}
