use super::super::{Entity, KeyType};
use crate::{CryptoKeystoreResult, traits::PrimaryKey};

pub(super) const AES_GCM_256_NONCE_SIZE: usize = 12;

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Aad {
    type_name: Vec<u8>,
    id: Vec<u8>,
}

impl<E> From<&'_ E> for Aad
where
    E: Entity,
    <E as PrimaryKey>::PrimaryKey: KeyType,
{
    fn from(value: &E) -> Self {
        let type_name = E::TABLE_NAME.as_bytes().to_vec();
        let id = value.primary_key().bytes().into_owned();
        Self { type_name, id }
    }
}

impl Aad {
    pub(super) fn serialize(&self) -> CryptoKeystoreResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(Into::into)
    }

    pub(super) fn from_primary_key<E>(primary_key: &E::PrimaryKey) -> Self
    where
        E: Entity,
        <E as PrimaryKey>::PrimaryKey: KeyType,
    {
        let type_name = E::TABLE_NAME.as_bytes().to_vec();
        let id = primary_key.bytes().into_owned();
        Self { type_name, id }
    }

    /// Don't use this unless you really have to! Prefer [`Self::from_primary_key`].
    pub(super) fn from_encryption_key_bytes<E: Entity>(key_bytes: impl AsRef<[u8]>) -> Self {
        let type_name = E::TABLE_NAME.as_bytes().to_vec();
        let id = key_bytes.as_ref().to_owned();
        Self { type_name, id }
    }
}
