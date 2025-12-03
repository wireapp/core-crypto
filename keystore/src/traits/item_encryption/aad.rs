use crate::{CryptoKeystoreResult, Entity, KeyType as _};

pub(super) const AES_GCM_256_NONCE_SIZE: usize = 12;

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Aad {
    type_name: Vec<u8>,
    id: Vec<u8>,
}

impl<E> From<&'_ E> for Aad
where
    E: Entity,
{
    fn from(value: &E) -> Self {
        let type_name = E::COLLECTION_NAME.as_bytes().to_vec();
        let id = value.primary_key().bytes().into_owned();
        Self { type_name, id }
    }
}

impl Aad {
    pub(super) fn serialize(&self) -> CryptoKeystoreResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(Into::into)
    }

    pub(super) fn from_primary_key<E: Entity>(primary_key: &E::PrimaryKey) -> Self {
        let type_name = E::COLLECTION_NAME.as_bytes().to_vec();
        let id = primary_key.bytes().into_owned();
        Self { type_name, id }
    }
}
