use crate::{
    CryptoKeystoreResult,
    traits::{BorrowPrimaryKey, Entity, EntityGetBorrowed, PrimaryKey, UniqueEntity},
};

#[derive(Debug, Eq, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DummyStoreValue;

impl PrimaryKey for DummyStoreValue {
    type PrimaryKey = Vec<u8>;
    fn primary_key(&self) -> Self::PrimaryKey {
        Vec::new()
    }
}

impl BorrowPrimaryKey for DummyStoreValue {
    type BorrowedPrimaryKey = [u8];
    fn borrow_primary_key(&self) -> &Self::BorrowedPrimaryKey {
        &[]
    }
}

impl Entity for DummyStoreValue {
    const COLLECTION_NAME: &'static str = "";

    fn get(_conn: &rusqlite::Connection, _key: &Vec<u8>) -> CryptoKeystoreResult<Option<Self>> {
        Ok(None)
    }

    fn count(_conn: &rusqlite::Connection) -> CryptoKeystoreResult<u32> {
        Ok(0)
    }

    fn load_all(_conn: &rusqlite::Connection) -> CryptoKeystoreResult<Vec<Self>> {
        Ok(Vec::new())
    }
}

impl EntityGetBorrowed for DummyStoreValue {
    fn get_borrowed(_conn: &rusqlite::Connection, _key: &[u8]) -> CryptoKeystoreResult<Option<Self>>
    where
        for<'pk> &'pk [u8]: crate::traits::KeyType,
    {
        Ok(None)
    }
}

impl UniqueEntity for DummyStoreValue {
    const KEY: Vec<u8> = Vec::new();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DummyValue(Vec<u8>);

impl From<&str> for DummyValue {
    fn from(id: &str) -> Self {
        DummyValue(format!("dummy value {id}").into_bytes())
    }
}
