//! This module was copied from an earlier version of core crypto (v1.0.0), with minor changes to make it
//! compile.
//! It is needed to migrate entities with encryption prior to changes to the aad.

mod error;
pub use error::*;

pub mod connection;
pub mod entities;
mod mls;
pub use self::mls::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "proteus-keystore")] {
        mod proteus;

    }
}

pub use connection::Connection;

#[cfg(feature = "dummy-entity")]
pub mod dummy_entity {
    use super::{
        CryptoKeystoreResult, MissingKeyErrorKind,
        entities::{Entity, EntityBase, EntityFindParams, StringEntityId},
    };

    #[derive(Debug, Eq, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct DummyStoreValue;
    #[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
    impl EntityBase for DummyStoreValue {
        type ConnectionType = crate::keystore_v_1_0_0::connection::KeystoreDatabaseConnection;
        type AutoGeneratedFields = ();

        fn to_missing_key_err_kind() -> MissingKeyErrorKind {
            MissingKeyErrorKind::MlsGroup
        }

        async fn save(&self, _conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
            Ok(())
        }
        async fn find_all(
            _conn: &mut Self::ConnectionType,
            _params: EntityFindParams,
        ) -> CryptoKeystoreResult<Vec<Self>> {
            Ok(vec![])
        }
        async fn find_one(
            _conn: &mut Self::ConnectionType,
            _id: &StringEntityId,
        ) -> CryptoKeystoreResult<Option<Self>> {
            Ok(Some(DummyStoreValue))
        }
        async fn find_many(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> CryptoKeystoreResult<Vec<Self>> {
            // Default, inefficient & naive method
            let mut ret = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(entity) = Self::find_one(conn, id).await? {
                    ret.push(entity);
                }
            }

            Ok(ret)
        }
        async fn count(_conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<usize> {
            Ok(0)
        }
        async fn delete(_conn: &mut Self::ConnectionType, _id: &[StringEntityId]) -> CryptoKeystoreResult<()> {
            Ok(())
        }
    }

    impl Entity for DummyStoreValue {
        fn id_raw(&self) -> &[u8] {
            b""
        }

        #[cfg(target_family = "wasm")]
        fn encrypt(&mut self, _cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
            Ok(())
        }
        #[cfg(target_family = "wasm")]
        fn decrypt(&mut self, _cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DummyValue(Vec<u8>);

    impl From<&str> for DummyValue {
        fn from(id: &str) -> Self {
            DummyValue(format!("dummy value {id}").into_bytes())
        }
    }
}
