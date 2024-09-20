// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

#![doc = include_str!("../README.md")]
#![doc = include_str!("../../docs/KEYSTORE_IMPLEMENTATION.md")]

mod error;
pub use error::*;

pub mod connection;
pub mod entities;
pub mod transaction;

cfg_if::cfg_if! {
    if #[cfg(feature = "mls-keystore")] {
        mod mls;
        pub use self::mls::CryptoKeystoreMls;
        pub use self::mls::{ser, deser};
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "proteus-keystore")] {
        mod proteus;
        pub use self::proteus::CryptoKeystoreProteus;
    }
}

pub use connection::Connection;
#[cfg(not(target_family = "wasm"))]
use sha2::{Digest, Sha256};
pub use transaction::KeystoreTransaction;

#[cfg(feature = "dummy-entity")]
pub mod dummy_entity {
    use std::marker::PhantomData;

    use crate::{
        entities::{Entity, EntityBase, EntityFindParams, StringEntityId},
        CryptoKeystoreResult, MissingKeyErrorKind,
    };

    #[derive(Debug, Eq, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct DummyStoreValue;
    #[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
    impl EntityBase for DummyStoreValue {
        type ConnectionType = crate::connection::KeystoreDatabaseConnection;
        type AutoGeneratedFields = ();
        const COLLECTION_NAME: &'static str = "";

        fn to_missing_key_err_kind() -> MissingKeyErrorKind {
            MissingKeyErrorKind::MlsGroup
        }

        fn to_transaction_entity(self) -> crate::transaction::Entity {
            unimplemented!("Not implemented")
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
        async fn delete(_conn: &mut Self::ConnectionType, _id: StringEntityId<'_>) -> CryptoKeystoreResult<()> {
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

/// Used to calculate ID hashes for some MlsEntities' SQLite tables (not used on wasm).
/// We only use sha256 on platforms where we use SQLite.
/// On wasm, we use IndexedDB, a key-value store, via the idb crate.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
