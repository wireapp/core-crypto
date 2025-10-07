use core_crypto_keystore::{ConnectionType, Database};

use crate::{CoreCryptoError, CoreCryptoResult};

/// The key used to encrypt the database.
#[derive(Debug, derive_more::From, derive_more::Into, PartialEq, Eq, Clone, derive_more::Deref, uniffi::Object)]
#[uniffi::export(Eq)]
pub struct DatabaseKey(core_crypto_keystore::DatabaseKey);

impl DatabaseKey {
    /// Convert a [`core_crypto_keystore::DatabaseKey`] into the local type.
    ///
    /// Note that the target of this conversion changes according to the compilation target.
    pub fn from_cc(cc: core_crypto_keystore::DatabaseKey) -> DatabaseKeyMaybeArc {
        Self(cc).into()
    }
}

#[uniffi::export]
impl DatabaseKey {
    /// Construct a new instance from a byte vector.
    #[uniffi::constructor]
    pub fn new(key: Vec<u8>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::DatabaseKey::try_from(key.as_slice())
            .map(Self)
            .map_err(CoreCryptoError::generic())
    }
}

pub(crate) type DatabaseKeyMaybeArc = std::sync::Arc<DatabaseKey>;

impl super::ToCc for DatabaseKeyMaybeArc {
    type Target = core_crypto_keystore::DatabaseKey;

    #[inline]
    fn to_cc(self) -> core_crypto_keystore::DatabaseKey {
        std::sync::Arc::unwrap_or_clone(self).0
    }

    #[inline]
    fn as_cc(&self) -> &core_crypto_keystore::DatabaseKey {
        &self.as_ref().0
    }
}

/// Updates the key of the CoreCrypto database.
/// To be used only once, when moving from CoreCrypto <= 5.x to CoreCrypto 6.x.
#[uniffi::export]
pub async fn migrate_database_key_type_to_bytes(
    path: &str,
    old_key: &str,
    new_key: &DatabaseKey,
) -> CoreCryptoResult<()> {
    Database::migrate_db_key_type_to_bytes(path, old_key, &new_key.0)
        .await
        .map_err(CoreCryptoError::generic())
}

/// Updates the key of the CoreCrypto database.
#[uniffi::export]
pub async fn update_database_key(name: &str, old_key: &DatabaseKey, new_key: &DatabaseKey) -> CoreCryptoResult<()> {
    let mut db = Database::open(ConnectionType::Persistent(name), &old_key.0)
        .await
        .map_err(CoreCryptoError::generic())?;
    db.update_key(&new_key.0).await.map_err(CoreCryptoError::generic())?;
    db.close().await.map_err(CoreCryptoError::generic())?;
    Ok(())
}
