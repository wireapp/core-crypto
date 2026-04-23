use core_crypto_keystore::Database;

use crate::{CoreCryptoError, CoreCryptoResult, bytes_wrapper::bytes_wrapper};

bytes_wrapper!(
    /// A unique identifier for an MLS client.
    ///
    /// Each app instance a user is running, such as desktop or mobile, is a separate client
    /// with its own client id. A single user may therefore have multiple clients.
    /// More information: <https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients>
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[uniffi::export(Debug, Eq)]
    DatabaseKey fallibly wraps core_crypto_keystore::DatabaseKey;
    constructor_map_err(CoreCryptoError::generic())
);

/// Updates the key of the CoreCrypto database.
///
/// This function is intended to be called only once, when migrating from CoreCrypto 5.x to 6.x.
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
