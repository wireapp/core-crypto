//! Migration of data from the legacy IndexedDB-based storage to the unified rusqlite connection.
//!
//! On WASM, this is called during [`super::Database::open_internal`] via [`super::os_unknown::open`]
//! to detect and migrate legacy data before the new connection is initialised.

mod legacy;
#[cfg(test)]
mod tests;

use idb::Factory;
use rusqlite::Connection;

use self::legacy::connection::{DatabaseConnection as _, KeystoreDatabaseConnection};
#[cfg(feature = "proteus-keystore")]
use self::legacy::entities::proteus::identity::LegacyProteusIdentity;
#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusPrekey, ProteusSession};
use crate::{
    CryptoKeystoreResult, DatabaseKey,
    connection::{
        idb_migration::legacy::entities::mls::{
            e2ei_acme_ca::E2eiAcmeCA, e2ei_crl::E2eiCrl, e2ei_intermediate_cert::E2eiIntermediateCert,
            group::legacy_persisted_mls_pending_group::LegacyPersistedMlsPendingGroup,
            pending_group::PersistedMlsPendingGroup as IdbPersistedMlsPendingGroup,
            pending_message::LegacyMlsPendingMessage, stored_keypackage::StoredKeypackage,
        },
        migrations::MigrationTarget,
    },
    entities::{ConsumerData, StoredBufferedCommit, StoredEncryptionKeyPair, StoredHpkePrivateKey, StoredPskBundle},
    migrations::{LegacyPersistedMlsGroup, StoredCredentialV36, V33StoredEpochEncryptionKeypair},
    traits::EntityDatabaseMutation as _,
};

/// Every legacy object store which [`maybe_migrate`] copies verbatim, named by the entity type it is read as.
///
/// Invoke with the name of a macro which accepts the list; that macro is expanded with the entities as its input.
/// Both the import itself and its tests expand this list, so an entity added here is seeded and checked by the tests,
/// and an entity added to the tests alone does not compile.
///
/// `PersistedMlsPendingGroup` is deliberately absent: its type changed shape, so the import copies it by hand.
macro_rules! for_each_imported_legacy_entity {
    ($callback:ident) => {
        $callback! {
            ConsumerData,
            E2eiAcmeCA,
            E2eiCrl,
            E2eiIntermediateCert,
            LegacyMlsPendingMessage,
            LegacyPersistedMlsGroup,
            StoredBufferedCommit,
            StoredCredentialV36,
            StoredEncryptionKeyPair,
            V33StoredEpochEncryptionKeypair,
            StoredHpkePrivateKey,
            StoredKeypackage,
            StoredPskBundle,
            #[cfg(feature = "proteus-keystore")]
            LegacyProteusIdentity,
            #[cfg(feature = "proteus-keystore")]
            ProteusPrekey,
            #[cfg(feature = "proteus-keystore")]
            ProteusSession,
        }
    };
}

/// This only needs reexport for use in the test module when we are testing.
#[cfg(test)]
pub(crate) use for_each_imported_legacy_entity;

/// Returns `true` if a legacy IndexedDB database with the given name exists and contains data.
///
/// A freshly-created (empty) IDB database always has version 1; any version greater than 1
/// indicates that the legacy migration sequence has been applied and there may be data present.
pub async fn legacy_idb_exists(name: &str) -> bool {
    let Ok(factory) = Factory::new() else {
        return false;
    };
    let Ok(req) = factory.open(name, None) else {
        return false;
    };
    let Ok(db) = req.await else {
        return false;
    };
    let version = db.version().unwrap_or(0);
    db.close();
    version > 1
}

/// Delete the legacy IndexedDB database with the given name.
///
/// This is exposed publicly so that callers can retry deletion independently if it fails during
/// [`maybe_migrate`] (e.g. after a crash between a successful data copy and a failed cleanup).
pub async fn delete_legacy_idb(name: &str) -> CryptoKeystoreResult<()> {
    let factory = Factory::new()?;
    factory.delete(name)?.await?;
    Ok(())
}

/// Rekey a legacy IndexedDB database from the old string-derived cipher to the new bytes [`DatabaseKey`].
///
/// As a straight passthrough to a `pub(crate)` function, this really only exists so that its caller in the
/// parent module has a nicer call path.
pub(super) async fn migrate_legacy_idb_key_type_to_bytes(
    name: &str,
    old_key: &str,
    new_key: &DatabaseKey,
) -> CryptoKeystoreResult<()> {
    self::legacy::connection::platform::wasm::migrations::migrate_db_key_type_to_bytes(name, old_key, new_key).await
}

/// If a legacy IDB database exists at `name` and its data has not yet been imported, copy all of it into
/// `new_conn`, then delete the legacy IDB.
///
/// Precondition: `new_conn` has been decrypted. It may be empty, or it may be left over from an earlier attempt
/// at this import which failed or was interrupted at any point.
///
/// Postconditions, when the import runs:
/// - `new_conn` is at the schema version matching the final IDB version, and holds exactly the legacy data
/// - the legacy IDB database is deleted, on a best-effort basis
/// - `new_conn` is _not_ fully migrated and requires a further migration to the latest version
///
/// Whether the import has already happened is judged by `new_conn`'s schema version. Creating the file and
/// importing into it are separate steps, and the file survives a failure between them; judging by the file
/// would take such a failure for a completed import and open an empty keystore over the user's unread data.
/// Judged by the schema version instead, a database at or below the import's version is one the import has not
/// finished, so the import runs again. To make that safe the copy is a single transaction which first clears
/// everything it is about to write, so partial state from an earlier attempt is replaced rather than duplicated.
/// The legacy database is only deleted after that transaction commits, so it remains the source of truth until
/// the copy is complete.
///
/// This is a no-op when:
/// - `new_conn` is past the import's schema version, which means the import finished on an earlier open, or
/// - no legacy IDB database exists at `name`, as on a fresh install.
pub(super) async fn maybe_migrate(
    name: &str,
    database_key: &DatabaseKey,
    new_conn: &mut Connection,
) -> CryptoKeystoreResult<()> {
    /// This SQL database version corresponds to the final IDB version,
    /// so is what we need to perform the migration from IDB.
    const SQL_DATABASE_VERSION_AS_OF_FINAL_IDB_VERSION: u16 = 22;

    // Checked first because it is cheap: an already-imported database never touches IndexedDB again.
    let version = new_conn.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))?;
    // Strictly greater, not equal: the schema reaches the import's version before the rows are copied, so a
    // database at exactly that version may hold nothing yet. Only the migrations which follow a successful
    // import move it past, so being past it is the earliest state which implies the copy committed.
    if version > i32::from(SQL_DATABASE_VERSION_AS_OF_FINAL_IDB_VERSION) {
        // the import finished on an earlier open and the database has moved on since
        return Ok(());
    }

    if !legacy_idb_exists(name).await {
        return Ok(());
    }

    // open the legacy IDB, running all IDB migrations (v0 → v11) in the process.
    let mut legacy_conn = KeystoreDatabaseConnection::open(name, database_key).await?;

    // Migrate the new connection to the version corresponding to the final IDB migration version.
    super::migrations::run_migrations(
        new_conn,
        MigrationTarget::Version(SQL_DATABASE_VERSION_AS_OF_FINAL_IDB_VERSION),
    )?;

    // the type of `PersistedMlsPendingGroup` changed, so it is copied by hand below rather than via the macro
    let pending_groups = <IdbPersistedMlsPendingGroup as legacy::traits::Entity>::load_all(&mut legacy_conn).await?;

    macro_rules! migrate_entities {
        ($( $(#[$attribute:meta])* $entity:ty ),* $(,)?) => {
            paste::paste! {
                // load all entities into memory -- probably fine, but we could consider interweaving
                // a bit and dropping each entity's list after it's saved to the transaction
                // if memory usage proves to be an issue
                $(
                    $(#[$attribute])*
                    let [<$entity:lower>] = <$entity as $crate::connection::idb_migration::legacy::traits::Entity>::load_all(&mut legacy_conn).await?;
                )*
                drop(legacy_conn);

                // Everything below is one transaction, so that an interrupted import leaves either all of the
                // legacy data in place or none of it, and a retry finds a state it knows how to handle.
                let tx = new_conn.transaction()?;

                // Clear whatever an earlier, unfinished attempt may have copied. At this schema version the legacy
                // table names are the SQL table names. Messages go before the pending groups they may reference.
                tx.execute("DELETE FROM mls_pending_messages", [])?;
                tx.execute("DELETE FROM mls_pending_groups", [])?;
                $(
                    $(#[$attribute])*
                    tx.execute(
                        &format!(
                            "DELETE FROM {}",
                            <$entity as $crate::connection::idb_migration::legacy::traits::EntityBase>::TABLE_NAME
                        ),
                        [],
                    )?;
                )*

                // we don't care about `parent_id`/`custom_configuration`; both are nullable and already dropped
                // at the end of the current migration chain.
                for IdbPersistedMlsPendingGroup {
                    ref mut id,
                    ref mut state,
                    ..
                } in pending_groups
                {
                    let id = std::mem::replace(id, Vec::new().into()).into();
                    let state = std::mem::take(state);
                    LegacyPersistedMlsPendingGroup { id, state }.save(&tx)?;
                }

                // write all entities into the rusqlite database
                $(
                    $(#[$attribute])*
                    for row in [<$entity:lower>] {
                        // note: no pre-save; preserve creation times etc
                        row.save(&tx)?;
                    }
                )*
                tx.commit()?;
            }
        };
    }

    for_each_imported_legacy_entity!(migrate_entities);

    // clients can recover independently from this; the migrations all succeeded, so no need to
    // propagate an error
    if let Err(err) = delete_legacy_idb(name).await {
        log::warn!(err:err; "failed to delete legacy IDB database during migration to rusqlite");
    }

    Ok(())
}
