//! This migration rewrites readable MLS groups and removes unreadable ones.
//!
//! This has the effect of upgrading from a `V10PersistedMlsGroup` to a `LegacyPersistedMlsGroup`, which differs
//! in that its `parent_id` field is no longer encrypted.

mod v10_persisted_mls_group;

use std::{cell::Cell, rc::Rc};

use idb::{Event as _, Factory, Request as _, builder::DatabaseBuilder};
use js_sys::Uint8Array;
use serde::Serialize as _;
use wasm_bindgen::JsValue;

use self::v10_persisted_mls_group::V10PersistedMlsGroup;
use super::DB_VERSION_11;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey,
    connection::idb_migration::legacy::{
        connection::Database,
        traits::{Encrypting as _, EntityBase as _},
    },
    migrations::historical::LegacyPersistedMlsGroup,
};

/// Rewrite MLS groups in the same transaction that advances the IndexedDB version.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v10::get_builder(name);
    let db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let storage = db_during_migration.storage();
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    let mut changes = Vec::new();
    for key in storage.get_all_storage_keys::<V10PersistedMlsGroup>().await? {
        let replacement = match storage.get::<V10PersistedMlsGroup>(&key).await {
            Ok(Some(group)) => {
                let group = LegacyPersistedMlsGroup::from(group);
                Some(group.encrypt(&storage.cipher)?.serialize(&serializer)?)
            }
            Ok(None) => None,
            Err(err) => {
                log::warn!("Dropping an unreadable IndexedDB v10 MLS group: {err}");
                None
            }
        };
        changes.push((JsValue::from(Uint8Array::from(key.as_slice())), replacement));
    }
    db_during_migration.close().await?;

    // V11 has no schema changes. Commit the data changes with the version bump so an interrupted
    // migration never tries to decrypt a plaintext parent ID on retry.
    let mut request = Factory::new()?.open(name, Some(DB_VERSION_11))?;
    let write_error = Rc::new(Cell::new(None));
    let movable_write_error = Rc::clone(&write_error);
    request.on_upgrade_needed(move |event| {
        let request = event.target().expect("IndexedDB upgrade event has an open request");
        let tx = request
            .transaction()
            .expect("IndexedDB upgrade has a versionchange transaction");
        let queue_writes = || -> Result<(), idb::Error> {
            let store = tx.object_store(V10PersistedMlsGroup::TABLE_NAME)?;
            for (key, replacement) in changes {
                if let Some(value) = replacement {
                    store.put(&value, Some(&key))?;
                } else {
                    store.delete(key)?;
                }
            }
            Ok(())
        };
        // Failed requests abort the upgrade by default. A synchronous error while queuing
        // requests needs an explicit abort to roll back any requests already queued.
        if let Err(err) = queue_writes() {
            movable_write_error.set(Some(err));
            if let Err(err) = tx.abort() {
                log::error!("Could not roll back the IndexedDB v11 upgrade: {err}");
            }
        }
    });

    let migrated_idb = request.await.map_err(|err| {
        let err = write_error.take().unwrap_or(err);
        CryptoKeystoreError::MigrationFailed(format!("rewriting IndexedDB v11 MLS groups: {err}"))
    })?;
    let version = migrated_idb.version();
    migrated_idb.close();
    version.map_err(Into::into)
}

/// Set up the builder for v11.
///
/// This has no structural changes; it's a pure data migration.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v10::get_builder(name).version(DB_VERSION_11)
}
