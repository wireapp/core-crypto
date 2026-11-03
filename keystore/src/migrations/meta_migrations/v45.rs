//! Backfill the key package lifecycle columns which V45 added to `mls_key_packages`.
//!
//! The credential, init key, and leaf encryption key columns can't be populated in SQL: the values only exist
//! inside the serialized key package. The init private key is copied over from `mls_hpke_private_keys`.

use log::warn;
use openmls::prelude::KeyPackage;
use rusqlite::{OptionalExtension, named_params, params};

use crate::{CryptoKeystoreResult, Sha256Hash, deser};

pub(crate) const VERSION: i32 = 45;

pub(crate) fn meta_migration(tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
    // clean up invalid keypackages first
    tx.execute(
        "DELETE FROM mls_key_packages WHERE key_package_ref IS NULL OR key_package IS NULL",
        [],
    )?;

    let rows: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT key_package_ref, key_package FROM mls_key_packages")?;
        stmt.query_map([], |row| Ok((row.get("key_package_ref")?, row.get("key_package")?)))?
            .collect::<Result<_, _>>()?
    };

    // drop these statements once they're no longer needed
    {
        let mut get_hpke_private_key_stmt = tx.prepare(
            "SELECT sk
                FROM mls_hpke_private_keys
                WHERE pk_sha256 = ?",
        )?;

        let mut update_stmt = tx.prepare(
            "UPDATE mls_key_packages SET
                credential_id = :credential_id,
                credential_type = :credential_type,
                hpke_init_public_key_hash = :hpke_init_public_key_hash,
                hpke_init_private_key = :hpke_init_private_key,
                leaf_encryption_key_hash = :leaf_encryption_key_hash
            WHERE key_package_ref = :key_package_ref",
        )?;

        let mut delete_keypackage_stmt = tx.prepare("DELETE FROM mls_key_packages WHERE key_package_ref = ?")?;
        let mut delete_enc_keypair_stmt = tx.prepare("DELETE FROM mls_encryption_keypairs WHERE pk_sha256 = ?")?;

        let mut query_credential_existence = tx.prepare(
            "SELECT EXISTS (
                SELECT 1 FROM mls_credentials
                WHERE public_key_sha256 = :credential_id AND credential_type = :credential_type
            )",
        )?;

        let mut query_leaf_keypair_existence = tx.prepare(
            "SELECT EXISTS (
                SELECT 1 FROM mls_encryption_keypairs
                WHERE pk_sha256 = ?
            )",
        )?;

        for (kp_ref, serialized) in rows {
            let key_package = match deser::<KeyPackage>(&serialized) {
                Ok(key_package) => key_package,
                Err(err) => {
                    warn!(
                        "failed to deserialize keypackage with ref {} due to {err}; removing",
                        hex::encode(&kp_ref)
                    );
                    delete_keypackage_stmt.execute(params![&kp_ref])?;
                    continue;
                }
            };

            let credential_id = Sha256Hash::hash_from(key_package.leaf_node().signature_key().as_slice());
            let credential_type = u16::from(key_package.leaf_node().credential().credential_type());
            let leaf_encryption_key_hash = Sha256Hash::hash_from(key_package.leaf_node().encryption_key().as_slice());
            let hpke_init_public_key_hash = Sha256Hash::hash_from(key_package.hpke_init_key().as_slice());
            let Some(hpke_init_private_key) = get_hpke_private_key_stmt
                .query_one([hpke_init_public_key_hash], |row| row.get::<_, Vec<u8>>(0))
                .optional()?
            else {
                warn!(
                    "failed to find hpke private key for keypackage with ref {}; removing",
                    hex::encode(&kp_ref)
                );
                delete_keypackage_stmt.execute(params![&kp_ref])?;
                delete_enc_keypair_stmt.execute(params![&leaf_encryption_key_hash])?;
                continue;
            };

            let credential_exists = query_credential_existence.query_one(
                named_params! {":credential_id": credential_id, ":credential_type": credential_type},
                |row| row.get::<_, bool>(0),
            )?;
            if !credential_exists {
                warn!(
                    "keypackage with ref {} references a credential which does not exist (hash {credential_id:?}, type {credential_type})",
                    hex::encode(&kp_ref)
                );
                delete_keypackage_stmt.execute(params![&kp_ref])?;
                delete_enc_keypair_stmt.execute(params![&leaf_encryption_key_hash])?;
                continue;
            }

            let leaf_keypair_exists = query_leaf_keypair_existence
                .query_one(params![leaf_encryption_key_hash], |row| row.get::<_, bool>(0))?;
            if !leaf_keypair_exists {
                warn!(
                    "keypackage with ref {} references a leaf keypair which does not exist (pk_sha256 = {})",
                    hex::encode(&kp_ref),
                    hex::encode(leaf_encryption_key_hash)
                );
            }

            // here we trust that the init and leaf key hashes are in fact unique, as they must be from the way we
            // generate key packages
            update_stmt.execute(named_params! {
                ":credential_id": credential_id,
                ":credential_type": credential_type,
                ":hpke_init_public_key_hash": hpke_init_public_key_hash,
                ":hpke_init_private_key": hpke_init_private_key,
                ":leaf_encryption_key_hash": leaf_encryption_key_hash,
                ":key_package_ref": kp_ref,
            })?;
        }
    }

    Ok(())
}
