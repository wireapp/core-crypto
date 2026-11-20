//! Convert the groups and key packages the old openmls fork stored into the state openmls stores now.
//!
//! The fork stored each group whole, serialized into `mls_groups.state`. openmls now stores a group in pieces, in the
//! columns V53 added, and can import one from a `GroupMigrationBundle`, which is a group in its own serde form. The
//! fork's serde form of a group is nearly the same, so we read each group with the fork, patch the differences in its
//! serde form, and import that. Fields that openmls no longer has are ignored.
//!
//! A pending commit of the fork's is dropped. openmls has a different form for it, and there's no use in converting
//! it: core-crypto sends a commit and merges it, or discards it, in the transaction that created it, so a pending
//! commit is only ever left behind by a transaction that failed halfway.
//!
//! A group which is pending, because we joined it by external commit and haven't heard back yet, is dropped. openmls
//! has no form for that at all: it merges an external commit as soon as it builds it. The client joins again.
//!
//! A group we can't convert is dropped, as other migrations do, so the client can still open the database. That means
//! the client has to rejoin the conversation.

use log::warn;
use openmls::{
    prelude::{BasicCredential, Certificate, Credential, KeyPackage, X509Credential},
    storage::GroupMigrationBundle,
};
use openmls_legacy::{group::MlsGroup as LegacyMlsGroup, prelude::KeyPackage as LegacyKeyPackage};
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{CryptoKeystoreError, CryptoKeystoreResult, deser, ser, transaction::MigrationStorage};

pub(crate) const VERSION: i32 = 53;

pub(crate) fn meta_migration(tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
    convert_groups(tx)?;
    convert_key_packages(tx)?;

    // Pre-shared keys other than the resumption keys kept in each group are something core-crypto never used, so
    // there's nothing to convert. Any row here is in the fork's form, which nothing reads anymore.
    let dropped = tx.execute("DELETE FROM mls_psk_bundles", [])?;
    if dropped > 0 {
        warn!("dropped {dropped} pre-shared keys stored by the old openmls fork");
    }
    Ok(())
}

fn convert_groups(tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
    // Group states can be large, and converting one inflates it several times over. So load them one at a time.
    let rows: Vec<(Vec<u8>, bool)> = {
        let mut stmt = tx.prepare("SELECT id, is_pending FROM mls_groups WHERE state IS NOT NULL")?;
        stmt.query_map([], |row| Ok((row.get("id")?, row.get("is_pending")?)))?
            .collect::<Result<_, _>>()?
    };

    let storage = MigrationStorage::from(tx);
    let mut state_stmt = tx.prepare("SELECT state FROM mls_groups WHERE id = ?")?;
    let mut clear_state_stmt = tx.prepare("UPDATE mls_groups SET state = NULL WHERE id = ?")?;
    let mut delete_stmt = tx.prepare("DELETE FROM mls_groups WHERE id = ?")?;

    for (id, is_pending) in rows {
        if is_pending {
            warn!(
                "dropping the pending join of mls group {}: openmls has no form for a pending external commit",
                hex::encode(&id)
            );
            delete_stmt.execute(params![&id])?;
            continue;
        }

        let state: Vec<u8> = state_stmt.query_row(params![&id], |row| row.get("state"))?;
        // Converting a group writes to several tables. The savepoint undoes that if it fails partway, so that the
        // group can be dropped cleanly instead.
        tx.execute("SAVEPOINT convert_group", [])?;
        let converted = migration_bundle(tx, &id, &state)
            .and_then(|bundle| bundle.store(&storage))
            .and_then(|()| Ok(clear_state_stmt.execute(params![&id])?));
        match converted {
            Ok(_) => {
                tx.execute("RELEASE convert_group", [])?;
            }
            Err(err) => {
                tx.execute_batch("ROLLBACK TO convert_group; RELEASE convert_group")?;
                // Dropping the group is deliberate: failing here would leave a database that can't be opened.
                warn!(
                    "failed to convert mls group {} due to {err}; removing",
                    hex::encode(&id)
                );
                delete_stmt.execute(params![&id])?;
            }
        }
    }

    Ok(())
}

/// The bundle openmls imports a group of the fork's from.
fn migration_bundle(
    tx: &rusqlite::Transaction<'_>,
    id: &[u8],
    state: &[u8],
) -> CryptoKeystoreResult<GroupMigrationBundle> {
    let group = deser::<LegacyMlsGroup>(state)?;
    let epoch_key_pairs = epoch_key_pairs(tx, id, group.own_leaf_index().u32(), group.epoch().as_u64())?;
    let update_key_pairs = group
        .own_leaf_nodes
        .iter()
        .map(|leaf_node| {
            let public_key_hash = crate::Sha256Hash::hash_from(leaf_node.encryption_key().as_slice());
            take_encryption_key_pair(tx, public_key_hash.as_slice())
        })
        .collect::<CryptoKeystoreResult<Vec<_>>>()?;

    let mut group = serde_json::to_value(&group)?;
    convert_legacy_forms(&mut group)?;

    let bundle = json!({
        "group": convert_group(group)?,
        "epoch_encryption_key_pairs": epoch_key_pairs,
        "update_encryption_key_pairs": update_key_pairs,
    });
    Ok(serde_json::from_value(bundle)?)
}

/// The fields of the fork's serde form of a group that openmls keeps elsewhere.
///
/// The fork kept most of a group in a nested `CoreGroup`, and the pending proposals in the group itself.
#[derive(Deserialize)]
struct LegacyGroup {
    group: LegacyCoreGroup,
    proposal_store: Value,
    mls_group_config: Value,
    resumption_psk_store: Value,
    own_leaf_nodes: Value,
    aad: Value,
    group_state: Value,
}

#[derive(Deserialize)]
struct LegacyCoreGroup {
    public_group: Map<String, Value>,
    group_epoch_secrets: Value,
    own_leaf_index: Value,
    message_secrets_store: Value,
}

/// Reshape the serde form of a group of the fork's into openmls's.
///
/// openmls has the core group's fields directly in the group, and keeps the pending proposals in the public group. The
/// fork's public group had an unused proposal store of its own, which this replaces.
fn convert_group(group: Value) -> CryptoKeystoreResult<Value> {
    let LegacyGroup {
        group: core_group,
        proposal_store,
        mls_group_config,
        resumption_psk_store,
        own_leaf_nodes,
        aad,
        group_state,
    } = serde_json::from_value(group)?;

    let mut public_group = core_group.public_group;
    public_group.insert("proposal_store".into(), proposal_store);

    let group_state = match group_state.as_str() {
        Some("Operational" | "Inactive") => group_state,
        _ => {
            warn!("dropping the pending commit of an mls group: openmls has a different form for it");
            json!("Operational")
        }
    };

    Ok(json!({
        "mls_group_config": mls_group_config,
        "public_group": public_group,
        "group_epoch_secrets": core_group.group_epoch_secrets,
        "own_leaf_index": core_group.own_leaf_index,
        "message_secrets_store": core_group.message_secrets_store,
        "resumption_psk_store": resumption_psk_store,
        "own_leaf_nodes": own_leaf_nodes,
        "aad": aad,
        "group_state": group_state,
    }))
}

/// Convert key packages, moving each one's leaf private key out of `mls_encryption_keypairs`, where the fork kept it.
fn convert_key_packages(tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx.prepare(
            "SELECT key_package_ref, key_package, leaf_encryption_key_hash FROM mls_key_packages
            WHERE leaf_encryption_private_key IS NULL",
        )?;
        stmt.query_map([], |row| {
            Ok((
                row.get("key_package_ref")?,
                row.get("key_package")?,
                row.get("leaf_encryption_key_hash")?,
            ))
        })?
        .collect::<Result<_, _>>()?
    };

    let mut update_stmt = tx.prepare(
        "UPDATE mls_key_packages SET key_package = ?, leaf_encryption_private_key = ? WHERE key_package_ref = ?",
    )?;
    let mut delete_stmt = tx.prepare("DELETE FROM mls_key_packages WHERE key_package_ref = ?")?;

    for (key_package_ref, key_package, leaf_encryption_key_hash) in rows {
        let converted = take_encryption_key_pair(tx, &leaf_encryption_key_hash)
            .and_then(|key_pair| Ok((convert_key_package(&key_package)?, ser(&key_pair.private_key.key)?)));
        match converted {
            Ok((key_package, leaf_encryption_private_key)) => {
                update_stmt.execute(params![key_package, leaf_encryption_private_key, key_package_ref])?;
            }
            Err(err) => {
                warn!(
                    "failed to convert key package {} due to {err}; removing",
                    hex::encode(&key_package_ref)
                );
                delete_stmt.execute(params![key_package_ref])?;
            }
        }
    }
    Ok(())
}

/// A key package of the fork's, serialized as openmls serializes its key packages.
fn convert_key_package(key_package: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
    let mut key_package = serde_json::to_value(deser::<LegacyKeyPackage>(key_package)?)?;
    convert_legacy_forms(&mut key_package)?;
    ser(&serde_json::from_value::<KeyPackage>(key_package)?)
}

/// Convert the credentials and init keys in the serde form of a group or key package, wherever they are.
///
/// Key packages are in groups too, in proposals to add a member.
fn convert_legacy_forms(value: &mut Value) -> CryptoKeystoreResult<()> {
    match value {
        Value::Object(map) if is_legacy_credential(map) => {
            let legacy = serde_json::from_value(Value::Object(std::mem::take(map)))?;
            *value = serde_json::to_value(convert_credential(legacy)?)?;
        }
        Value::Object(map) => {
            wrap_init_key(map);
            map.values_mut().try_for_each(convert_legacy_forms)?;
        }
        Value::Array(items) => items.iter_mut().try_for_each(convert_legacy_forms)?,
        _ => {}
    }
    Ok(())
}

/// Credentials are the only objects with exactly the fields `credential_type` and `credential`.
fn is_legacy_credential(map: &Map<String, Value>) -> bool {
    map.len() == 2 && map.contains_key("credential_type") && map.contains_key("credential")
}

/// The serde form of a credential of the fork's: its type, and a basic or X509 credential.
#[derive(Deserialize)]
struct LegacyCredential {
    credential: LegacyMlsCredentialType,
}

#[derive(Deserialize)]
enum LegacyMlsCredentialType {
    Basic { identity: Bytes },
    X509 { certificates: Vec<Bytes> },
}

/// Rebuild a credential of the fork's from its parts.
///
/// The fork's credentials are an enum of a basic and an X509 credential. openmls keeps a credential's content as the
/// bytes it is encoded as.
fn convert_credential(LegacyCredential { credential }: LegacyCredential) -> CryptoKeystoreResult<Credential> {
    Ok(match credential {
        LegacyMlsCredentialType::Basic { identity } => BasicCredential::new(identity.vec).into(),
        LegacyMlsCredentialType::X509 { certificates } => {
            X509Credential::new(certificates.into_iter().map(|c| Certificate::new(c.vec)).collect())
                .try_into()
                .map_err(|e| CryptoKeystoreError::InvalidX509Credential(format!("encoding the chain: {e}")))?
        }
    })
}

/// Wrap a key package's init key in the `InitKey` openmls has for it.
///
/// The fork had the bare `HpkePublicKey`, whose serde form is `{ vec }`.
fn wrap_init_key(map: &mut Map<String, Value>) {
    if let Some(init_key) = map.get_mut("init_key")
        && init_key.get("vec").is_some()
    {
        *init_key = json!({ "key": init_key.take() });
    }
}

/// `VLBytes`, `SecretVLBytes` and the newtypes around them.
#[derive(Deserialize, Serialize)]
struct Bytes {
    vec: Vec<u8>,
}

/// An `EncryptionKeyPair`, in the serde form the fork and openmls share. Neither crate exports the type.
#[derive(Deserialize, Serialize)]
struct EncryptionKeyPair {
    public_key: Key,
    private_key: Key,
}

#[derive(Deserialize, Serialize)]
struct Key {
    key: Bytes,
}

/// The encryption key pairs of our own leaf and the parent nodes we know the private keys of, in this epoch.
fn epoch_key_pairs(
    tx: &rusqlite::Transaction<'_>,
    id: &[u8],
    own_leaf_index: u32,
    epoch: u64,
) -> CryptoKeystoreResult<Vec<EncryptionKeyPair>> {
    let key_pairs: Option<Vec<u8>> = tx
        .query_row(
            "SELECT keypairs FROM epoch_encryption_keypairs
            WHERE conversation_id = ? AND own_leaf_index = ? AND epoch = ?",
            params![id, own_leaf_index, epoch],
            |row| row.get(0),
        )
        .optional()?;
    match key_pairs {
        Some(key_pairs) => deser(&key_pairs),
        None => Ok(Vec::new()),
    }
}

/// An encryption key pair, by the hash of its public key, removed from where the fork kept it.
///
/// openmls keeps it elsewhere now: in a group, for an update we proposed, or with its key package.
fn take_encryption_key_pair(
    tx: &rusqlite::Transaction<'_>,
    public_key_hash: &[u8],
) -> CryptoKeystoreResult<EncryptionKeyPair> {
    let key_pair: Vec<u8> = tx
        .query_row(
            "SELECT sk FROM mls_encryption_keypairs WHERE pk_sha256 = ?",
            params![public_key_hash],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| CryptoKeystoreError::MigrationFailed("an encryption key pair is missing".into()))?;
    tx.execute(
        "DELETE FROM mls_encryption_keypairs WHERE pk_sha256 = ?",
        params![public_key_hash],
    )?;
    deser(&key_pair)
}

#[cfg(test)]
mod tests {
    use openmls::prelude::tls_codec::Serialize as _;

    use super::*;

    const CERTIFICATE: &[&str] = &[
        "3082017e30820130a003020102021460ac166fb880286029a3bebc93c21c3f0345fd07300506032b65703010310e300c0603",
        "5504030c05616c696365301e170d3236313131393135343535355a170d3236313132303135343535355a3010310e300c0603",
        "5504030c05616c696365302a300506032b6570032100663b27f6d6f4f05f7a2287cb63e30bc028ae1bec5dfaac58eee4dc2c",
        "eaee6345a3819b308198301d0603551d0e04160414fcd4301905bcba2d719fae83e959b5fce7a67780301f0603551d230418",
        "30168014fcd4301905bcba2d719fae83e959b5fce7a67780300f0603551d130101ff040530030101ff30450603551d11043e",
        "303c863a776972656170703a2f2f5a48704c5a4c5a4d524f654d577034734a6c4c3258412164656530393066316564393465",
        "34633840776972652e636f6d300506032b6570034100ce560f21fb54b8f9df7e405002089b9e6e8732e2d5702d4e52640492",
        "21a1df5530385c3f16015b56b59c860a986074f4008fcf502a0833468a18663e61994100",
    ];

    /// An X509 credential of the fork's becomes openmls's form of the same credential: its encoding, which RFC 9420
    /// defines, is unchanged.
    #[test]
    fn x509_credentials_are_converted() {
        // The fork parses the certificates, so they have to be real ones. This one is self-signed, with a Wire client
        // ID in its subject alternative name, which is where the fork looks for the identity.
        let certificate = hex::decode(CERTIFICATE.concat()).unwrap();
        let legacy = openmls_legacy::prelude::Credential::new_x509(vec![certificate]).unwrap();
        let mut value = json!({ "credential": legacy.clone() });

        convert_legacy_forms(&mut value).unwrap();
        let credential: openmls::prelude::Credential = serde_json::from_value(value["credential"].take()).unwrap();

        assert_eq!(
            credential.tls_serialize_detached().unwrap(),
            legacy.tls_serialize_detached().unwrap()
        );
    }

    /// A key package's init key gets the wrapper openmls has for it, wherever the key package is.
    #[test]
    fn init_keys_are_wrapped() {
        let mut value = json!({ "queued": [{ "payload": { "init_key": { "vec": [1, 2, 3] } } }] });

        convert_legacy_forms(&mut value).unwrap();

        assert_eq!(
            value["queued"][0]["payload"]["init_key"],
            json!({ "key": { "vec": [1, 2, 3] } })
        );
    }
}
