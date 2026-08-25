//! Parse epoch encryption keypair primary keys and copy parsed data into the new table

use log::warn;
use rusqlite::named_params;

use crate::{
    CryptoKeystoreResult, entities::StoredEpochEncryptionKeypairPkRef, migrations::V33StoredEpochEncryptionKeypair,
    traits::Entity,
};

pub(crate) const VERSION: i32 = 34;

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;

    let mut stmt = tx.prepare(
        "INSERT INTO epoch_encryption_keypairs (
        conversation_id,
        own_leaf_index,
        epoch,
        keypairs
    ) VALUES (
        :conversation_id,
        :own_leaf_idx,
        :epoch,
        :keypairs
    )",
    )?;

    let keypairs = V33StoredEpochEncryptionKeypair::load_all(&tx)?;
    for keypair in keypairs {
        let Ok(pk) = StoredEpochEncryptionKeypairPkRef::parse_bytes(&keypair.id) else {
            warn!(
                "failed to parse StoredEpochEncryptionKeypairPkRef from id: {}",
                hex::encode(&keypair.id)
            );
            continue;
        };
        stmt.execute(named_params! {
            ":conversation_id": pk.conversation_id,
            ":own_leaf_idx": pk.own_leaf_idx,
            ":epoch": pk.epoch,
            ":keypairs": keypair.keypairs,
        })?;
    }
    drop(stmt);

    tx.commit()?;

    Ok(())
}
