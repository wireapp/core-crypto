use core_crypto_keystore::{
    CryptoKeystoreError, Transaction,
    entities::ProteusPrekey,
    traits::{Entity, EntityDatabaseMutation as _, FetchFromDatabase as _},
};
use proteus_wasm::keys::PreKeyBundle;

use super::ProteusCentral;
use crate::{KeystoreError, ProteusError, Result};

impl ProteusCentral {
    /// Generates a new Proteus PreKey, stores it in the keystore and returns a serialized PreKeyBundle to be consumed
    /// externally
    ///
    /// Fails if `id` is already taken. Prekeys are not replaceable: the id has been published to
    /// peers in a bundle, and overwriting it would strand anyone still holding that bundle.
    pub(crate) async fn new_prekey(&self, id: u16, transaction: &Transaction) -> Result<Vec<u8>> {
        use proteus_wasm::keys::{PreKey, PreKeyId};

        // The keystore also refuses a duplicate id, but only once the transaction is applied,
        // which would take down whatever else that transaction was doing and report the conflict
        // far from the call responsible for it. Catch it here, while we can still name the id and
        // leave the transaction usable. Reading through the transaction consults its buffered
        // operations as well as the database, so an id claimed earlier in this same transaction
        // counts as taken.
        if transaction
            .get::<ProteusPrekey>(&id)
            .await
            .map_err(KeystoreError::wrap("checking whether a proteus prekey id is free"))?
            .is_some()
        {
            return Err(
                KeystoreError::wrap("saving keystore prekey")(CryptoKeystoreError::AlreadyExists(
                    <ProteusPrekey as Entity>::TABLE_NAME,
                ))
                .into(),
            );
        }

        let prekey_id = PreKeyId::new(id);
        let prekey = PreKey::new(prekey_id);
        let keystore_prekey = core_crypto_keystore::entities::ProteusPrekey::from_raw(
            id,
            prekey.serialise().map_err(ProteusError::wrap("serialising prekey"))?,
        );
        let bundle = PreKeyBundle::new(self.proteus_identity.as_ref().public_key.clone(), &prekey);
        let bundle = bundle
            .serialise()
            .map_err(ProteusError::wrap("serialising prekey bundle"))?;
        keystore_prekey
            .save(transaction)
            .map_err(KeystoreError::wrap("saving keystore prekey"))?;
        Ok(bundle)
    }

    /// Generates a new Proteus Prekey, with an automatically auto-incremented ID.
    ///
    /// See [ProteusCentral::new_prekey]
    pub(crate) async fn new_prekey_auto(&self, transaction: &Transaction) -> Result<(u16, Vec<u8>)> {
        // the guard over the transaction's connectin is not reentrant, so we have to release
        // it before `self.new_prekey` tries to acquire it
        let id = {
            let conn = transaction
                .conn()
                .map_err(KeystoreError::wrap("getting connection from transaction"))?;
            ProteusPrekey::get_free_id(&conn).map_err(KeystoreError::wrap("getting proteus prekey by id"))?
        };
        Ok((id, self.new_prekey(id, transaction).await?))
    }

    /// Returns the Proteus last resort prekey ID (u16::MAX = 65535 = 0xFFFF)
    pub fn last_resort_prekey_id() -> u16 {
        proteus_wasm::keys::MAX_PREKEY_ID.value()
    }

    /// Returns the Proteus last resort prekey
    /// If it cannot be found, one will be created.
    pub(crate) async fn last_resort_prekey(&self, transaction: &Transaction) -> Result<Vec<u8>> {
        let last_resort = if let Some(last_resort) = transaction
            .get::<core_crypto_keystore::entities::ProteusPrekey>(&Self::last_resort_prekey_id())
            .await
            .map_err(KeystoreError::wrap("finding proteus prekey"))?
        {
            proteus_wasm::keys::PreKey::deserialise(&last_resort.prekey)
                .map_err(ProteusError::wrap("deserialising proteus prekey"))?
        } else {
            let last_resort = proteus_wasm::keys::PreKey::last_resort();
            let prekey = last_resort
                .serialise()
                .map_err(ProteusError::wrap("serializing last resort prekey"))?;

            ProteusPrekey::from_raw(Self::last_resort_prekey_id(), prekey)
                .save(transaction)
                .map_err(KeystoreError::wrap("storing proteus last resort prekey"))?;

            last_resort
        };

        let bundle = PreKeyBundle::new(self.proteus_identity.as_ref().public_key.clone(), &last_resort);
        let bundle = bundle
            .serialise()
            .map_err(ProteusError::wrap("serialising prekey bundle"))?;

        Ok(bundle)
    }

    /// Hex-encoded fingerprint of the given prekey
    ///
    /// # Errors
    /// If the prekey cannot be deserialized
    pub fn fingerprint_prekeybundle(prekey: &[u8]) -> Result<String> {
        let prekey = PreKeyBundle::deserialise(prekey).map_err(ProteusError::wrap("deserialising prekey bundle"))?;
        Ok(prekey.identity_key.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::DatabaseKey;
    use rand::RngExt as _;

    use super::*;
    use crate::test_utils::{proteus_utils::*, *};

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn can_produce_proteus_consumed_prekeys() {
        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();

        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();

        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Database::open(&path, &key).await.unwrap();
        let tx = keystore.new_transaction().await.unwrap();
        let mut alice = ProteusCentral::try_new(&tx).await.unwrap();

        let mut bob = CryptoboxLike::init();

        let alice_prekey_bundle_ser = alice.new_prekey(1, &tx).await.unwrap();

        bob.init_session_from_prekey_bundle(&session_id, &alice_prekey_bundle_ser);
        let message = b"Hello world!";
        let encrypted = bob.encrypt(&session_id, message);

        let (_, decrypted) = alice.session_from_message(&tx, &session_id, &encrypted).await.unwrap();

        assert_eq!(message, decrypted.as_slice());

        let encrypted = alice.encrypt(&tx, &session_id, message).await.unwrap();
        let decrypted = bob.decrypt(&session_id, &encrypted).await;

        assert_eq!(message, decrypted.as_slice());
        tx.commit().await.unwrap();
        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }

    /// Auto prekeys fill the holes left by deleted prekeys before extending the id space.
    ///
    /// The order in which the holes get filled is deliberately not asserted: the keystore tracks
    /// ids freed within a transaction in an unordered map, so all that is promised is that every
    /// hole is filled exactly once before any fresh id is handed out.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn auto_prekeys_fill_holes() {
        use core_crypto_keystore::entities::ProteusPrekey;
        const GAP_AMOUNT: usize = 5;
        /// How far past the end of the filled id space to keep claiming ids
        const EXTRA_AMOUNT: u16 = 10;
        const ID_TEST_RANGE: std::ops::RangeInclusive<u16> = 1..=30;

        /// Claim `count` auto prekeys, returning the assigned ids in the order they were handed out.
        async fn claim(alice: &ProteusCentral, tx: &Transaction, count: usize) -> Vec<u16> {
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                let (pk_id, pkb) = alice.new_prekey_auto(tx).await.unwrap();
                let prekey = proteus_wasm::keys::PreKeyBundle::deserialise(&pkb).unwrap();
                assert_eq!(prekey.prekey_id.value(), pk_id, "the bundle must carry the assigned id");
                ids.push(pk_id);
            }
            ids
        }

        /// Pick `count` distinct ids from `ID_TEST_RANGE`, in ascending order.
        fn pick_gap_ids(rng: &mut impl rand::Rng, count: usize) -> Vec<u16> {
            let mut ids = Vec::with_capacity(count);
            while ids.len() < count {
                let id = rng.random_range(ID_TEST_RANGE);
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            ids.sort();
            ids
        }

        fn ascending(ids: &[u16]) -> Vec<u16> {
            let mut ids = ids.to_owned();
            ids.sort();
            ids
        }

        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();

        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Database::open(&path, &key).await.unwrap();
        let tx = keystore.new_transaction().await.unwrap();
        let alice = ProteusCentral::try_new(&tx).await.unwrap();

        // with no holes to fill, ids are simply assigned in ascending order from 1
        let claimed = claim(&alice, &tx, ID_TEST_RANGE.count()).await;
        assert_eq!(claimed, ID_TEST_RANGE.collect::<Vec<_>>());

        let mut rng = rand::rng();

        // punch some holes; the next claims must fill exactly those
        let gap_ids = pick_gap_ids(&mut rng, GAP_AMOUNT);
        for gap_id in &gap_ids {
            ProteusPrekey::delete(&*tx, gap_id).unwrap();
        }
        let claimed = claim(&alice, &tx, GAP_AMOUNT).await;
        assert_eq!(
            ascending(&claimed),
            gap_ids,
            "every deleted id must be reassigned exactly once"
        );

        // punch holes again, but this time keep claiming past them, to check both that holes take
        // priority over fresh ids and that the fresh ids resume above the filled id space
        let gap_ids = pick_gap_ids(&mut rng, GAP_AMOUNT);
        for gap_id in &gap_ids {
            ProteusPrekey::delete(&*tx, gap_id).unwrap();
        }
        let claimed = claim(&alice, &tx, GAP_AMOUNT + EXTRA_AMOUNT as usize).await;
        let (filled, extended) = claimed.split_at(GAP_AMOUNT);
        assert_eq!(
            ascending(filled),
            gap_ids,
            "holes must all be filled before the id space is extended"
        );
        let high_water_mark = *ID_TEST_RANGE.end();
        assert_eq!(
            extended,
            (high_water_mark + 1..=high_water_mark + EXTRA_AMOUNT).collect::<Vec<_>>(),
            "once no holes remain, ids extend the id space in ascending order"
        );

        tx.commit().await.unwrap();
        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }

    /// The last resort prekey is stored in the same table as ordinary prekeys, at `u16::MAX`.
    /// Free-id selection must not treat it as though the id space were exhausted.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn last_resort_prekey_does_not_exhaust_id_space() {
        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();

        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Database::open(&path, &key).await.unwrap();

        // in this transaction the last resort prekey is only cached, never persisted
        let tx = keystore.new_transaction().await.unwrap();
        let alice = ProteusCentral::try_new(&tx).await.unwrap();
        alice.last_resort_prekey(&tx).await.unwrap();
        let (pk_id, _) = alice.new_prekey_auto(&tx).await.unwrap();
        assert_eq!(
            pk_id, 1,
            "an uncommitted last resort prekey must not block auto prekeys"
        );
        tx.commit().await.unwrap();

        // now the last resort prekey is persisted, so it's the database query which has to skip it
        let tx = keystore.new_transaction().await.unwrap();
        let (pk_id, _) = alice.new_prekey_auto(&tx).await.unwrap();
        assert_eq!(pk_id, 2, "a persisted last resort prekey must not block auto prekeys");
        tx.commit().await.unwrap();

        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }

    /// Claiming a prekey id which is already taken fails, and fails at the call responsible.
    ///
    /// The keystore refuses the duplicate on its own, but only when the transaction is applied.
    /// This exercises the guard in front of it: the caller learns immediately, the prekey already
    /// stored under that id is left alone, and the transaction survives to commit whatever else
    /// it was carrying.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn cannot_reuse_a_prekey_id() {
        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();

        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Database::open(&path, &key).await.unwrap();
        let tx = keystore.new_transaction().await.unwrap();
        let alice = ProteusCentral::try_new(&tx).await.unwrap();

        let bundle = alice.new_prekey(1, &tx).await.unwrap();

        // taken by an id claimed earlier in this same transaction, which is only visible in the
        // transaction's buffered operations and not yet in the database
        assert!(
            alice.new_prekey(1, &tx).await.is_err(),
            "an id claimed earlier in this transaction must not be reassigned"
        );
        tx.commit().await.unwrap();

        // and taken by an id claimed in an earlier transaction, which reaches the database
        let tx = keystore.new_transaction().await.unwrap();
        assert!(
            alice.new_prekey(1, &tx).await.is_err(),
            "a persisted id must not be reassigned"
        );

        // the original prekey survived both rejected claims
        let stored = tx.get::<ProteusPrekey>(&1).await.unwrap().unwrap();
        let stored = proteus_wasm::keys::PreKey::deserialise(&stored.prekey).unwrap();
        let bundle = PreKeyBundle::deserialise(&bundle).unwrap();
        assert_eq!(
            stored.key_pair.public_key, bundle.public_key,
            "the rejected claims must have left the original prekey in place"
        );

        // and the transaction is still usable
        let (pk_id, _) = alice.new_prekey_auto(&tx).await.unwrap();
        assert_eq!(pk_id, 2, "a rejected claim must not poison the transaction");
        tx.commit().await.unwrap();

        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }
}
