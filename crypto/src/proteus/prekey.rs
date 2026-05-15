use core_crypto_keystore::{Database, traits::FetchFromDatabase as _};
use proteus_wasm::keys::PreKeyBundle;

use super::ProteusCentral;
use crate::{KeystoreError, ProteusError, Result};

impl ProteusCentral {
    /// Generates a new Proteus PreKey, stores it in the keystore and returns a serialized PreKeyBundle to be consumed
    /// externally
    pub(crate) async fn new_prekey(&self, id: u16, keystore: &Database) -> Result<Vec<u8>> {
        use proteus_wasm::keys::{PreKey, PreKeyId};

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
        keystore
            .save(keystore_prekey)
            .await
            .map_err(KeystoreError::wrap("saving keystore prekey"))?;
        Ok(bundle)
    }

    /// Generates a new Proteus Prekey, with an automatically auto-incremented ID.
    ///
    /// See [ProteusCentral::new_prekey]
    pub(crate) async fn new_prekey_auto(&self, keystore: &Database) -> Result<(u16, Vec<u8>)> {
        let id = core_crypto_keystore::entities::ProteusPrekey::get_free_id(keystore)
            .await
            .map_err(KeystoreError::wrap("getting proteus prekey by id"))?;
        Ok((id, self.new_prekey(id, keystore).await?))
    }

    /// Returns the Proteus last resort prekey ID (u16::MAX = 65535 = 0xFFFF)
    pub fn last_resort_prekey_id() -> u16 {
        proteus_wasm::keys::MAX_PREKEY_ID.value()
    }

    /// Returns the Proteus last resort prekey
    /// If it cannot be found, one will be created.
    pub(crate) async fn last_resort_prekey(&self, keystore: &Database) -> Result<Vec<u8>> {
        let last_resort = if let Some(last_resort) = keystore
            .get::<core_crypto_keystore::entities::ProteusPrekey>(&Self::last_resort_prekey_id())
            .await
            .map_err(KeystoreError::wrap("finding proteus prekey"))?
        {
            proteus_wasm::keys::PreKey::deserialise(&last_resort.prekey)
                .map_err(ProteusError::wrap("deserialising proteus prekey"))?
        } else {
            let last_resort = proteus_wasm::keys::PreKey::last_resort();

            use core_crypto_keystore::CryptoKeystoreProteus as _;
            keystore
                .proteus_store_prekey(
                    Self::last_resort_prekey_id(),
                    &last_resort
                        .serialise()
                        .map_err(ProteusError::wrap("serialising last resort prekey"))?,
                )
                .await
                .map_err(KeystoreError::wrap("storing proteus prekey"))?;

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
    use core_crypto_keystore::{ConnectionType, DatabaseKey};

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
        let mut keystore = core_crypto_keystore::Database::open(ConnectionType::Persistent(&path), &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();
        let mut alice = ProteusCentral::try_new(&keystore).await.unwrap();

        let mut bob = CryptoboxLike::init();

        let alice_prekey_bundle_ser = alice.new_prekey(1, &keystore).await.unwrap();

        bob.init_session_from_prekey_bundle(&session_id, &alice_prekey_bundle_ser);
        let message = b"Hello world!";
        let encrypted = bob.encrypt(&session_id, message);

        let (_, decrypted) = alice
            .session_from_message(&mut keystore, &session_id, &encrypted)
            .await
            .unwrap();

        assert_eq!(message, decrypted.as_slice());

        let encrypted = alice.encrypt(&mut keystore, &session_id, message).await.unwrap();
        let decrypted = bob.decrypt(&session_id, &encrypted).await;

        assert_eq!(message, decrypted.as_slice());
        keystore.commit_transaction().await.unwrap();
        keystore.wipe().await.unwrap();
        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn auto_prekeys_are_sequential() {
        use core_crypto_keystore::entities::ProteusPrekey;
        const GAP_AMOUNT: u16 = 5;
        const ID_TEST_RANGE: std::ops::RangeInclusive<u16> = 1..=30;

        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();

        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Database::open(ConnectionType::Persistent(&path), &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();
        let alice = ProteusCentral::try_new(&keystore).await.unwrap();

        for i in ID_TEST_RANGE {
            let (pk_id, pkb) = alice.new_prekey_auto(&keystore).await.unwrap();
            assert_eq!(i, pk_id);
            let prekey = proteus_wasm::keys::PreKeyBundle::deserialise(&pkb).unwrap();
            assert_eq!(prekey.prekey_id.value(), pk_id);
        }

        use rand::Rng as _;
        let mut rng = rand::thread_rng();
        let mut gap_ids: Vec<u16> = (0..GAP_AMOUNT).map(|_| rng.gen_range(ID_TEST_RANGE)).collect();
        gap_ids.sort();
        gap_ids.dedup();
        while gap_ids.len() < GAP_AMOUNT as usize {
            gap_ids.push(rng.gen_range(ID_TEST_RANGE));
            gap_ids.sort();
            gap_ids.dedup();
        }
        for gap_id in gap_ids.iter() {
            keystore.remove::<ProteusPrekey>(gap_id).await.unwrap();
        }

        gap_ids.sort();

        for gap_id in gap_ids.iter() {
            let (pk_id, pkb) = alice.new_prekey_auto(&keystore).await.unwrap();
            assert_eq!(pk_id, *gap_id);
            let prekey = proteus_wasm::keys::PreKeyBundle::deserialise(&pkb).unwrap();
            assert_eq!(prekey.prekey_id.value(), *gap_id);
        }

        let mut gap_ids: Vec<u16> = (0..GAP_AMOUNT).map(|_| rng.gen_range(ID_TEST_RANGE)).collect();
        gap_ids.sort();
        gap_ids.dedup();
        while gap_ids.len() < GAP_AMOUNT as usize {
            gap_ids.push(rng.gen_range(ID_TEST_RANGE));
            gap_ids.sort();
            gap_ids.dedup();
        }
        for gap_id in gap_ids.iter() {
            keystore.remove::<ProteusPrekey>(gap_id).await.unwrap();
        }

        let potential_range = *ID_TEST_RANGE.end()..=(*ID_TEST_RANGE.end() * 2);
        let potential_range_check = potential_range.clone();
        for _ in potential_range {
            let (pk_id, pkb) = alice.new_prekey_auto(&keystore).await.unwrap();
            assert!(gap_ids.contains(&pk_id) || potential_range_check.contains(&pk_id));
            let prekey = proteus_wasm::keys::PreKeyBundle::deserialise(&pkb).unwrap();
            assert_eq!(prekey.prekey_id.value(), pk_id);
        }
        keystore.commit_transaction().await.unwrap();
        keystore.wipe().await.unwrap();
        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }
}
