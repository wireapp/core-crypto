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

use crate::{CryptoError, CryptoResult, ProteusError};
use core_crypto_keystore::{
    entities::{ProteusIdentity, ProteusSession},
    Connection as CryptoKeystore,
};
use proteus_wasm::{
    keys::{IdentityKeyPair, PreKeyBundle},
    message::Envelope,
    session::Session,
};
use std::{collections::HashMap, sync::Arc};

/// Proteus session IDs, it seems it's basically a string
pub type SessionIdentifier = String;

/// Proteus Session wrapper, that contains the identifier and the associated proteus Session
#[derive(Debug)]
pub struct ProteusConversationSession {
    identifier: SessionIdentifier,
    session: Session<Arc<IdentityKeyPair>>,
}

impl ProteusConversationSession {
    /// Encrypts a message for this Proteus session
    pub fn encrypt(&mut self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        Ok(self
            .session
            .encrypt(plaintext)
            .and_then(|e| e.serialise())
            .map_err(ProteusError::from)?)
    }

    /// Decrypts a message for this Proteus session
    pub async fn decrypt(
        &mut self,
        store: &mut core_crypto_keystore::Connection,
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let envelope = Envelope::deserialise(ciphertext).map_err(ProteusError::from)?;
        Ok(self
            .session
            .decrypt(store, &envelope)
            .await
            .map_err(ProteusError::from)?)
    }

    /// Returns the session identifier
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Returns the public key fingerprint of the local identity (= self identity)
    pub fn fingerprint_local(&self) -> String {
        self.session.local_identity().fingerprint()
    }

    /// Returns the public key fingerprint of the remote identity (= client you're communicating with)
    pub fn fingerprint_remote(&self) -> String {
        self.session.remote_identity().fingerprint()
    }
}

/// Proteus counterpart of [crate::mls::MlsCentral]
/// The big difference is that [ProteusCentral] doesn't *own* its own keystore but must borrow it from the outside.
/// Whether it's exclusively for this struct's purposes or it's shared with our main struct, [MlsCentral]
#[derive(Debug)]
pub struct ProteusCentral {
    proteus_identity: Arc<IdentityKeyPair>,
    proteus_sessions: HashMap<SessionIdentifier, ProteusConversationSession>,
}

impl ProteusCentral {
    /// Initializes the [ProteusCentral]
    pub async fn try_new(keystore: &CryptoKeystore) -> CryptoResult<Self> {
        let proteus_identity: Arc<IdentityKeyPair> = Arc::new(Self::load_or_create_identity(keystore).await?);

        let proteus_sessions = Self::restore_sessions(keystore, &proteus_identity).await?;

        Ok(Self {
            proteus_identity,
            proteus_sessions,
        })
    }

    /// This function will try to load a proteus Identity from our keystore; If it cannot, it will create a new one
    /// This means this function doesn't fail except in cases of deeper errors (such as in the Keystore and other crypto errors)
    async fn load_or_create_identity(keystore: &CryptoKeystore) -> CryptoResult<IdentityKeyPair> {
        let keypair = if let Some(identity) = keystore.find::<ProteusIdentity>(&[]).await? {
            let sk = identity.sk_raw();
            let pk = identity.pk_raw();
            // SAFETY: Byte lengths are ensured at the keystore level so this function is safe to call, despite being cursed
            let kp = unsafe { IdentityKeyPair::from_raw_key_pair(*sk, *pk) };

            kp
        } else {
            Self::create_identity(keystore).await?
        };

        Ok(keypair)
    }

    /// Internal function to create and save a new Proteus Identity
    async fn create_identity(keystore: &CryptoKeystore) -> CryptoResult<IdentityKeyPair> {
        let kp = IdentityKeyPair::new();
        let pk_fingerprint = kp.public_key.public_key.fingerprint();
        let pk = hex::decode(pk_fingerprint)?;

        let ks_identity = ProteusIdentity {
            sk: kp.secret_key.to_bytes_extended().into(),
            pk,
        };
        keystore.save(ks_identity).await?;

        Ok(kp)
    }

    /// Restores the saved sessions in memory. This is performed automatically on init
    async fn restore_sessions(
        keystore: &core_crypto_keystore::Connection,
        identity: &Arc<IdentityKeyPair>,
    ) -> CryptoResult<HashMap<SessionIdentifier, ProteusConversationSession>> {
        let mut proteus_sessions = HashMap::new();
        for session in keystore
            .find_all::<ProteusSession>(Default::default())
            .await?
            .into_iter()
        {
            let proteus_session =
                Session::deserialise(identity.clone(), &session.session).map_err(ProteusError::from)?;

            let identifier = session.id.clone();

            let proteus_conversation = ProteusConversationSession {
                identifier: identifier.clone(),
                session: proteus_session,
            };

            proteus_sessions.insert(identifier, proteus_conversation);
        }

        Ok(proteus_sessions)
    }

    /// Creates a new session from a prekey
    pub async fn session_from_prekey(
        &mut self,
        session_id: &str,
        key: &[u8],
    ) -> CryptoResult<&mut ProteusConversationSession> {
        let prekey = PreKeyBundle::deserialise(key).map_err(ProteusError::from)?;
        let proteus_session =
            Session::init_from_prekey(self.proteus_identity.clone(), prekey).map_err(ProteusError::from)?;

        let proteus_conversation = ProteusConversationSession {
            identifier: session_id.into(),
            session: proteus_session,
        };

        self.proteus_sessions.insert(session_id.into(), proteus_conversation);

        Ok(self.proteus_sessions.get_mut(session_id).unwrap())
    }

    /// Creates a new proteus Session from a received message
    pub async fn session_from_message(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        envelope: &[u8],
    ) -> CryptoResult<(&mut ProteusConversationSession, Vec<u8>)> {
        let message = Envelope::deserialise(envelope).map_err(ProteusError::from)?;
        let (session, payload) = Session::init_from_message(self.proteus_identity.clone(), keystore, &message)
            .await
            .map_err(ProteusError::from)?;

        let proteus_conversation = ProteusConversationSession {
            identifier: session_id.into(),
            session,
        };

        self.proteus_sessions.insert(session_id.into(), proteus_conversation);

        Ok((self.proteus_sessions.get_mut(session_id).unwrap(), payload))
    }

    /// Persists a session in store
    pub async fn session_save(&self, keystore: &CryptoKeystore, session_id: &str) -> CryptoResult<()> {
        if let Some(session) = self.proteus_sessions.get(session_id) {
            let db_session = ProteusSession {
                id: session_id.into(),
                session: session.session.serialise().map_err(ProteusError::from)?,
            };
            keystore.save(db_session).await?;
        }

        Ok(())
    }

    /// Deletes a session in the store
    pub async fn session_delete(&mut self, keystore: &CryptoKeystore, session_id: &str) -> CryptoResult<()> {
        if keystore.remove::<ProteusSession, _>(session_id).await.is_ok() {
            let _ = self.proteus_sessions.remove(session_id);
        }
        Ok(())
    }

    /// Session accessor
    pub fn session(&mut self, session_id: &str) -> Option<&mut ProteusConversationSession> {
        self.proteus_sessions.get_mut(session_id)
    }

    /// Decrypt a proteus message for an already existing session
    /// Note: This cannot be used for handshake messages, see [ProteusCentral::session_from_message]
    pub async fn decrypt(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if let Some(session) = self.proteus_sessions.get_mut(session_id) {
            session.decrypt(keystore, ciphertext).await
        } else {
            Err(CryptoError::ConversationNotFound(session_id.as_bytes().into()))
        }
    }

    /// Encrypt a message for a session
    pub fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if let Some(session) = self.session(session_id) {
            session.encrypt(plaintext)
        } else {
            Err(CryptoError::ConversationNotFound(session_id.as_bytes().into()))
        }
    }

    /// Encrypts a message for a list of sessions
    /// This is mainly used for conversations with multiple clients, this allows to minimize FFI roundtrips
    pub fn encrypt_batched(
        &mut self,
        sessions: &[impl AsRef<str>],
        plaintext: &[u8],
    ) -> CryptoResult<HashMap<String, Vec<u8>>> {
        let mut acc = HashMap::new();
        for session_id in sessions {
            if let Some(session) = self.session(session_id.as_ref()) {
                acc.insert(session.identifier.clone(), session.encrypt(plaintext)?);
            }
        }
        Ok(acc)
    }

    /// Generates a new Proteus PreKey, stores it in the keystore and returns a serialized PreKeyBundle to be consumed externally
    pub async fn new_prekey(&self, id: u16, keystore: &CryptoKeystore) -> CryptoResult<Vec<u8>> {
        use proteus_wasm::keys::{PreKey, PreKeyId};

        let prekey_id = PreKeyId::new(id);
        let prekey = PreKey::new(prekey_id);
        let keystore_prekey = core_crypto_keystore::entities::ProteusPrekey::from_raw(
            id,
            prekey.serialise().map_err(ProteusError::from)?,
        );
        let bundle = PreKeyBundle::new(self.proteus_identity.as_ref().public_key.clone(), &prekey);
        let bundle = bundle.serialise().map_err(ProteusError::from)?;
        keystore.save(keystore_prekey).await?;
        Ok(bundle)
    }

    /// Proteus identity keypair
    pub fn identity(&self) -> &IdentityKeyPair {
        self.proteus_identity.as_ref()
    }

    /// Proteus Public key hex-encoded fingerprint
    pub fn fingerprint(&self) -> String {
        self.proteus_identity.as_ref().public_key.fingerprint()
    }

    /// Cryptobox -> CoreCrypto migration
    #[cfg_attr(not(feature = "cryptobox-migrate"), allow(unused_variables))]
    pub async fn cryptobox_migrate(keystore: &CryptoKeystore, path: &str) -> CryptoResult<()> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "cryptobox-migrate")] {
                Self::cryptobox_migrate_impl(keystore, path).await?;
                Ok(())
            } else {
                Err(CryptoError::ProteusSupportNotEnabled("cryptobox-migrate".into()))
            }
        }
    }
}

#[cfg(feature = "cryptobox-migrate")]
#[allow(dead_code)]
impl ProteusCentral {
    #[cfg(not(target_family = "wasm"))]
    async fn cryptobox_migrate_impl(keystore: &CryptoKeystore, path: &str) -> CryptoResult<()> {
        let root_dir = std::path::PathBuf::from(path);
        let session_dir = root_dir.join("sessions");
        let prekey_dir = root_dir.join("prekeys");

        let mut identity = if let Some(store_kp) = keystore.find::<ProteusIdentity>(&[]).await? {
            Some(unsafe { IdentityKeyPair::from_raw_key_pair(*store_kp.sk_raw(), *store_kp.pk_raw()) })
        } else {
            let identity_dir = root_dir.join("identities");

            let identity = identity_dir.join("local");
            let legacy_identity = identity_dir.join("local_identity");
            // Old "local_identity" migration step
            let identity_check = if legacy_identity.exists() {
                let kp_cbor = async_fs::read(&legacy_identity).await?;
                let kp = IdentityKeyPair::deserialise(&kp_cbor).map_err(ProteusError::from)?;
                Some((kp, true))
            } else if identity.exists() {
                let kp_cbor = async_fs::read(&identity).await?;
                let kp = proteus_wasm::identity::Identity::deserialise(&kp_cbor).map_err(ProteusError::from)?;
                if let proteus_wasm::identity::Identity::Sec(kp) = kp {
                    Some((kp.into_owned(), false))
                } else {
                    None
                }
            } else {
                None
            };

            if let Some((kp, delete)) = identity_check {
                let pk_fingerprint = kp.public_key.public_key.fingerprint();
                let pk = hex::decode(pk_fingerprint)?;

                let ks_identity = ProteusIdentity {
                    sk: kp.secret_key.to_bytes_extended().into(),
                    pk,
                };
                keystore.save(ks_identity).await?;
                if delete {
                    async_fs::remove_file(legacy_identity).await?;
                }

                Some(kp)
            } else {
                None
            }
        };

        let identity = if let Some(identity) = identity.take() {
            identity
        } else {
            Self::create_identity(keystore).await?
        };

        use futures_lite::stream::StreamExt as _;
        // Session migration
        let mut session_entries = async_fs::read_dir(session_dir).await?;
        while let Some(session_file) = session_entries.try_next().await? {
            // The name of the file is the session id
            let proteus_session_id: String = session_file.file_name().to_string_lossy().to_string();

            // If the session is already in store, skip ahead
            if keystore
                .find::<ProteusSession>(proteus_session_id.as_bytes())
                .await?
                .is_some()
            {
                continue;
            }

            let raw_session = async_fs::read(session_file.path()).await?;
            if Session::deserialise(&identity, &raw_session).is_ok() {
                let keystore_session = ProteusSession {
                    id: proteus_session_id,
                    session: raw_session,
                };

                keystore.save(keystore_session).await?;
            }
        }

        // Prekey migration
        use core_crypto_keystore::entities::ProteusPrekey;
        let mut prekey_entries = async_fs::read_dir(prekey_dir).await?;
        while let Some(prekey_file) = prekey_entries.try_next().await? {
            // The name of the file is the prekey id, so we parse it to get the ID
            let proteus_prekey_id =
                proteus_wasm::keys::PreKeyId::new(prekey_file.file_name().to_string_lossy().parse()?);

            // Check if the prekey ID is already existing
            if keystore
                .find::<ProteusPrekey>(&proteus_prekey_id.value().to_le_bytes())
                .await?
                .is_some()
            {
                continue;
            }

            let raw_prekey = async_fs::read(prekey_file.path()).await?;
            // Integrity check to see if the PreKey is actually correct
            if proteus_wasm::keys::PreKey::deserialise(&raw_prekey).is_ok() {
                let keystore_prekey = ProteusPrekey::from_raw(proteus_prekey_id.value(), raw_prekey);
                keystore.save(keystore_prekey).await?;
            }
        }

        Ok(())
    }

    #[cfg(target_family = "wasm")]
    async fn cryptobox_migrate_impl(keystore: &CryptoKeystore, path: &str) -> CryptoResult<()> {
        use rexie::{Rexie, TransactionMode};

        use crate::CryptoboxMigrationError;
        let local_identity_key = "local_identity";
        let local_identity_store_name = "keys";
        let prekeys_store_name = "prekeys";
        let sessions_store_name = "sessions";

        // Path should be following this logic: https://github.com/wireapp/wire-web-packages/blob/main/packages/core/src/main/Account.ts#L645
        let db = Rexie::builder(path)
            .build()
            .await
            .map_err(CryptoboxMigrationError::from)?;

        let store_names = db.store_names();

        // No identity - no migration
        if !store_names.contains(&local_identity_store_name.to_string()) {
            return Ok(());
        }

        let mut proteus_identity = if let Some(store_kp) = keystore.find::<ProteusIdentity>(&[]).await? {
            Some(unsafe {
                proteus_wasm::keys::IdentityKeyPair::from_raw_key_pair(*store_kp.sk_raw(), *store_kp.pk_raw())
            })
        } else {
            let transaction = db
                .transaction(&[local_identity_store_name], TransactionMode::ReadOnly)
                .map_err(CryptoboxMigrationError::from)?;

            let identity_store = transaction
                .store(local_identity_store_name)
                .map_err(CryptoboxMigrationError::from)?;

            if let Some(cryptobox_js_value) = identity_store
                .get(&local_identity_key.into())
                .await
                .map_err(CryptoboxMigrationError::from)?
            {
                let js_value: serde_json::map::Map<String, serde_json::Value> =
                    serde_wasm_bindgen::from_value(cryptobox_js_value).map_err(CryptoboxMigrationError::from)?;

                let kp_js_value =
                    serde_wasm_bindgen::to_value(&js_value["serialised"]).map_err(CryptoboxMigrationError::from)?;

                let kp_cbor: Vec<u8> =
                    serde_wasm_bindgen::from_value(kp_js_value).map_err(CryptoboxMigrationError::from)?;

                let kp = proteus_wasm::keys::IdentityKeyPair::deserialise(&kp_cbor).map_err(ProteusError::from)?;

                let pk_fingerprint = kp.public_key.public_key.fingerprint();
                let pk = hex::decode(pk_fingerprint)?;

                let ks_identity = ProteusIdentity {
                    sk: kp.secret_key.to_bytes_extended().into(),
                    pk,
                };
                keystore.save(ks_identity).await?;

                Some(kp)
            } else {
                None
            }
        };

        let proteus_identity = if let Some(identity) = proteus_identity.take() {
            identity
        } else {
            Self::create_identity(keystore).await?
        };

        if store_names.contains(&sessions_store_name.to_string()) {
            let transaction = db
                .transaction(&[sessions_store_name], TransactionMode::ReadOnly)
                .map_err(CryptoboxMigrationError::from)?;

            let sessions_store = transaction
                .store(sessions_store_name)
                .map_err(CryptoboxMigrationError::from)?;

            let sessions = sessions_store
                .get_all(None, None, None, None)
                .await
                .map_err(CryptoboxMigrationError::from)?;

            for (session_id, session_cbor) in sessions
                .into_iter()
                .map(|(k, v)| (k.as_string().unwrap(), v.as_string().unwrap()))
            {
                // If the session is already in store, skip ahead
                if keystore.find::<ProteusSession>(session_id.as_bytes()).await?.is_some() {
                    continue;
                }

                let session_cbor_bytes = session_cbor.into_bytes();

                // Integrity check
                if proteus_wasm::session::Session::deserialise(&proteus_identity, &session_cbor_bytes).is_ok() {
                    let keystore_session = ProteusSession {
                        id: session_id,
                        session: session_cbor_bytes,
                    };

                    keystore.save(keystore_session).await?;
                }
            }
        }

        if store_names.contains(&prekeys_store_name.to_string()) {
            use core_crypto_keystore::entities::ProteusPrekey;

            let transaction = db
                .transaction(&[prekeys_store_name], TransactionMode::ReadOnly)
                .map_err(CryptoboxMigrationError::from)?;

            let prekeys_store = transaction
                .store(prekeys_store_name)
                .map_err(CryptoboxMigrationError::from)?;

            let prekeys = prekeys_store
                .get_all(None, None, None, None)
                .await
                .map_err(CryptoboxMigrationError::from)?;

            for (prekey_id, prekey_cbor) in prekeys
                .into_iter()
                .map(|(id, cbor)| (id.as_string().unwrap(), cbor.as_string().unwrap()))
            {
                let prekey_id: u16 = prekey_id.parse()?;
                let raw_prekey_cbor = prekey_cbor.into_bytes();

                // Check if the prekey ID is already existing
                if keystore
                    .find::<ProteusPrekey>(&prekey_id.to_le_bytes())
                    .await?
                    .is_some()
                {
                    continue;
                }

                // Integrity check to see if the PreKey is actually correct
                if proteus_wasm::keys::PreKey::deserialise(&raw_prekey_cbor).is_ok() {
                    let keystore_prekey = ProteusPrekey::from_raw(prekey_id, raw_prekey_cbor);
                    keystore.save(keystore_prekey).await?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use proteus_traits::PreKeyStore;
    use proteus_wasm::keys::PreKey;
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[derive(Debug, Default)]
    struct TestStore {
        prekeys: Vec<PreKey>,
    }

    #[async_trait::async_trait(?Send)]
    impl proteus_traits::PreKeyStore for TestStore {
        type Error = ();

        async fn prekey(&mut self, id: proteus_traits::RawPreKeyId) -> Result<Option<proteus_traits::RawPreKey>, ()> {
            if let Some(prekey) = self.prekeys.iter().find(|k| k.key_id.value() == id) {
                Ok(Some(prekey.serialise().unwrap()))
            } else {
                Ok(None)
            }
        }

        async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), ()> {
            self.prekeys
                .iter()
                .position(|k| k.key_id.value() == id)
                .map(|ix| self.prekeys.swap_remove(ix));
            Ok(())
        }
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn can_init() {
        let (path, db_file) = crate::test_utils::tmp_db_file();
        let keystore = core_crypto_keystore::Connection::open_with_key(&path, "test")
            .await
            .unwrap();
        let central = ProteusCentral::try_new(&keystore).await.unwrap();
        let identity = (*central.proteus_identity).clone();

        let keystore = core_crypto_keystore::Connection::open_with_key(path, "test")
            .await
            .unwrap();

        let central = ProteusCentral::try_new(&keystore).await.unwrap();

        assert_eq!(identity, *central.proteus_identity);

        keystore.wipe().await.unwrap();
        drop(db_file);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn can_talk_with_proteus() {
        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let (path, db_file) = crate::test_utils::tmp_db_file();

        let mut keystore = core_crypto_keystore::Connection::open_with_key(path, "test")
            .await
            .unwrap();
        let mut alice = ProteusCentral::try_new(&keystore).await.unwrap();
        let bob = proteus_wasm::keys::IdentityKeyPair::new();
        let mut bob_store = TestStore::default();
        let prekey = proteus_wasm::keys::PreKey::new(proteus_wasm::keys::PreKeyId::new(1));
        bob_store.prekeys.push(prekey.clone());
        let bob_pk_bundle = proteus_wasm::keys::PreKeyBundle::new(bob.public_key.clone(), &prekey);

        alice
            .session_from_prekey(&session_id, &bob_pk_bundle.serialise().unwrap())
            .await
            .unwrap();

        let message = b"Hello world";

        let encrypted = alice.encrypt(&session_id, message).unwrap();
        let envelope = proteus_wasm::message::Envelope::deserialise(&encrypted).unwrap();

        let (mut bob_session, decrypted) =
            proteus_wasm::session::Session::init_from_message(bob, &mut bob_store, &envelope)
                .await
                .unwrap();

        assert_eq!(decrypted, message);

        let encrypted = bob_session.encrypt(message).unwrap();

        let decrypted = alice
            .decrypt(&mut keystore, &session_id, &encrypted.serialise().unwrap())
            .await
            .unwrap();

        assert_eq!(decrypted, message);

        keystore.wipe().await.unwrap();
        drop(db_file);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn can_produce_proteus_consumed_prekeys() {
        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let (path, db_file) = crate::test_utils::tmp_db_file();

        let mut keystore = core_crypto_keystore::Connection::open_with_key(path, "test")
            .await
            .unwrap();
        let mut alice = ProteusCentral::try_new(&keystore).await.unwrap();
        let bob = proteus_wasm::keys::IdentityKeyPair::new();
        let mut bob_store = TestStore::default();

        let alice_prekey_bundle_ser = alice.new_prekey(1, &keystore).await.unwrap();
        let alice_prekey_bundle = proteus_wasm::keys::PreKeyBundle::deserialise(&alice_prekey_bundle_ser).unwrap();
        let mut bob_session =
            proteus_wasm::session::Session::init_from_prekey::<()>(&bob, alice_prekey_bundle).unwrap();
        let message = b"Hello world!";
        let encrypted = bob_session.encrypt(message).unwrap().serialise().unwrap();

        let (_, decrypted) = alice
            .session_from_message(&mut keystore, &session_id, &encrypted)
            .await
            .unwrap();

        assert_eq!(message, decrypted.as_slice());

        let encrypted = alice.encrypt(&session_id, message).unwrap();
        let decrypted = bob_session
            .decrypt(
                &mut bob_store,
                &proteus_wasm::message::Envelope::deserialise(&encrypted).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(message, decrypted.as_slice());

        keystore.wipe().await.unwrap();
        drop(db_file);
    }

    #[cfg(all(feature = "cryptobox-migrate", not(target_family = "wasm")))]
    #[async_std::test]
    async fn can_import_cryptobox() {
        let cryptobox_folder = tempfile::tempdir().unwrap();
        let alice = cryptobox::CBox::file_open(cryptobox_folder.path()).unwrap();
        let alice_fingerprint = alice.fingerprint();

        let bob = proteus_wasm::keys::IdentityKeyPair::new();
        let mut bob_store = TestStore::default();
        let prekey = proteus_wasm::keys::PreKey::new(proteus_wasm::keys::PreKeyId::new(1));
        bob_store.prekeys.push(prekey.clone());
        let bob_pk_bundle = proteus_wasm::keys::PreKeyBundle::new(bob.public_key.clone(), &prekey);

        let alice_pk = alice.new_prekey(proteus::keys::PreKeyId::new(1)).unwrap();
        let session_id = "test";

        let mut alice_session = alice
            .session_from_prekey(session_id.into(), &bob_pk_bundle.serialise().unwrap())
            .unwrap();
        let message = b"Hello world!";
        let alice_msg_envelope =
            proteus_wasm::message::Envelope::deserialise(&alice_session.encrypt(message).unwrap()).unwrap();

        let (mut bob_session, decrypted) =
            proteus_wasm::session::Session::init_from_message(bob, &mut bob_store, &alice_msg_envelope)
                .await
                .unwrap();

        assert_eq!(decrypted, message);

        alice.session_save(&mut alice_session).unwrap();

        drop(alice);

        let keystore_dir = tempfile::tempdir().unwrap();
        let keystore_file = keystore_dir.path().join("keystore");

        let mut keystore =
            core_crypto_keystore::Connection::open_with_key(keystore_file.as_os_str().to_string_lossy(), "test")
                .await
                .unwrap();

        ProteusCentral::cryptobox_migrate(&keystore, &cryptobox_folder.path().to_string_lossy())
            .await
            .unwrap();

        let mut proteus_central = ProteusCentral::try_new(&keystore).await.unwrap();

        // Identity check
        assert_eq!(proteus_central.fingerprint(), alice_fingerprint);

        // Session integrity check
        let session = proteus_central.session(session_id).unwrap();
        assert_eq!(
            session.session.local_identity().fingerprint(),
            alice_session.fingerprint_local()
        );
        assert_eq!(
            session.session.remote_identity().fingerprint(),
            alice_session.fingerprint_remote()
        );

        // Prekey integrity check
        let keystore_pk = keystore.prekey(1).await.unwrap().unwrap();
        let keystore_pk = proteus_wasm::keys::PreKey::deserialise(&keystore_pk).unwrap();
        assert_eq!(alice_pk.prekey_id.value(), keystore_pk.key_id.value());
        assert_eq!(
            alice_pk.public_key.fingerprint(),
            keystore_pk.key_pair.public_key.fingerprint()
        );

        // Make sure ProteusCentral can still keep communicating with bob
        let encrypted = proteus_central.encrypt(session_id, &message[..]).unwrap();
        let decrypted = bob_session
            .decrypt(
                &mut bob_store,
                &proteus_wasm::message::Envelope::deserialise(&encrypted).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(&decrypted, &message[..]);

        keystore.wipe().await.unwrap();
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))] {
            // use wasm_bindgen::prelude::*;
            const CRYPTOBOX_JS_DBNAME: &str = "cryptobox-migrate-test";
            // FIXME: This is not working because wasm-bindgen-test-runner is behaving weird with inline_js stuff (aka not working basically)
    //         #[allow(dead_code)]
    //         const CRYPTOBOX_JS_SETUP: &str = r#"export async function run_cryptobox() {
    //     const { Cryptobox } = await import("https://unpkg.com/@wireapp/cryptobox@latest/src/index.js");
    //     const { IndexedDBEngine } = await import("https://unpkg.com/@wireapp/store-engine-dexie@latest/src/index.js");
    //     const store = new IndexedDBEngine();
    //     await store.init("cryptobox-migrate-test", true);
    //     const cryptobox = new Cryptobox(store);
    //     await cryptobox.create();
    //     window.cryptobox = cryptobox;
    //     return cryptobox.getIdentity().fingerprint();
    // }"#;
    //         #[wasm_bindgen(inline_js = CRYPTOBOX_JS_SETUP)]
    //         extern "C" {
    //             fn run_cryptobox() -> js_sys::Promise;
    //         }

            // ! So instead we emulate how cryptobox-js works
            // Returns Promise<JsString>
            fn run_cryptobox() -> js_sys::Promise {
                wasm_bindgen_futures::future_to_promise(async move {
                    use rexie::{Rexie, ObjectStore, TransactionMode};
                    use proteus_wasm::keys::IdentityKeyPair;
                    use js_sys::JsString;

                    // Delete the maybe past database to make sure we start fresh
                    Rexie::builder(CRYPTOBOX_JS_DBNAME)
                        .delete()
                        .await?;

                    let kp = IdentityKeyPair::new();
                    let rexie = Rexie::builder(CRYPTOBOX_JS_DBNAME)
                        .version(1)
                        .add_object_store(ObjectStore::new("keys").auto_increment(false))
                        .add_object_store(ObjectStore::new("prekeys").auto_increment(false))
                        .add_object_store(ObjectStore::new("sessions").auto_increment(false))
                        .build()
                        .await?;

                    let transaction = rexie.transaction(&["keys"], TransactionMode::ReadWrite)?;
                    let store = transaction.store("keys")?;
                    let json = serde_json::json!({
                        "created": 0,
                        "id": "local_identity",
                        "serialised": kp.serialise().unwrap(),
                        "version": "1.0"
                    });
                    let js_value = serde_wasm_bindgen::to_value(&json)?;

                    store.add(&js_value, Some(&JsString::from("local_identity").into())).await?;

                    Ok(JsString::from(kp.public_key.fingerprint().as_str()).into())
                })
            }

            #[wasm_bindgen_test]
            async fn can_import_cryptobox() {
                let fingerprint = wasm_bindgen_futures::JsFuture::from(run_cryptobox()).await.unwrap().as_string().unwrap();
                let keystore = core_crypto_keystore::Connection::open_with_key(&format!("{CRYPTOBOX_JS_DBNAME}-imported"), "test").await.unwrap();
                ProteusCentral::cryptobox_migrate(&keystore, CRYPTOBOX_JS_DBNAME).await.unwrap();

                let proteus_central = ProteusCentral::try_new(&keystore).await.unwrap();

                assert_eq!(fingerprint, proteus_central.identity().public_key.fingerprint());
            }
        }
    }
}
