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

use crate::{prelude::ClientId, CryptoError, CryptoResult, ProteusError};
use core_crypto_keystore::{
    entities::{ProteusIdentity, ProteusSession},
    Connection as CryptoKeystore,
};
use proteus::{keys::IdentityKeyPair, session::Session};
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
    /// TODO:
    pub fn encrypt(&mut self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        Ok(self
            .session
            .encrypt(plaintext)
            .and_then(|e| e.serialise())
            .map_err(ProteusError::from)?)
    }

    /// TODO:
    pub async fn decrypt(
        &mut self,
        store: &mut core_crypto_keystore::Connection,
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let envelope = proteus::message::Envelope::deserialise(ciphertext).map_err(ProteusError::from)?;
        Ok(self
            .session
            .decrypt(store, &envelope)
            .await
            .map_err(ProteusError::from)?)
    }

    /// TODO:
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// TODO:
    pub fn fingerprint_local(&self) -> String {
        self.session.local_identity().fingerprint()
    }

    /// TODO:
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
    pub async fn try_new(client_id: ClientId, keystore: &CryptoKeystore) -> CryptoResult<Self> {
        let proteus_identity: Arc<IdentityKeyPair> = Self::load_or_create_identity(keystore, client_id.as_slice())
            .await?
            .into();

        let proteus_sessions = Self::restore_sessions(keystore, &proteus_identity).await?;

        Ok(Self {
            proteus_identity,
            proteus_sessions,
        })
    }

    /// This function will try to load a proteus Identity from our keystore; If it cannot, it will create a new one
    /// This means this function doesn't fail except in cases of deeper errors (such as in the Keystore and other crypto errors)
    async fn load_or_create_identity(keystore: &CryptoKeystore, client_id: &[u8]) -> CryptoResult<IdentityKeyPair> {
        let keypair = if let Some(identity) = keystore.find::<ProteusIdentity>(client_id).await? {
            let sk = identity.sk_raw();
            let pk = identity.pk_raw();
            // SAFETY: Byte lengths are ensured at the keystore level so this function is safe to call, despite being cursed
            unsafe { IdentityKeyPair::from_raw_key_pair(*sk, *pk) }
        } else {
            Self::create_identity(keystore).await?
        };

        Ok(keypair)
    }

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
        let prekey = proteus::keys::PreKeyBundle::deserialise(key).map_err(ProteusError::from)?;
        let proteus_session =
            Session::init_from_prekey(self.proteus_identity.clone(), prekey).map_err(ProteusError::from)?;

        let proteus_conversation = ProteusConversationSession {
            identifier: session_id.into(),
            session: proteus_session,
        };

        self.proteus_sessions.insert(session_id.into(), proteus_conversation);

        Ok(self.proteus_sessions.get_mut(session_id).unwrap())
    }

    /// Creates a new proteus Session from a recieved message
    pub async fn session_from_message(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        envelope: &[u8],
    ) -> CryptoResult<(&mut ProteusConversationSession, Vec<u8>)> {
        let message = proteus::message::Envelope::deserialise(envelope).map_err(ProteusError::from)?;
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

    /// Proteus identity keypair
    pub fn identity(&self) -> &IdentityKeyPair {
        self.proteus_identity.as_ref()
    }

    /// Proteus Public key hex-encoded fingerprint
    pub fn fingerprint(&self) -> String {
        self.identity().public_key.fingerprint()
    }

    /// Cryptobox -> CoreCrypto migration
    pub async fn cryptobox_migrate(&self, keystore: &CryptoKeystore, path: &str) -> CryptoResult<()> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "cryptobox-migrate")] {
                self.cryptobox_migrate_impl(keystore, path).await?;
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
    async fn cryptobox_migrate_impl(&self, keystore: &CryptoKeystore, path: &str) -> CryptoResult<()> {
        let root_dir = std::path::PathBuf::from(path);
        let session_dir = root_dir.join("sessions");
        let prekey_dir = root_dir.join("prekeys");

        let mut identity = if let Some(store_kp) = keystore.find::<ProteusIdentity>(&[]).await? {
            Some(unsafe { proteus::keys::IdentityKeyPair::from_raw_key_pair(*store_kp.sk_raw(), *store_kp.pk_raw()) })
        } else {
            let identity_dir = root_dir.join("identities");

            let identity = identity_dir.join("local");
            let legacy_identity = identity_dir.join("local_identity");
            // Old "local_identity" migration step
            let identity_check = if legacy_identity.exists() {
                let kp_cbor = async_fs::read(&legacy_identity).await?;
                let kp = proteus::keys::IdentityKeyPair::deserialise(&kp_cbor).map_err(ProteusError::from)?;
                Some((kp, true))
            } else if identity.exists() {
                let kp_cbor = async_fs::read(&identity).await?;
                let kp = proteus::identity::Identity::deserialise(&kp_cbor).map_err(ProteusError::from)?;
                if let proteus::identity::Identity::Sec(kp) = kp {
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
            if proteus::session::Session::deserialise(&identity, &raw_session).is_ok() {
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
            let proteus_prekey_id = proteus::keys::PreKeyId::new(prekey_file.file_name().to_string_lossy().parse()?);

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
            if proteus::keys::PreKey::deserialise(&raw_prekey).is_ok() {
                let keystore_prekey = ProteusPrekey::from_raw(proteus_prekey_id.value(), raw_prekey);
                keystore.save(keystore_prekey).await?;
            }
        }

        Ok(())
    }

    #[cfg(target_family = "wasm")]
    async fn cryptobox_migrate_impl(&self, keystore: &CryptoKeystore, path: &str) -> CryptoResult<()> {
        use core_crypto_keystore::CryptoKeystoreError;
        use rexie::{ObjectStore, Rexie, TransactionMode};
        let local_identity_key = "local_identity";
        let local_identity_store_name = "keys";
        let prekeys_store_name = "prekeys";
        let sessions_store_name = "sessions";

        // Path should be following this logic: https://github.com/wireapp/wire-web-packages/blob/main/packages/core/src/main/Account.ts#L645
        let db = Rexie::builder(path)
            .add_object_store(ObjectStore::new(local_identity_store_name))
            .add_object_store(ObjectStore::new(prekeys_store_name))
            .add_object_store(ObjectStore::new(sessions_store_name))
            .build()
            .await
            .map_err(CryptoKeystoreError::from)?;

        let transaction = db
            .transaction(
                &[local_identity_store_name, prekeys_store_name, sessions_store_name],
                TransactionMode::ReadOnly,
            )
            .map_err(CryptoKeystoreError::from)?;

        let identity_store = transaction
            .store(local_identity_store_name)
            .map_err(CryptoKeystoreError::from)?;

        let mut proteus_identity = if let Some(store_kp) = keystore.find::<ProteusIdentity>(&[]).await? {
            Some(unsafe { proteus::keys::IdentityKeyPair::from_raw_key_pair(*store_kp.sk_raw(), *store_kp.pk_raw()) })
        } else if let Some(kp_cbor) = identity_store
            .get(&local_identity_key.into())
            .await
            .map_err(CryptoKeystoreError::from)?
        {
            let kp_cbor = kp_cbor.as_string().unwrap();
            Some(proteus::keys::IdentityKeyPair::deserialise(kp_cbor.as_bytes()).map_err(ProteusError::from)?)
        } else {
            None
        };

        let proteus_identity = if let Some(identity) = proteus_identity.take() {
            identity
        } else {
            Self::create_identity(keystore).await?
        };

        let sessions_store = transaction
            .store(sessions_store_name)
            .map_err(CryptoKeystoreError::from)?;

        let sessions = sessions_store
            .get_all(None, None, None, None)
            .await
            .map_err(CryptoKeystoreError::from)?;

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
            if proteus::session::Session::deserialise(&proteus_identity, &session_cbor_bytes).is_ok() {
                let keystore_session = ProteusSession {
                    id: session_id,
                    session: session_cbor_bytes,
                };

                keystore.save(keystore_session).await?;
            }
        }

        use core_crypto_keystore::entities::ProteusPrekey;
        let prekeys_store = transaction
            .store(prekeys_store_name)
            .map_err(CryptoKeystoreError::from)?;

        let prekeys = prekeys_store
            .get_all(None, None, None, None)
            .await
            .map_err(CryptoKeystoreError::from)?;

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
            if proteus::keys::PreKey::deserialise(&raw_prekey_cbor).is_ok() {
                let keystore_prekey = ProteusPrekey::from_raw(prekey_id, raw_prekey_cbor);
                keystore.save(keystore_prekey).await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proteus::keys::PreKey;
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
        let uuid = uuid::Uuid::new_v4();
        let (path, db_file) = crate::test_utils::tmp_db_file();
        let keystore = core_crypto_keystore::Connection::open_with_key(&path, "test")
            .await
            .unwrap();
        let central = ProteusCentral::try_new(uuid.into_bytes().to_vec().into(), &keystore)
            .await
            .unwrap();
        let identity = (*central.proteus_identity).clone();

        let keystore = core_crypto_keystore::Connection::open_with_key(path, "test")
            .await
            .unwrap();

        let central = ProteusCentral::try_new(ClientId::from(uuid.into_bytes().to_vec()), &keystore)
            .await
            .unwrap();

        assert_eq!(identity, *central.proteus_identity);

        keystore.wipe().await.unwrap();
        drop(db_file);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn can_talk_with_proteus() {
        let uuid = uuid::Uuid::new_v4();
        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let (path, db_file) = crate::test_utils::tmp_db_file();

        let mut keystore = core_crypto_keystore::Connection::open_with_key(path, "test")
            .await
            .unwrap();
        let mut alice = ProteusCentral::try_new(uuid.into_bytes().to_vec().into(), &keystore)
            .await
            .unwrap();
        let bob = proteus::keys::IdentityKeyPair::new();
        let mut bob_store = TestStore::default();
        let prekey = proteus::keys::PreKey::new(proteus::keys::PreKeyId::new(1));
        bob_store.prekeys.push(prekey.clone());
        let bob_pk_bundle = proteus::keys::PreKeyBundle::new(bob.public_key.clone(), &prekey);

        alice
            .session_from_prekey(&session_id, &bob_pk_bundle.serialise().unwrap())
            .await
            .unwrap();

        let message = b"Hello world";

        let encrypted = alice.encrypt(&session_id, message).unwrap();
        let envelope = proteus::message::Envelope::deserialise(&encrypted).unwrap();

        let (mut bob_session, decrypted) = proteus::session::Session::init_from_message(bob, &mut bob_store, &envelope)
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
}
