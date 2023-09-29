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

use crate::{
    group_store::{GroupStore, GroupStoreValue},
    CoreCrypto, CryptoError, CryptoResult, ProteusError,
};
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
    pub(crate) identifier: SessionIdentifier,
    pub(crate) session: Session<Arc<IdentityKeyPair>>,
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

impl CoreCrypto {
    /// Initializes the proteus client
    pub async fn proteus_init(&mut self) -> CryptoResult<()> {
        // ? Cannot inline the statement or the borrow checker gets really confused about the type of `keystore`
        let keystore = self.mls.mls_backend.borrow_keystore();
        let proteus_client = ProteusCentral::try_new(keystore).await?;

        // ? Make sure the last resort prekey exists
        let _ = proteus_client.last_resort_prekey(keystore).await?;

        self.proteus = Some(proteus_client);
        Ok(())
    }

    /// Reloads the sessions from the key store
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or it will do nothing
    pub async fn proteus_reload_sessions(&mut self) -> CryptoResult<()> {
        if let Some(proteus) = self.proteus.as_mut() {
            let keystore = self.mls.mls_backend.borrow_keystore();
            proteus.reload_sessions(keystore).await
        } else {
            Ok(())
        }
    }

    /// Creates a proteus session from a prekey
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_from_prekey(
        &mut self,
        session_id: &str,
        prekey: &[u8],
    ) -> CryptoResult<GroupStoreValue<ProteusConversationSession>> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let session = proteus.session_from_prekey(session_id, prekey).await?;
        let keystore = self.mls.mls_backend.borrow_keystore_mut();
        ProteusCentral::session_save_by_ref(keystore, session.clone()).await?;

        Ok(session)
    }

    /// Creates a proteus session from a Proteus message envelope
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_from_message(
        &mut self,
        session_id: &str,
        envelope: &[u8],
    ) -> CryptoResult<(GroupStoreValue<ProteusConversationSession>, Vec<u8>)> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore_mut();
        let (session, message) = proteus.session_from_message(keystore, session_id, envelope).await?;
        ProteusCentral::session_save_by_ref(keystore, session.clone()).await?;

        Ok((session, message))
    }

    /// Saves a proteus session in the keystore
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_save(&mut self, session_id: &str) -> CryptoResult<()> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore_mut();
        proteus.session_save(keystore, session_id).await
    }

    /// Deletes a proteus session from the keystore
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_delete(&mut self, session_id: &str) -> CryptoResult<()> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore();
        proteus.session_delete(keystore, session_id).await
    }

    /// Proteus session accessor
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session(
        &mut self,
        session_id: &str,
    ) -> CryptoResult<Option<GroupStoreValue<ProteusConversationSession>>> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore_mut();
        proteus.session(session_id, keystore).await
    }

    /// Proteus session exists
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_exists(&mut self, session_id: &str) -> CryptoResult<bool> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore_mut();
        Ok(proteus.session_exists(session_id, keystore).await)
    }

    /// Decrypts a proteus message envelope
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore_mut();
        proteus.decrypt(keystore, session_id, ciphertext).await
    }

    /// Encrypts proteus message for a given session ID
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore_mut();
        proteus.encrypt(keystore, session_id, plaintext).await
    }

    /// Encrypts a proteus message for several sessions ID. This is more efficient than other methods as the calls are batched.
    /// This also reduces the rountrips when crossing over the FFI
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_encrypt_batched(
        &mut self,
        sessions: &[impl AsRef<str>],
        plaintext: &[u8],
    ) -> CryptoResult<std::collections::HashMap<String, Vec<u8>>> {
        let proteus = self.proteus.as_mut().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore_mut();
        proteus.encrypt_batched(keystore, sessions, plaintext).await
    }

    /// Creates a new Proteus prekey and returns the CBOR-serialized version of the prekey bundle
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> CryptoResult<Vec<u8>> {
        let proteus = self.proteus.as_ref().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore();
        proteus.new_prekey(prekey_id, keystore).await
    }

    /// Creates a new Proteus prekey with an automatically incremented ID and returns the CBOR-serialized version of the prekey bundle
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_new_prekey_auto(&self) -> CryptoResult<(u16, Vec<u8>)> {
        let proteus = self.proteus.as_ref().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore();
        proteus.new_prekey_auto(keystore).await
    }

    /// Returns the last resort prekey
    pub async fn proteus_last_resort_prekey(&self) -> CryptoResult<Vec<u8>> {
        let proteus = self.proteus.as_ref().ok_or(CryptoError::ProteusNotInitialized)?;
        let keystore = self.mls.mls_backend.borrow_keystore();

        proteus.last_resort_prekey(keystore).await
    }

    /// Returns the proteus last resort prekey id (u16::MAX = 65535)
    pub fn proteus_last_resort_prekey_id() -> u16 {
        ProteusCentral::last_resort_prekey_id()
    }

    /// Returns the proteus identity keypair
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub fn proteus_identity(&self) -> CryptoResult<&proteus_wasm::keys::IdentityKeyPair> {
        let proteus = self.proteus.as_ref().ok_or(CryptoError::ProteusNotInitialized)?;
        Ok(proteus.identity())
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub fn proteus_fingerprint(&self) -> CryptoResult<String> {
        let proteus = self.proteus.as_ref().ok_or(CryptoError::ProteusNotInitialized)?;
        Ok(proteus.fingerprint())
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_fingerprint_local(&mut self, session_id: &str) -> CryptoResult<String> {
        if let Some(proteus) = &mut self.proteus {
            let keystore = self.mls.mls_backend.borrow_keystore_mut();
            proteus.fingerprint_local(session_id, keystore).await
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_fingerprint_remote(&mut self, session_id: &str) -> CryptoResult<String> {
        if let Some(proteus) = &mut self.proteus {
            let keystore = self.mls.mls_backend.borrow_keystore_mut();
            proteus.fingerprint_remote(session_id, keystore).await
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Migrates an existing Cryptobox data store (whether a folder or an IndexedDB database) located at `path` to the keystore.
    ///
    ///The client can then be initialized with [CoreCrypto::proteus_init]
    pub async fn proteus_cryptobox_migrate(&self, path: &str) -> CryptoResult<()> {
        let keystore = self.mls.mls_backend.borrow_keystore();
        ProteusCentral::cryptobox_migrate(keystore, path).await
    }
}

/// Proteus counterpart of [crate::mls::MlsCentral]
/// The big difference is that [ProteusCentral] doesn't *own* its own keystore but must borrow it from the outside.
/// Whether it's exclusively for this struct's purposes or it's shared with our main struct, [crate::mls::MlsCentral]
#[derive(Debug)]
pub struct ProteusCentral {
    proteus_identity: Arc<IdentityKeyPair>,
    proteus_sessions: GroupStore<ProteusConversationSession>,
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

    /// Restore proteus sessions from disk
    pub async fn reload_sessions(&mut self, keystore: &CryptoKeystore) -> CryptoResult<()> {
        self.proteus_sessions = Self::restore_sessions(keystore, &self.proteus_identity).await?;
        Ok(())
    }

    /// This function will try to load a proteus Identity from our keystore; If it cannot, it will create a new one
    /// This means this function doesn't fail except in cases of deeper errors (such as in the Keystore and other crypto errors)
    async fn load_or_create_identity(keystore: &CryptoKeystore) -> CryptoResult<IdentityKeyPair> {
        let keypair = if let Some(identity) = keystore.find::<ProteusIdentity>(&[]).await? {
            let sk = identity.sk_raw();
            let pk = identity.pk_raw();
            // SAFETY: Byte lengths are ensured at the keystore level so this function is safe to call, despite being cursed

            unsafe { IdentityKeyPair::from_raw_key_pair(*sk, *pk) }
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
            sk: kp.secret_key.as_slice().into(),
            pk,
        };
        keystore.save(ks_identity).await?;

        Ok(kp)
    }

    /// Restores the saved sessions in memory. This is performed automatically on init
    async fn restore_sessions(
        keystore: &core_crypto_keystore::Connection,
        identity: &Arc<IdentityKeyPair>,
    ) -> CryptoResult<GroupStore<ProteusConversationSession>> {
        let mut proteus_sessions = GroupStore::new_with_limit(crate::group_store::ITEM_LIMIT * 2);
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

            if proteus_sessions
                .try_insert(identifier.into_bytes(), proteus_conversation)
                .is_err()
            {
                break;
            }
        }

        Ok(proteus_sessions)
    }

    /// Creates a new session from a prekey
    pub async fn session_from_prekey(
        &mut self,
        session_id: &str,
        key: &[u8],
    ) -> CryptoResult<GroupStoreValue<ProteusConversationSession>> {
        let prekey = PreKeyBundle::deserialise(key).map_err(ProteusError::from)?;
        let proteus_session =
            Session::init_from_prekey(self.proteus_identity.clone(), prekey).map_err(ProteusError::from)?;

        let proteus_conversation = ProteusConversationSession {
            identifier: session_id.into(),
            session: proteus_session,
        };

        self.proteus_sessions.insert(session_id.into(), proteus_conversation);

        Ok(self.proteus_sessions.get(session_id.as_bytes()).unwrap().clone())
    }

    /// Creates a new proteus Session from a received message
    pub async fn session_from_message(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        envelope: &[u8],
    ) -> CryptoResult<(GroupStoreValue<ProteusConversationSession>, Vec<u8>)> {
        let message = Envelope::deserialise(envelope).map_err(ProteusError::from)?;
        let (session, payload) = Session::init_from_message(self.proteus_identity.clone(), keystore, &message)
            .await
            .map_err(ProteusError::from)?;

        let proteus_conversation = ProteusConversationSession {
            identifier: session_id.into(),
            session,
        };

        self.proteus_sessions.insert(session_id.into(), proteus_conversation);

        Ok((
            self.proteus_sessions.get(session_id.as_bytes()).unwrap().clone(),
            payload,
        ))
    }

    /// Persists a session in store
    ///
    /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
    pub async fn session_save(&mut self, keystore: &mut CryptoKeystore, session_id: &str) -> CryptoResult<()> {
        if let Some(session) = self
            .proteus_sessions
            .get_fetch(session_id.as_bytes(), keystore, Some(self.proteus_identity.clone()))
            .await?
        {
            Self::session_save_by_ref(keystore, session).await?;
        }

        Ok(())
    }

    async fn session_save_by_ref(
        keystore: &CryptoKeystore,
        session: GroupStoreValue<ProteusConversationSession>,
    ) -> CryptoResult<()> {
        let session = session.read().await;
        let db_session = ProteusSession {
            id: session.identifier().to_string(),
            session: session.session.serialise().map_err(ProteusError::from)?,
        };
        keystore.save(db_session).await?;
        Ok(())
    }

    /// Deletes a session in the store
    pub async fn session_delete(&mut self, keystore: &CryptoKeystore, session_id: &str) -> CryptoResult<()> {
        if keystore.remove::<ProteusSession, _>(session_id).await.is_ok() {
            let _ = self.proteus_sessions.remove(session_id.as_bytes());
        }
        Ok(())
    }

    /// Session accessor
    pub async fn session(
        &mut self,
        session_id: &str,
        keystore: &mut CryptoKeystore,
    ) -> CryptoResult<Option<GroupStoreValue<ProteusConversationSession>>> {
        self.proteus_sessions
            .get_fetch(session_id.as_bytes(), keystore, Some(self.proteus_identity.clone()))
            .await
    }

    /// Session exists
    pub async fn session_exists(&mut self, session_id: &str, keystore: &mut CryptoKeystore) -> bool {
        self.session(session_id, keystore).await.ok().flatten().is_some()
    }

    /// Decrypt a proteus message for an already existing session
    /// Note: This cannot be used for handshake messages, see [ProteusCentral::session_from_message]
    pub async fn decrypt(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if let Some(session) = self
            .proteus_sessions
            .get_fetch(session_id.as_bytes(), keystore, Some(self.proteus_identity.clone()))
            .await?
        {
            let plaintext = session.write().await.decrypt(keystore, ciphertext).await?;
            ProteusCentral::session_save_by_ref(keystore, session).await?;

            Ok(plaintext)
        } else {
            Err(CryptoError::ConversationNotFound(session_id.as_bytes().into()))
        }
    }

    /// Encrypt a message for a session
    pub async fn encrypt(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if let Some(session) = self.session(session_id, keystore).await? {
            let ciphertext = session.write().await.encrypt(plaintext)?;
            ProteusCentral::session_save_by_ref(keystore, session).await?;

            Ok(ciphertext)
        } else {
            Err(CryptoError::ConversationNotFound(session_id.as_bytes().into()))
        }
    }

    /// Encrypts a message for a list of sessions
    /// This is mainly used for conversations with multiple clients, this allows to minimize FFI roundtrips
    pub async fn encrypt_batched(
        &mut self,
        keystore: &mut CryptoKeystore,
        sessions: &[impl AsRef<str>],
        plaintext: &[u8],
    ) -> CryptoResult<HashMap<String, Vec<u8>>> {
        let mut acc = HashMap::new();
        for session_id in sessions {
            if let Some(session) = self.session(session_id.as_ref(), keystore).await? {
                let mut session_w = session.write().await;
                acc.insert(session_w.identifier.clone(), session_w.encrypt(plaintext)?);
                drop(session_w);

                ProteusCentral::session_save_by_ref(keystore, session).await?;
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

    /// Generates a new Proteus Prekey, with an automatically auto-incremented ID.
    ///
    /// See [ProteusCentral::new_prekey]
    pub async fn new_prekey_auto(&self, keystore: &CryptoKeystore) -> CryptoResult<(u16, Vec<u8>)> {
        let id = core_crypto_keystore::entities::ProteusPrekey::get_free_id(keystore).await?;
        Ok((id, self.new_prekey(id, keystore).await?))
    }

    /// Returns the Proteus last resort prekey ID (u16::MAX = 65535 = 0xFFFF)
    pub fn last_resort_prekey_id() -> u16 {
        proteus_wasm::keys::MAX_PREKEY_ID.value()
    }

    /// Returns the Proteus last resort prekey
    /// If it cannot be found, one will be created.
    pub async fn last_resort_prekey(&self, keystore: &CryptoKeystore) -> CryptoResult<Vec<u8>> {
        let last_resort = if let Some(last_resort) = keystore
            .find::<core_crypto_keystore::entities::ProteusPrekey>(Self::last_resort_prekey_id().to_le_bytes())
            .await?
        {
            proteus_wasm::keys::PreKey::deserialise(&last_resort.prekey).map_err(ProteusError::from)?
        } else {
            let last_resort = proteus_wasm::keys::PreKey::last_resort();

            use core_crypto_keystore::CryptoKeystoreProteus as _;
            keystore
                .proteus_store_prekey(
                    Self::last_resort_prekey_id(),
                    &last_resort.serialise().map_err(ProteusError::from)?,
                )
                .await?;

            last_resort
        };

        let bundle = PreKeyBundle::new(self.proteus_identity.as_ref().public_key.clone(), &last_resort);
        let bundle = bundle.serialise().map_err(ProteusError::from)?;

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

    /// Proteus Session local hex-encoded fingerprint
    ///
    /// # Errors
    /// When the session is not found
    pub async fn fingerprint_local(&mut self, session_id: &str, keystore: &mut CryptoKeystore) -> CryptoResult<String> {
        if let Some(session) = self.session(session_id, keystore).await? {
            Ok(session.read().await.fingerprint_local())
        } else {
            Err(CryptoError::ConversationNotFound(session_id.as_bytes().into()))
        }
    }

    /// Proteus Session remote hex-encoded fingerprint
    ///
    /// # Errors
    /// When the session is not found
    pub async fn fingerprint_remote(
        &mut self,
        session_id: &str,
        keystore: &mut CryptoKeystore,
    ) -> CryptoResult<String> {
        if let Some(session) = self.session(session_id, keystore).await? {
            Ok(session.read().await.fingerprint_remote())
        } else {
            Err(CryptoError::ConversationNotFound(session_id.as_bytes().into()))
        }
    }

    /// Hex-encoded fingerprint of the given prekey
    ///
    /// # Errors
    /// If the prekey cannot be deserialized
    pub fn fingerprint_prekeybundle(prekey: &[u8]) -> CryptoResult<String> {
        let prekey = PreKeyBundle::deserialise(prekey).map_err(ProteusError::from)?;
        Ok(prekey.identity_key.fingerprint())
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

        if !root_dir.exists() {
            return Err(crate::CryptoboxMigrationError::ProvidedPathDoesNotExist(path.into()).into());
        }

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
                let pk = kp.public_key.public_key.as_slice().into();

                let ks_identity = ProteusIdentity {
                    sk: kp.secret_key.as_slice().into(),
                    pk,
                };

                keystore.save(ks_identity).await?;

                if delete && legacy_identity.exists() {
                    async_fs::remove_file(legacy_identity).await?;
                }

                Some(kp)
            } else {
                None
            }
        };

        let Some(identity) = identity.take() else {
            return Err(crate::CryptoboxMigrationError::IdentityNotFound(path.into()).into());
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
            // Session integrity check
            let Ok(_) = Session::deserialise(&identity, &raw_session) else {
                continue;
            };

            let keystore_session = ProteusSession {
                id: proteus_session_id,
                session: raw_session,
            };

            keystore.save(keystore_session).await?;
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
    fn get_cbor_bytes_from_map(map: serde_json::map::Map<String, serde_json::Value>) -> CryptoResult<Vec<u8>> {
        use crate::CryptoboxMigrationError;

        let Some(js_value) = map.get("serialised") else {
            return Err(CryptoboxMigrationError::MissingKeyInValue("serialised".to_string()).into());
        };

        let Some(b64_value) = js_value.as_str() else {
            return Err(CryptoboxMigrationError::WrongValueType("string".to_string()).into());
        };

        use base64::Engine as _;
        let cbor_bytes = base64::prelude::BASE64_STANDARD
            .decode(b64_value)
            .map_err(CryptoboxMigrationError::from)?;
        Ok(cbor_bytes)
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

        let expected_stores = &[prekeys_store_name, sessions_store_name, local_identity_store_name];

        if !expected_stores
            .iter()
            .map(|s| s.to_string())
            .all(|s| store_names.contains(&s))
        {
            return Err(crate::CryptoboxMigrationError::ProvidedPathDoesNotExist(path.into()).into());
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

                let kp_cbor = Self::get_cbor_bytes_from_map(js_value)?;

                let kp = proteus_wasm::keys::IdentityKeyPair::deserialise(&kp_cbor).map_err(ProteusError::from)?;

                let pk_fingerprint = kp.public_key.public_key.fingerprint();
                let pk = hex::decode(pk_fingerprint)?;

                let ks_identity = ProteusIdentity {
                    sk: kp.secret_key.as_slice().into(),
                    pk,
                };
                keystore.save(ks_identity).await?;

                Some(kp)
            } else {
                None
            }
        };

        let Some(proteus_identity) = proteus_identity.take() else {
            return Err(crate::CryptoboxMigrationError::IdentityNotFound(path.into()).into());
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

            for (session_id, session_js_value) in sessions.into_iter().map(|(k, v)| (k.as_string().unwrap(), v)) {
                // If the session is already in store, skip ahead
                if keystore.find::<ProteusSession>(session_id.as_bytes()).await?.is_some() {
                    continue;
                }

                let js_value: serde_json::map::Map<String, serde_json::Value> =
                    serde_wasm_bindgen::from_value(session_js_value).map_err(CryptoboxMigrationError::from)?;

                let session_cbor_bytes = Self::get_cbor_bytes_from_map(js_value)?;

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

            for (prekey_id, prekey_js_value) in prekeys
                .into_iter()
                .map(|(id, prekey_js_value)| (id.as_string().unwrap(), prekey_js_value))
            {
                let prekey_id: u16 = prekey_id.parse()?;

                // Check if the prekey ID is already existing
                if keystore
                    .find::<ProteusPrekey>(&prekey_id.to_le_bytes())
                    .await?
                    .is_some()
                {
                    continue;
                }

                let js_value: serde_json::map::Map<String, serde_json::Value> =
                    serde_wasm_bindgen::from_value(prekey_js_value).map_err(CryptoboxMigrationError::from)?;

                let raw_prekey_cbor = Self::get_cbor_bytes_from_map(js_value)?;

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
    use crate::{
        prelude::{CertificateBundle, MlsCentral, MlsCentralConfiguration},
        test_utils::{proteus_utils::*, *},
    };

    use crate::prelude::{ClientIdentifier, MlsCredentialType};
    use proteus_traits::PreKeyStore;
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn cc_can_init(case: TestCase) {
        let (path, db_file) = tmp_db_file();
        let client_id = "alice".into();
        let cfg = MlsCentralConfiguration::try_new(
            path,
            "test".to_string(),
            Some(client_id),
            vec![case.ciphersuite()],
            None,
        )
        .unwrap();
        let mut cc: CoreCrypto = MlsCentral::try_new(cfg).await.unwrap().into();
        assert!(cc.proteus_init().await.is_ok());
        assert!(cc.proteus_new_prekey(1).await.is_ok());
        drop(db_file);
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn cc_can_2_phase_init(case: TestCase) {
        let (path, db_file) = tmp_db_file();
        // we are deferring MLS initialization here, not passing a MLS 'client_id' yet
        let cfg =
            MlsCentralConfiguration::try_new(path, "test".to_string(), None, vec![case.ciphersuite()], None).unwrap();
        let mut cc: CoreCrypto = MlsCentral::try_new(cfg).await.unwrap().into();
        assert!(cc.proteus_init().await.is_ok());
        // proteus is initialized, prekeys can be generated
        assert!(cc.proteus_new_prekey(1).await.is_ok());
        // 👇 and so a unique 'client_id' can be fetched from wire-server
        let client_id = "alice".into();
        let identifier = match case.credential_type {
            MlsCredentialType::Basic => ClientIdentifier::Basic(client_id),
            MlsCredentialType::X509 => CertificateBundle::rand_identifier(&[case.signature_scheme()], client_id),
        };
        cc.mls_init(identifier, vec![case.ciphersuite()]).await.unwrap();
        // expect MLS to work
        assert_eq!(
            cc.get_or_create_client_keypackages(case.ciphersuite(), case.credential_type, 2)
                .await
                .unwrap()
                .len(),
            2
        );
        drop(db_file);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn can_init() {
        let (path, db_file) = tmp_db_file();
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
        let (path, db_file) = tmp_db_file();

        let mut keystore = core_crypto_keystore::Connection::open_with_key(path, "test")
            .await
            .unwrap();
        let mut alice = ProteusCentral::try_new(&keystore).await.unwrap();

        let mut bob = CryptoboxLike::init();
        let bob_pk_bundle = bob.new_prekey();

        alice
            .session_from_prekey(&session_id, &bob_pk_bundle.serialise().unwrap())
            .await
            .unwrap();

        let message = b"Hello world";

        let encrypted = alice.encrypt(&mut keystore, &session_id, message).await.unwrap();
        let decrypted = bob.decrypt(&session_id, &encrypted).await;
        assert_eq!(decrypted, message);

        let encrypted = bob.encrypt(&session_id, message);
        let decrypted = alice.decrypt(&mut keystore, &session_id, &encrypted).await.unwrap();
        assert_eq!(decrypted, message);

        keystore.wipe().await.unwrap();
        drop(db_file);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn can_produce_proteus_consumed_prekeys() {
        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let (path, db_file) = tmp_db_file();

        let mut keystore = core_crypto_keystore::Connection::open_with_key(path, "test")
            .await
            .unwrap();
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

        keystore.wipe().await.unwrap();
        drop(db_file);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn auto_prekeys_are_sequential() {
        use core_crypto_keystore::entities::ProteusPrekey;
        const GAP_AMOUNT: u16 = 5;
        const ID_TEST_RANGE: std::ops::RangeInclusive<u16> = 1..=30;
        let (path, db_file) = tmp_db_file();

        let keystore = core_crypto_keystore::Connection::open_with_key(path, "test")
            .await
            .unwrap();
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
            keystore.remove::<ProteusPrekey, _>(gap_id.to_le_bytes()).await.unwrap();
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
            keystore.remove::<ProteusPrekey, _>(gap_id.to_le_bytes()).await.unwrap();
        }

        let potential_range = *ID_TEST_RANGE.end()..=(*ID_TEST_RANGE.end() * 2);
        let potential_range_check = potential_range.clone();
        for _ in potential_range {
            let (pk_id, pkb) = alice.new_prekey_auto(&keystore).await.unwrap();
            assert!(gap_ids.contains(&pk_id) || potential_range_check.contains(&pk_id));
            let prekey = proteus_wasm::keys::PreKeyBundle::deserialise(&pkb).unwrap();
            assert_eq!(prekey.prekey_id.value(), pk_id);
        }

        keystore.wipe().await.unwrap();
        drop(db_file);
    }

    #[cfg(all(feature = "cryptobox-migrate", not(target_family = "wasm")))]
    #[async_std::test]
    async fn can_import_cryptobox() {
        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();

        let cryptobox_folder = tempfile::tempdir().unwrap();
        let alice = cryptobox::CBox::file_open(cryptobox_folder.path()).unwrap();
        let alice_fingerprint = alice.fingerprint();

        let mut bob = CryptoboxLike::init();
        let bob_pk_bundle = bob.new_prekey();

        let alice_pk_id = proteus::keys::PreKeyId::new(1u16);
        let alice_pk = alice.new_prekey(alice_pk_id).unwrap();

        let mut alice_session = alice
            .session_from_prekey(session_id.clone(), &bob_pk_bundle.serialise().unwrap())
            .unwrap();

        let message = b"Hello world!";

        let alice_msg_envelope = alice_session.encrypt(message).unwrap();
        let decrypted = bob.decrypt(&session_id, &alice_msg_envelope).await;
        assert_eq!(decrypted, message);

        alice.session_save(&mut alice_session).unwrap();

        let encrypted = bob.encrypt(&session_id, &message[..]);
        let decrypted = alice_session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, message);

        alice.session_save(&mut alice_session).unwrap();

        drop(alice);

        let keystore_dir = tempfile::tempdir().unwrap();
        let keystore_file = keystore_dir.path().join("keystore");

        let mut keystore =
            core_crypto_keystore::Connection::open_with_key(keystore_file.as_os_str().to_string_lossy(), "test")
                .await
                .unwrap();

        let Err(crate::CryptoError::CryptoboxMigrationError(crate::CryptoboxMigrationError::ProvidedPathDoesNotExist(
            _,
        ))) = ProteusCentral::cryptobox_migrate(&keystore, "invalid path").await
        else {
            panic!("ProteusCentral::cryptobox_migrate did not throw an error on invalid path");
        };

        ProteusCentral::cryptobox_migrate(&keystore, &cryptobox_folder.path().to_string_lossy())
            .await
            .unwrap();

        let mut proteus_central = ProteusCentral::try_new(&keystore).await.unwrap();

        // Identity check
        assert_eq!(proteus_central.fingerprint(), alice_fingerprint);

        // Session integrity check
        let alice_new_session_lock = proteus_central
            .session(&session_id, &mut keystore)
            .await
            .unwrap()
            .unwrap();
        let alice_new_session = alice_new_session_lock.read().await;
        assert_eq!(
            alice_new_session.session.local_identity().fingerprint(),
            alice_session.fingerprint_local()
        );
        assert_eq!(
            alice_new_session.session.remote_identity().fingerprint(),
            alice_session.fingerprint_remote()
        );

        drop(alice_new_session);
        drop(alice_new_session_lock);

        // Prekey integrity check
        let keystore_pk = keystore.prekey(1).await.unwrap().unwrap();
        let keystore_pk = proteus_wasm::keys::PreKey::deserialise(&keystore_pk).unwrap();
        assert_eq!(alice_pk.prekey_id.value(), keystore_pk.key_id.value());
        assert_eq!(
            alice_pk.public_key.fingerprint(),
            keystore_pk.key_pair.public_key.fingerprint()
        );

        // Make sure ProteusCentral can still keep communicating with bob
        let encrypted = proteus_central
            .encrypt(&mut keystore, &session_id, &message[..])
            .await
            .unwrap();
        let decrypted = bob.decrypt(&session_id, &encrypted).await;

        assert_eq!(&decrypted, &message[..]);

        // CL-110 assertion
        // Happens when a migrated client ratchets just after migration. It does not happen when ratchet is not required
        // Having alice(A), bob(B) and migration(M), you can reproduce this behaviour with `[A->B][B->A] M [A->B][B->A]`
        // However you won't reproduce it like this because migrated alice does not ratchet `[A->B][B->A] M [B->A][A->B]`
        let encrypted = bob.encrypt(&session_id, &message[..]);
        let decrypted = proteus_central
            .decrypt(&mut keystore, &session_id, &encrypted)
            .await
            .unwrap();
        assert_eq!(&decrypted, &message[..]);

        proteus_central.session_save(&mut keystore, &session_id).await.unwrap();

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
            fn run_cryptobox(alice: CryptoboxLike) -> js_sys::Promise {
                wasm_bindgen_futures::future_to_promise(async move {
                    use rexie::{Rexie, ObjectStore, TransactionMode};
                    use wasm_bindgen::JsValue;

                    // Delete the maybe past database to make sure we start fresh
                    Rexie::builder(CRYPTOBOX_JS_DBNAME)
                        .delete()
                        .await?;

                    let rexie = Rexie::builder(CRYPTOBOX_JS_DBNAME)
                        .version(1)
                        .add_object_store(ObjectStore::new("keys").auto_increment(false))
                        .add_object_store(ObjectStore::new("prekeys").auto_increment(false))
                        .add_object_store(ObjectStore::new("sessions").auto_increment(false))
                        .build()
                        .await?;

                    // Add identity key
                    let transaction = rexie.transaction(&["keys"], TransactionMode::ReadWrite)?;
                    let store = transaction.store("keys")?;

                    use base64::Engine as _;
                    let json = serde_json::json!({
                        "created": 0,
                        "id": "local_identity",
                        "serialised": base64::prelude::BASE64_STANDARD.encode(alice.identity.serialise().unwrap()),
                        "version": "1.0"
                    });
                    let js_value = serde_wasm_bindgen::to_value(&json)?;

                    store.add(&js_value, Some(&JsValue::from_str("local_identity"))).await?;

                    // Add prekeys
                    let transaction = rexie.transaction(&["prekeys"], TransactionMode::ReadWrite)?;
                    let store = transaction.store("prekeys")?;
                    for prekey in alice.prekeys.0.into_iter() {
                        let id = prekey.key_id.value().to_string();
                        let json = serde_json::json!({
                            "created": 0,
                            "id": &id,
                            "serialised": base64::prelude::BASE64_STANDARD.encode(prekey.serialise().unwrap()),
                            "version": "1.0"
                        });
                        let js_value = serde_wasm_bindgen::to_value(&json)?;
                        store.add(&js_value, Some(&JsValue::from_str(&id))).await?;
                    }

                    // Add sessions
                    let transaction = rexie.transaction(&["sessions"], TransactionMode::ReadWrite)?;
                    let store = transaction.store("sessions")?;
                    for (session_id, session) in alice.sessions.into_iter() {
                        let json = serde_json::json!({
                            "created": 0,
                            "id": session_id,
                            "serialised": base64::prelude::BASE64_STANDARD.encode(session.serialise().unwrap()),
                            "version": "1.0"
                        });

                        let js_value = serde_wasm_bindgen::to_value(&json)?;
                        store.add(&js_value, Some(&JsValue::from_str(&session_id))).await?;
                    }

                    Ok(JsValue::UNDEFINED)
                })
            }

            #[wasm_bindgen_test]
            async fn can_import_cryptobox() {
                let session_id = uuid::Uuid::new_v4().hyphenated().to_string();

                let mut alice = CryptoboxLike::init();
                let alice_fingerprint = alice.fingerprint();
                const PREKEY_COUNT: usize = 10;
                let prekey_iter_range = 0..PREKEY_COUNT;
                // Save prekey bundles for later to check if they're the same after migration
                let prekey_bundles: Vec<proteus_wasm::keys::PreKeyBundle> = prekey_iter_range.clone().map(|_| alice.new_prekey()).collect();

                // Ensure alice and bob can communicate before migration
                let mut bob = CryptoboxLike::init();
                let bob_pk_bundle = bob.new_prekey();
                let message = b"Hello world!";

                alice.init_session_from_prekey_bundle(&session_id, &bob_pk_bundle.serialise().unwrap());
                let alice_to_bob_message = alice.encrypt(&session_id, message);
                let decrypted = bob.decrypt(&session_id, &alice_to_bob_message).await;
                assert_eq!(&message[..], decrypted.as_slice());

                let bob_to_alice_message = bob.encrypt(&session_id, message);
                let decrypted = alice.decrypt(&session_id, &bob_to_alice_message).await;
                assert_eq!(&message[..], decrypted.as_slice());

                let alice_session = alice.session(&session_id);
                let alice_session_fingerprint_local = alice_session.local_identity().fingerprint();
                let alice_session_fingerprint_remote = alice_session.remote_identity().fingerprint();

                let _ = wasm_bindgen_futures::JsFuture::from(run_cryptobox(alice)).await.unwrap();
                let mut keystore = core_crypto_keystore::Connection::open_with_key(&format!("{CRYPTOBOX_JS_DBNAME}-imported"), "test").await.unwrap();
                let Err(crate::CryptoError::CryptoboxMigrationError(crate::CryptoboxMigrationError::ProvidedPathDoesNotExist(_))) = ProteusCentral::cryptobox_migrate(&keystore, "invalid path").await else {
                    panic!("ProteusCentral::cryptobox_migrate did not throw an error on invalid path");
                };

                ProteusCentral::cryptobox_migrate(&keystore, CRYPTOBOX_JS_DBNAME).await.unwrap();

                let mut proteus_central = ProteusCentral::try_new(&keystore).await.unwrap();

                // Identity check
                assert_eq!(proteus_central.fingerprint(), alice_fingerprint);

                // Session integrity check
                let alice_new_session_lock = proteus_central
                    .session(&session_id, &mut keystore)
                    .await
                    .unwrap()
                    .unwrap();
                let alice_new_session = alice_new_session_lock.read().await;
                assert_eq!(
                    alice_new_session.session.local_identity().fingerprint(),
                    alice_session_fingerprint_local
                );
                assert_eq!(
                    alice_new_session.session.remote_identity().fingerprint(),
                    alice_session_fingerprint_remote
                );

                drop(alice_new_session);
                drop(alice_new_session_lock);

                // Prekey integrity check
                for i in prekey_iter_range {
                    let prekey_id = (i + 1) as u16;
                    let keystore_pk = keystore.prekey(prekey_id).await.unwrap().unwrap();
                    let keystore_pk = proteus_wasm::keys::PreKey::deserialise(&keystore_pk).unwrap();
                    let alice_pk = &prekey_bundles[i];

                    assert_eq!(alice_pk.prekey_id.value(), keystore_pk.key_id.value());
                    assert_eq!(
                        alice_pk.public_key.fingerprint(),
                        keystore_pk.key_pair.public_key.fingerprint()
                    );
                }


                // Make sure ProteusCentral can still keep communicating with bob
                let encrypted = proteus_central.encrypt(&mut keystore, &session_id, &message[..]).await.unwrap();
                let decrypted = bob.decrypt(&session_id, &encrypted).await;

                assert_eq!(&decrypted, &message[..]);

                // CL-110 assertion
                let encrypted = bob.encrypt(&session_id, &message[..]);
                let decrypted = proteus_central
                    .decrypt(&mut keystore, &session_id, &encrypted)
                    .await
                    .unwrap();
                assert_eq!(&decrypted, &message[..]);

                keystore.wipe().await.unwrap();
            }
        }
    }
}
