use crate::{
    CoreCrypto, Error, KeystoreError, LeafError, ProteusError, Result,
    group_store::{GroupStore, GroupStoreEntity, GroupStoreValue},
};
use core_crypto_keystore::{
    Connection as CryptoKeystore,
    connection::FetchFromDatabase,
    entities::{ProteusIdentity, ProteusSession},
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
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.session
            .encrypt(plaintext)
            .and_then(|e| e.serialise())
            .map_err(ProteusError::wrap("encrypting message for proteus session"))
            .map_err(Into::into)
    }

    /// Decrypts a message for this Proteus session
    pub async fn decrypt(
        &mut self,
        store: &mut core_crypto_keystore::Connection,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let envelope = Envelope::deserialise(ciphertext).map_err(ProteusError::wrap("deserializing envelope"))?;
        self.session
            .decrypt(store, &envelope)
            .await
            .map_err(ProteusError::wrap("decrypting message for proteus session"))
            .map_err(Into::into)
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

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl GroupStoreEntity for ProteusConversationSession {
    type RawStoreValue = core_crypto_keystore::entities::ProteusSession;
    type IdentityType = Arc<proteus_wasm::keys::IdentityKeyPair>;

    async fn fetch_from_id(
        id: &[u8],
        identity: Option<Self::IdentityType>,
        keystore: &impl FetchFromDatabase,
    ) -> crate::Result<Option<Self>> {
        let result = keystore
            .find::<Self::RawStoreValue>(id)
            .await
            .map_err(KeystoreError::wrap("finding raw group store entity by id"))?;
        let Some(store_value) = result else {
            return Ok(None);
        };

        let Some(identity) = identity else {
            return Err(crate::Error::ProteusNotInitialized);
        };

        let session = proteus_wasm::session::Session::deserialise(identity, &store_value.session)
            .map_err(ProteusError::wrap("deserializing session"))?;

        Ok(Some(Self {
            identifier: store_value.id.clone(),
            session,
        }))
    }
}

impl CoreCrypto {
    /// Proteus session accessor
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_session(
        &self,
        session_id: &str,
    ) -> Result<Option<GroupStoreValue<ProteusConversationSession>>> {
        let mut mutex = self.proteus.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.mls.crypto_provider.keystore();
        proteus.session(session_id, &keystore).await
    }

    /// Proteus session exists
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_session_exists(&self, session_id: &str) -> Result<bool> {
        let mut mutex = self.proteus.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.mls.crypto_provider.keystore();
        Ok(proteus.session_exists(session_id, &keystore).await)
    }

    /// Returns the proteus last resort prekey id (u16::MAX = 65535)
    pub fn proteus_last_resort_prekey_id() -> u16 {
        ProteusCentral::last_resort_prekey_id()
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_fingerprint(&self) -> Result<String> {
        let mutex = self.proteus.lock().await;
        let proteus = mutex.as_ref().ok_or(Error::ProteusNotInitialized)?;
        Ok(proteus.fingerprint())
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_fingerprint_local(&self, session_id: &str) -> Result<String> {
        let mut mutex = self.proteus.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.mls.crypto_provider.keystore();
        proteus.fingerprint_local(session_id, &keystore).await
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_fingerprint_remote(&self, session_id: &str) -> Result<String> {
        let mut mutex = self.proteus.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        let keystore = self.mls.crypto_provider.keystore();
        proteus.fingerprint_remote(session_id, &keystore).await
    }
}

/// Proteus counterpart of [crate::mls::session::Session]
///
/// The big difference is that [ProteusCentral] doesn't *own* its own keystore but must borrow it from the outside.
/// Whether it's exclusively for this struct's purposes or it's shared with our main struct, [crate::mls::session::Session]
#[derive(Debug)]
pub struct ProteusCentral {
    proteus_identity: Arc<IdentityKeyPair>,
    proteus_sessions: GroupStore<ProteusConversationSession>,
}

impl ProteusCentral {
    /// Initializes the [ProteusCentral]
    pub async fn try_new(keystore: &CryptoKeystore) -> Result<Self> {
        let proteus_identity: Arc<IdentityKeyPair> = Arc::new(Self::load_or_create_identity(keystore).await?);
        let proteus_sessions = Self::restore_sessions(keystore, &proteus_identity).await?;

        Ok(Self {
            proteus_identity,
            proteus_sessions,
        })
    }

    /// Restore proteus sessions from disk
    pub(crate) async fn reload_sessions(&mut self, keystore: &CryptoKeystore) -> Result<()> {
        self.proteus_sessions = Self::restore_sessions(keystore, &self.proteus_identity).await?;
        Ok(())
    }

    /// This function will try to load a proteus Identity from our keystore; If it cannot, it will create a new one
    /// This means this function doesn't fail except in cases of deeper errors (such as in the Keystore and other crypto errors)
    async fn load_or_create_identity(keystore: &CryptoKeystore) -> Result<IdentityKeyPair> {
        let Some(identity) = keystore
            .find::<ProteusIdentity>(&[])
            .await
            .map_err(KeystoreError::wrap("finding proteus identity"))?
        else {
            return Self::create_identity(keystore).await;
        };

        let sk = identity.sk_raw();
        let pk = identity.pk_raw();

        // SAFETY: Byte lengths are ensured at the keystore level so this function is safe to call, despite being cursed
        IdentityKeyPair::from_raw_key_pair(*sk, *pk)
            .map_err(ProteusError::wrap("constructing identity keypair"))
            .map_err(Into::into)
    }

    /// Internal function to create and save a new Proteus Identity
    async fn create_identity(keystore: &CryptoKeystore) -> Result<IdentityKeyPair> {
        let kp = IdentityKeyPair::new();
        let pk = kp.public_key.public_key.as_slice().to_vec();

        let ks_identity = ProteusIdentity {
            sk: kp.secret_key.to_keypair_bytes().into(),
            pk,
        };
        keystore
            .save(ks_identity)
            .await
            .map_err(KeystoreError::wrap("saving new proteus identity"))?;

        Ok(kp)
    }

    /// Restores the saved sessions in memory. This is performed automatically on init
    async fn restore_sessions(
        keystore: &core_crypto_keystore::Connection,
        identity: &Arc<IdentityKeyPair>,
    ) -> Result<GroupStore<ProteusConversationSession>> {
        let mut proteus_sessions = GroupStore::new_with_limit(crate::group_store::ITEM_LIMIT * 2);
        for session in keystore
            .find_all::<ProteusSession>(Default::default())
            .await
            .map_err(KeystoreError::wrap("finding all proteus sessions"))?
            .into_iter()
        {
            let proteus_session = Session::deserialise(identity.clone(), &session.session)
                .map_err(ProteusError::wrap("deserializing session"))?;

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
    ) -> Result<GroupStoreValue<ProteusConversationSession>> {
        let prekey = PreKeyBundle::deserialise(key).map_err(ProteusError::wrap("deserializing prekey bundle"))?;
        // Note on the `::<>` turbofish below:
        //
        // `init_from_prekey` returns an error type which is parametric over some wrapped `E`,
        // because one variant (not relevant to this particular operation) wraps an error type based
        // on a parameter of a different function entirely.
        //
        // Rust complains here, because it can't figure out what type that `E` should be. After all, it's
        // not inferrable from this function call! It is also entirely irrelevant in this case.
        //
        // We can derive two general rules about error-handling in Rust from this example:
        //
        // 1. It's better to make smaller error types where possible, encapsulating fallible operations
        //    with their own error variants, and then wrapping those errors where required, as opposed to
        //    creating giant catch-all errors. Doing so also has knock-on benefits with regard to tracing
        //    the precise origin of the error.
        // 2. One should never make an error wrapper parametric. If you need to wrap an unknown error,
        //    it's always better to wrap a `Box<dyn std::error::Error>` than to make your error type parametric.
        //    The allocation cost of creating the `Box` is utterly trivial in an error-handling path, and
        //    it avoids parametric virality. (`init_from_prekey` is itself only generic because it returns
        //    this error type with a type-parametric variant, which the function never returns.)
        //
        // In this case, we have the out of band knowledge that `ProteusErrorKind` has a `#[from]` implementation
        // for `proteus_wasm::session::Error<core_crypto_keystore::CryptoKeystoreError>` and for no other kinds
        // of session error. So we can safely say that the type of error we are meant to catch here, and
        // therefore pass in that otherwise-irrelevant type, to ensure that error handling works properly.
        //
        // Some people say that if it's stupid but it works, it's not stupid. I disagree. If it's stupid but
        // it works, that's our cue to seek out even better, non-stupid ways to get things done. I reiterate:
        // the actual type referred to in this turbofish is nothing but a magic incantation to make error
        // handling work; it has no bearing on the error retured from this function. How much better would it
        // have been if `session::Error` were not parametric and we could have avoided the turbofish entirely?
        let proteus_session = Session::init_from_prekey::<core_crypto_keystore::CryptoKeystoreError>(
            self.proteus_identity.clone(),
            prekey,
        )
        .map_err(ProteusError::wrap("initializing session from prekey"))?;

        let proteus_conversation = ProteusConversationSession {
            identifier: session_id.into(),
            session: proteus_session,
        };

        self.proteus_sessions.insert(session_id.into(), proteus_conversation);

        Ok(self.proteus_sessions.get(session_id.as_bytes()).unwrap().clone())
    }

    /// Creates a new proteus Session from a received message
    pub(crate) async fn session_from_message(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        envelope: &[u8],
    ) -> Result<(GroupStoreValue<ProteusConversationSession>, Vec<u8>)> {
        let message = Envelope::deserialise(envelope).map_err(ProteusError::wrap("deserialising envelope"))?;
        let (session, payload) = Session::init_from_message(self.proteus_identity.clone(), keystore, &message)
            .await
            .map_err(ProteusError::wrap("initializing session from message"))?;

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
    pub(crate) async fn session_save(&mut self, keystore: &CryptoKeystore, session_id: &str) -> Result<()> {
        if let Some(session) = self
            .proteus_sessions
            .get_fetch(session_id.as_bytes(), keystore, Some(self.proteus_identity.clone()))
            .await?
        {
            Self::session_save_by_ref(keystore, session).await?;
        }

        Ok(())
    }

    pub(crate) async fn session_save_by_ref(
        keystore: &CryptoKeystore,
        session: GroupStoreValue<ProteusConversationSession>,
    ) -> Result<()> {
        let session = session.read().await;
        let db_session = ProteusSession {
            id: session.identifier().to_string(),
            session: session
                .session
                .serialise()
                .map_err(ProteusError::wrap("serializing session"))?,
        };
        keystore
            .save(db_session)
            .await
            .map_err(KeystoreError::wrap("saving proteus session"))?;
        Ok(())
    }

    /// Deletes a session in the store
    pub(crate) async fn session_delete(&mut self, keystore: &CryptoKeystore, session_id: &str) -> Result<()> {
        if keystore.remove::<ProteusSession, _>(session_id).await.is_ok() {
            let _ = self.proteus_sessions.remove(session_id.as_bytes());
        }
        Ok(())
    }

    /// Session accessor
    pub(crate) async fn session(
        &mut self,
        session_id: &str,
        keystore: &CryptoKeystore,
    ) -> Result<Option<GroupStoreValue<ProteusConversationSession>>> {
        self.proteus_sessions
            .get_fetch(session_id.as_bytes(), keystore, Some(self.proteus_identity.clone()))
            .await
    }

    /// Session exists
    pub(crate) async fn session_exists(&mut self, session_id: &str, keystore: &CryptoKeystore) -> bool {
        self.session(session_id, keystore).await.ok().flatten().is_some()
    }

    /// Decrypt a proteus message for an already existing session
    /// Note: This cannot be used for handshake messages, see [ProteusCentral::session_from_message]
    pub(crate) async fn decrypt(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .proteus_sessions
            .get_fetch(session_id.as_bytes(), keystore, Some(self.proteus_identity.clone()))
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;

        let plaintext = session.write().await.decrypt(keystore, ciphertext).await?;
        ProteusCentral::session_save_by_ref(keystore, session).await?;

        Ok(plaintext)
    }

    /// Encrypt a message for a session
    pub(crate) async fn encrypt(
        &mut self,
        keystore: &mut CryptoKeystore,
        session_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .session(session_id, keystore)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;

        let ciphertext = session.write().await.encrypt(plaintext)?;
        ProteusCentral::session_save_by_ref(keystore, session).await?;

        Ok(ciphertext)
    }

    /// Encrypts a message for a list of sessions
    /// This is mainly used for conversations with multiple clients, this allows to minimize FFI roundtrips
    pub(crate) async fn encrypt_batched(
        &mut self,
        keystore: &mut CryptoKeystore,
        sessions: &[impl AsRef<str>],
        plaintext: &[u8],
    ) -> Result<HashMap<String, Vec<u8>>> {
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
    pub(crate) async fn new_prekey(&self, id: u16, keystore: &CryptoKeystore) -> Result<Vec<u8>> {
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
    pub(crate) async fn new_prekey_auto(&self, keystore: &CryptoKeystore) -> Result<(u16, Vec<u8>)> {
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
    pub(crate) async fn last_resort_prekey(&self, keystore: &CryptoKeystore) -> Result<Vec<u8>> {
        let last_resort = if let Some(last_resort) = keystore
            .find::<core_crypto_keystore::entities::ProteusPrekey>(
                Self::last_resort_prekey_id().to_le_bytes().as_slice(),
            )
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
    pub(crate) async fn fingerprint_local(&mut self, session_id: &str, keystore: &CryptoKeystore) -> Result<String> {
        let session = self
            .session(session_id, keystore)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;
        let fingerprint = session.read().await.fingerprint_local();
        Ok(fingerprint)
    }

    /// Proteus Session remote hex-encoded fingerprint
    ///
    /// # Errors
    /// When the session is not found
    pub(crate) async fn fingerprint_remote(&mut self, session_id: &str, keystore: &CryptoKeystore) -> Result<String> {
        let session = self
            .session(session_id, keystore)
            .await?
            .ok_or(LeafError::ConversationNotFound(session_id.as_bytes().into()))
            .map_err(ProteusError::wrap("getting session"))?;
        let fingerprint = session.read().await.fingerprint_remote();
        Ok(fingerprint)
    }

    /// Hex-encoded fingerprint of the given prekey
    ///
    /// # Errors
    /// If the prekey cannot be deserialized
    pub fn fingerprint_prekeybundle(prekey: &[u8]) -> Result<String> {
        let prekey = PreKeyBundle::deserialise(prekey).map_err(ProteusError::wrap("deserialising prekey bundle"))?;
        Ok(prekey.identity_key.fingerprint())
    }

    /// Cryptobox -> CoreCrypto migration
    #[cfg_attr(not(feature = "cryptobox-migrate"), allow(unused_variables))]
    pub(crate) async fn cryptobox_migrate(keystore: &CryptoKeystore, path: &str) -> Result<()> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "cryptobox-migrate")] {
                Self::cryptobox_migrate_impl(keystore, path).await?;
                Ok(())
            } else {
                Err(Error::FeatureDisabled("cryptobox-migrate"))
            }
        }
    }
}

#[cfg(feature = "cryptobox-migrate")]
#[allow(dead_code)]
impl ProteusCentral {
    #[cfg(not(target_family = "wasm"))]
    async fn cryptobox_migrate_impl(keystore: &CryptoKeystore, path: &str) -> Result<()> {
        let root_dir = std::path::PathBuf::from(path);

        if !root_dir.exists() {
            return Err(CryptoboxMigrationError::wrap("root dir does not exist")(
                crate::CryptoboxMigrationErrorKind::ProvidedPathDoesNotExist(path.into()),
            )
            .into());
        }

        let session_dir = root_dir.join("sessions");
        let prekey_dir = root_dir.join("prekeys");

        // return early any time we can't figure out some part of the identity
        let missing_identity = Err(CryptoboxMigrationError::wrap("taking identity keypair")(
            crate::CryptoboxMigrationErrorKind::IdentityNotFound(path.into()),
        )
        .into());

        let identity = if let Some(store_kp) = keystore
            .find::<ProteusIdentity>(&[])
            .await
            .map_err(KeystoreError::wrap("finding proteus identity"))?
        {
            Box::new(
                IdentityKeyPair::from_raw_key_pair(*store_kp.sk_raw(), *store_kp.pk_raw())
                    .map_err(ProteusError::wrap("constructing identity keypair from raw keypair"))?,
            )
        } else {
            let identity_dir = root_dir.join("identities");

            let identity = identity_dir.join("local");
            let legacy_identity = identity_dir.join("local_identity");
            // Old "local_identity" migration step
            let kp = if legacy_identity.exists() {
                let kp_cbor = async_fs::read(&legacy_identity)
                    .await
                    .map_err(CryptoboxMigrationError::wrap("reading legacy identity from filesystem"))?;
                let kp = IdentityKeyPair::deserialise(&kp_cbor)
                    .map_err(ProteusError::wrap("deserialising identity keypair"))?;

                Box::new(kp)
            } else if identity.exists() {
                let kp_cbor = async_fs::read(&identity)
                    .await
                    .map_err(CryptoboxMigrationError::wrap("reading identity from filesystem"))?;
                let kp = proteus_wasm::identity::Identity::deserialise(&kp_cbor)
                    .map_err(ProteusError::wrap("deserialising identity"))?;

                if let proteus_wasm::identity::Identity::Sec(kp) = kp {
                    kp.into_owned()
                } else {
                    return missing_identity;
                }
            } else {
                return missing_identity;
            };

            let pk = kp.public_key.public_key.as_slice().into();

            let ks_identity = ProteusIdentity {
                sk: kp.secret_key.to_keypair_bytes().into(),
                pk,
            };

            keystore
                .save(ks_identity)
                .await
                .map_err(KeystoreError::wrap("saving proteus identity"))?;

            if legacy_identity.exists() {
                async_fs::remove_file(legacy_identity)
                    .await
                    .map_err(CryptoboxMigrationError::wrap("removing legacy identity"))?;
            }

            kp
        };

        let identity = *identity;

        use futures_lite::stream::StreamExt as _;
        // Session migration
        let mut session_entries = async_fs::read_dir(session_dir)
            .await
            .map_err(CryptoboxMigrationError::wrap("reading session entries"))?;
        while let Some(session_file) = session_entries
            .try_next()
            .await
            .map_err(CryptoboxMigrationError::wrap("getting next session file"))?
        {
            // The name of the file is the session id
            let proteus_session_id: String = session_file.file_name().to_string_lossy().to_string();

            // If the session is already in store, skip ahead
            if keystore
                .find::<ProteusSession>(proteus_session_id.as_bytes())
                .await
                .map_err(KeystoreError::wrap("finding proteus session by id"))?
                .is_some()
            {
                continue;
            }

            let raw_session = async_fs::read(session_file.path())
                .await
                .map_err(CryptoboxMigrationError::wrap("reading session file"))?;
            // Session integrity check
            let Ok(_) = Session::deserialise(&identity, &raw_session) else {
                continue;
            };

            let keystore_session = ProteusSession {
                id: proteus_session_id,
                session: raw_session,
            };

            keystore
                .save(keystore_session)
                .await
                .map_err(KeystoreError::wrap("saving proteus session"))?;
        }

        // Prekey migration
        use core_crypto_keystore::entities::ProteusPrekey;

        use crate::CryptoboxMigrationError;
        let mut prekey_entries = async_fs::read_dir(prekey_dir)
            .await
            .map_err(CryptoboxMigrationError::wrap("reading prekey entries"))?;
        while let Some(prekey_file) = prekey_entries
            .try_next()
            .await
            .map_err(CryptoboxMigrationError::wrap("getting next prekey file"))?
        {
            // The name of the file is the prekey id, so we parse it to get the ID
            let proteus_prekey_id = proteus_wasm::keys::PreKeyId::new(
                prekey_file
                    .file_name()
                    .to_string_lossy()
                    .parse()
                    .map_err(CryptoboxMigrationError::wrap("parsing prekey file name"))?,
            );

            // Check if the prekey ID is already existing
            if keystore
                .find::<ProteusPrekey>(&proteus_prekey_id.value().to_le_bytes())
                .await
                .map_err(KeystoreError::wrap("finding proteus prekey by id"))?
                .is_some()
            {
                continue;
            }

            let raw_prekey = async_fs::read(prekey_file.path())
                .await
                .map_err(CryptoboxMigrationError::wrap("reading prekey file"))?;
            // Integrity check to see if the PreKey is actually correct
            if proteus_wasm::keys::PreKey::deserialise(&raw_prekey).is_ok() {
                let keystore_prekey = ProteusPrekey::from_raw(proteus_prekey_id.value(), raw_prekey);
                keystore
                    .save(keystore_prekey)
                    .await
                    .map_err(KeystoreError::wrap("saving proteus prekey"))?;
            }
        }

        Ok(())
    }

    #[cfg(target_family = "wasm")]
    fn get_cbor_bytes_from_map(map: serde_json::map::Map<String, serde_json::Value>) -> Result<Vec<u8>> {
        use crate::{CryptoboxMigrationError, CryptoboxMigrationErrorKind};

        let Some(js_value) = map.get("serialised") else {
            return Err(CryptoboxMigrationError::wrap("getting serialised cbor bytes from map")(
                CryptoboxMigrationErrorKind::MissingKeyInValue("serialised".to_string()),
            )
            .into());
        };

        let Some(b64_value) = js_value.as_str() else {
            return Err(CryptoboxMigrationError::wrap("getting js value as string")(
                CryptoboxMigrationErrorKind::WrongValueType("string".to_string()),
            )
            .into());
        };

        use base64::Engine as _;
        let cbor_bytes = base64::prelude::BASE64_STANDARD
            .decode(b64_value)
            .map_err(CryptoboxMigrationError::wrap("decoding cbor bytes"))?;
        Ok(cbor_bytes)
    }

    #[cfg(target_family = "wasm")]
    async fn cryptobox_migrate_impl(keystore: &CryptoKeystore, path: &str) -> Result<()> {
        use rexie::{Rexie, TransactionMode};

        use crate::{CryptoboxMigrationError, CryptoboxMigrationErrorKind};
        let local_identity_key = "local_identity";
        let local_identity_store_name = "keys";
        let prekeys_store_name = "prekeys";
        let sessions_store_name = "sessions";

        // Path should be following this logic: https://github.com/wireapp/wire-web-packages/blob/main/packages/core/src/main/Account.ts#L645
        let db = Rexie::builder(path)
            .build()
            .await
            .map_err(CryptoboxMigrationError::wrap("building rexie"))?;

        let store_names = db.store_names();

        let expected_stores = &[prekeys_store_name, sessions_store_name, local_identity_store_name];

        if !expected_stores
            .iter()
            .map(ToString::to_string)
            .all(|s| store_names.contains(&s))
        {
            return Err(CryptoboxMigrationError::wrap("checking expected stores")(
                CryptoboxMigrationErrorKind::ProvidedPathDoesNotExist(path.into()),
            )
            .into());
        }

        let mut proteus_identity = if let Some(store_kp) = keystore
            .find::<ProteusIdentity>(&[])
            .await
            .map_err(KeystoreError::wrap("finding proteus identity for empty id"))?
        {
            Some(
                proteus_wasm::keys::IdentityKeyPair::from_raw_key_pair(*store_kp.sk_raw(), *store_kp.pk_raw())
                    .map_err(ProteusError::wrap("constructing identity keypair from raw"))?,
            )
        } else {
            let transaction = db
                .transaction(&[local_identity_store_name], TransactionMode::ReadOnly)
                .map_err(CryptoboxMigrationError::wrap("initializing rexie transaction"))?;

            let identity_store = transaction
                .store(local_identity_store_name)
                .map_err(CryptoboxMigrationError::wrap("storing local identity store name"))?;

            if let Some(cryptobox_js_value) = identity_store
                .get(local_identity_key.into())
                .await
                .map_err(CryptoboxMigrationError::wrap("getting local identity key js value"))?
            {
                let js_value: serde_json::map::Map<String, serde_json::Value> =
                    serde_wasm_bindgen::from_value(cryptobox_js_value).map_err(CryptoboxMigrationError::wrap(
                        "getting local identity key from identity store",
                    ))?;

                let kp_cbor = Self::get_cbor_bytes_from_map(js_value)?;

                let kp = proteus_wasm::keys::IdentityKeyPair::deserialise(&kp_cbor)
                    .map_err(ProteusError::wrap("deserializing identity keypair"))?;

                let pk = kp.public_key.public_key.as_slice().to_vec();

                let ks_identity = ProteusIdentity {
                    sk: kp.secret_key.to_keypair_bytes().into(),
                    pk,
                };
                keystore
                    .save(ks_identity)
                    .await
                    .map_err(KeystoreError::wrap("saving proteus identity in keystore"))?;

                Some(kp)
            } else {
                None
            }
        };

        let Some(proteus_identity) = proteus_identity.take() else {
            return Err(CryptoboxMigrationError::wrap("taking proteus identity")(
                CryptoboxMigrationErrorKind::IdentityNotFound(path.into()),
            )
            .into());
        };

        if store_names.contains(&sessions_store_name.to_string()) {
            let transaction = db
                .transaction(&[sessions_store_name], TransactionMode::ReadOnly)
                .map_err(CryptoboxMigrationError::wrap("starting rexie transaction"))?;

            let sessions_store = transaction
                .store(sessions_store_name)
                .map_err(CryptoboxMigrationError::wrap("getting sessions store"))?;

            let sessions = sessions_store
                .scan(None, None, None, None)
                .await
                .map_err(CryptoboxMigrationError::wrap("scanning sessions store for sessions"))?;

            for (session_id, session_js_value) in sessions.into_iter().map(|(k, v)| (k.as_string().unwrap(), v)) {
                // If the session is already in store, skip ahead
                if keystore
                    .find::<ProteusSession>(session_id.as_bytes())
                    .await
                    .map_err(KeystoreError::wrap("finding proteus session by id"))?
                    .is_some()
                {
                    continue;
                }

                let js_value: serde_json::map::Map<String, serde_json::Value> =
                    serde_wasm_bindgen::from_value(session_js_value).map_err(CryptoboxMigrationError::wrap(
                        "converting session js value to serde map",
                    ))?;

                let session_cbor_bytes = Self::get_cbor_bytes_from_map(js_value)?;

                // Integrity check
                if proteus_wasm::session::Session::deserialise(&proteus_identity, &session_cbor_bytes).is_ok() {
                    let keystore_session = ProteusSession {
                        id: session_id,
                        session: session_cbor_bytes,
                    };

                    keystore
                        .save(keystore_session)
                        .await
                        .map_err(KeystoreError::wrap("saving keystore session"))?;
                }
            }
        }

        if store_names.contains(&prekeys_store_name.to_string()) {
            use core_crypto_keystore::entities::ProteusPrekey;

            let transaction = db
                .transaction(&[prekeys_store_name], TransactionMode::ReadOnly)
                .map_err(CryptoboxMigrationError::wrap("beginning rexie transaction"))?;

            let prekeys_store = transaction
                .store(prekeys_store_name)
                .map_err(CryptoboxMigrationError::wrap("getting prekeys store"))?;

            let prekeys = prekeys_store
                .scan(None, None, None, None)
                .await
                .map_err(CryptoboxMigrationError::wrap("scanning for prekeys"))?;

            for (prekey_id, prekey_js_value) in prekeys
                .into_iter()
                .map(|(id, prekey_js_value)| (id.as_string().unwrap(), prekey_js_value))
            {
                let prekey_id: u16 = prekey_id
                    .parse()
                    .map_err(CryptoboxMigrationError::wrap("parsing prekey id"))?;

                // Check if the prekey ID is already existing
                if keystore
                    .find::<ProteusPrekey>(&prekey_id.to_le_bytes())
                    .await
                    .map_err(KeystoreError::wrap(
                        "finding proteus prekey by id to check for existence",
                    ))?
                    .is_some()
                {
                    continue;
                }

                let js_value: serde_json::map::Map<String, serde_json::Value> =
                    serde_wasm_bindgen::from_value(prekey_js_value)
                        .map_err(CryptoboxMigrationError::wrap("converting prekey js value to serde map"))?;

                let raw_prekey_cbor = Self::get_cbor_bytes_from_map(js_value)?;

                // Integrity check to see if the PreKey is actually correct
                if proteus_wasm::keys::PreKey::deserialise(&raw_prekey_cbor).is_ok() {
                    let keystore_prekey = ProteusPrekey::from_raw(prekey_id, raw_prekey_cbor);
                    keystore
                        .save(keystore_prekey)
                        .await
                        .map_err(KeystoreError::wrap("saving proteus prekey"))?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        prelude::{CertificateBundle, ClientIdentifier, MlsClientConfiguration, MlsCredentialType, Session},
        test_utils::{proteus_utils::*, x509::X509TestChain, *},
    };

    use crate::prelude::INITIAL_KEYING_MATERIAL_COUNT;
    use proteus_traits::PreKeyStore;

    use super::*;

    use core_crypto_keystore::DatabaseKey;

    #[apply(all_cred_cipher)]
    async fn cc_can_init(case: TestContext) {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();
        let client_id = "alice".into();
        let cfg = MlsClientConfiguration::try_new(
            path,
            DatabaseKey::generate(),
            Some(client_id),
            vec![case.ciphersuite()],
            None,
            Some(INITIAL_KEYING_MATERIAL_COUNT),
        )
        .unwrap();
        let cc: CoreCrypto = Session::try_new(cfg).await.unwrap().into();
        let context = cc.new_transaction().await.unwrap();
        assert!(context.proteus_init().await.is_ok());
        assert!(context.proteus_new_prekey(1).await.is_ok());
        context.finish().await.unwrap();
        #[cfg(not(target_family = "wasm"))]
        drop(db_file);
    }

    #[apply(all_cred_cipher)]
    async fn cc_can_2_phase_init(case: TestContext) {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();
        // we are deferring MLS initialization here, not passing a MLS 'client_id' yet
        let cfg = MlsClientConfiguration::try_new(
            path,
            DatabaseKey::generate(),
            None,
            vec![case.ciphersuite()],
            None,
            Some(INITIAL_KEYING_MATERIAL_COUNT),
        )
        .unwrap();
        let cc: CoreCrypto = Session::try_new(cfg).await.unwrap().into();
        let transaction = cc.new_transaction().await.unwrap();
        let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
        x509_test_chain.register_with_central(&transaction).await;
        assert!(transaction.proteus_init().await.is_ok());
        // proteus is initialized, prekeys can be generated
        assert!(transaction.proteus_new_prekey(1).await.is_ok());
        // 👇 and so a unique 'client_id' can be fetched from wire-server
        let client_id = "alice";
        let identifier = match case.credential_type {
            MlsCredentialType::Basic => ClientIdentifier::Basic(client_id.into()),
            MlsCredentialType::X509 => {
                CertificateBundle::rand_identifier(client_id, &[x509_test_chain.find_local_intermediate_ca()])
            }
        };
        transaction
            .mls_init(
                identifier,
                vec![case.ciphersuite()],
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            )
            .await
            .unwrap();
        // expect MLS to work
        assert_eq!(
            transaction
                .get_or_create_client_keypackages(case.ciphersuite(), case.credential_type, 2)
                .await
                .unwrap()
                .len(),
            2
        );
        #[cfg(not(target_family = "wasm"))]
        drop(db_file);
    }

    #[async_std::test]
    async fn can_init() {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();
        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Connection::open_with_key(&path, &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();
        let central = ProteusCentral::try_new(&keystore).await.unwrap();
        let identity = (*central.proteus_identity).clone();
        keystore.commit_transaction().await.unwrap();

        let keystore = core_crypto_keystore::Connection::open_with_key(path, &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();
        let central = ProteusCentral::try_new(&keystore).await.unwrap();
        keystore.commit_transaction().await.unwrap();
        assert_eq!(identity, *central.proteus_identity);

        keystore.wipe().await.unwrap();
        #[cfg(not(target_family = "wasm"))]
        drop(db_file);
    }

    #[async_std::test]
    async fn can_talk_with_proteus() {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();

        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();

        let key = DatabaseKey::generate();
        let mut keystore = core_crypto_keystore::Connection::open_with_key(path, &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();

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

        keystore.commit_transaction().await.unwrap();
        keystore.wipe().await.unwrap();
        #[cfg(not(target_family = "wasm"))]
        drop(db_file);
    }

    #[async_std::test]
    async fn can_produce_proteus_consumed_prekeys() {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();

        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();

        let key = DatabaseKey::generate();
        let mut keystore = core_crypto_keystore::Connection::open_with_key(path, &key)
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
        #[cfg(not(target_family = "wasm"))]
        drop(db_file);
    }

    #[async_std::test]
    async fn auto_prekeys_are_sequential() {
        use core_crypto_keystore::entities::ProteusPrekey;
        const GAP_AMOUNT: u16 = 5;
        const ID_TEST_RANGE: std::ops::RangeInclusive<u16> = 1..=30;

        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();

        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Connection::open_with_key(path, &key)
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
        keystore.commit_transaction().await.unwrap();
        keystore.wipe().await.unwrap();
        #[cfg(not(target_family = "wasm"))]
        drop(db_file);
    }

    #[cfg(all(feature = "cryptobox-migrate", not(target_family = "wasm")))]
    #[async_std::test]
    async fn can_import_cryptobox() {
        use crate::CryptoboxMigrationErrorKind;

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

        let key = DatabaseKey::generate();
        let mut keystore =
            core_crypto_keystore::Connection::open_with_key(keystore_file.as_os_str().to_string_lossy(), &key)
                .await
                .unwrap();
        keystore.new_transaction().await.unwrap();

        let Err(crate::Error::CryptoboxMigration(crate::CryptoboxMigrationError {
            source: CryptoboxMigrationErrorKind::ProvidedPathDoesNotExist(_),
            ..
        })) = ProteusCentral::cryptobox_migrate(&keystore, "invalid path").await
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
        let alice_new_session_lock = proteus_central.session(&session_id, &keystore).await.unwrap().unwrap();
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

        proteus_central.session_save(&keystore, &session_id).await.unwrap();
        keystore.commit_transaction().await.unwrap();
        keystore.wipe().await.unwrap();
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))] {
            // use wasm_bindgen::prelude::*;
            const CRYPTOBOX_JS_DBNAME: &str = "cryptobox-migrate-test";
            // wasm-bindgen-test-runner is behaving weird with inline_js stuff (aka not working basically), which we had previously
            // So instead we emulate how cryptobox-js works
            // Returns Promise<JsString>
            fn run_cryptobox(alice: CryptoboxLike) -> js_sys::Promise {
                wasm_bindgen_futures::future_to_promise(async move {
                    use rexie::{Rexie, ObjectStore, TransactionMode};
                    use wasm_bindgen::JsValue;

                    // Delete the maybe past database to make sure we start fresh
                    Rexie::builder(CRYPTOBOX_JS_DBNAME)
                        .delete()
                        .await.map_err(|err| err.to_string())?;

                    let rexie = Rexie::builder(CRYPTOBOX_JS_DBNAME)
                        .version(1)
                        .add_object_store(ObjectStore::new("keys").auto_increment(false))
                        .add_object_store(ObjectStore::new("prekeys").auto_increment(false))
                        .add_object_store(ObjectStore::new("sessions").auto_increment(false))
                        .build()
                        .await.map_err(|err| err.to_string())?;

                    // Add identity key
                    let transaction = rexie.transaction(&["keys"], TransactionMode::ReadWrite).map_err(|err| err.to_string())?;
                    let store = transaction.store("keys").map_err(|err| err.to_string())?;

                    use base64::Engine as _;
                    let json = serde_json::json!({
                        "created": 0,
                        "id": "local_identity",
                        "serialised": base64::prelude::BASE64_STANDARD.encode(alice.identity.serialise().unwrap()),
                        "version": "1.0"
                    });
                    let js_value = serde_wasm_bindgen::to_value(&json)?;

                    store.add(&js_value, Some(&JsValue::from_str("local_identity"))).await.map_err(|err| err.to_string())?;

                    // Add prekeys
                    let transaction = rexie.transaction(&["prekeys"], TransactionMode::ReadWrite).map_err(|err| err.to_string())?;
                    let store = transaction.store("prekeys").map_err(|err| err.to_string())?;
                    for prekey in alice.prekeys.0.into_iter() {
                        let id = prekey.key_id.value().to_string();
                        let json = serde_json::json!({
                            "created": 0,
                            "id": &id,
                            "serialised": base64::prelude::BASE64_STANDARD.encode(prekey.serialise().unwrap()),
                            "version": "1.0"
                        });
                        let js_value = serde_wasm_bindgen::to_value(&json)?;
                        store.add(&js_value, Some(&JsValue::from_str(&id))).await.map_err(|err| err.to_string())?;
                    }

                    // Add sessions
                    let transaction = rexie.transaction(&["sessions"], TransactionMode::ReadWrite).map_err(|err| err.to_string())?;
                    let store = transaction.store("sessions").map_err(|err| err.to_string())?;
                    for (session_id, session) in alice.sessions.into_iter() {
                        let json = serde_json::json!({
                            "created": 0,
                            "id": session_id,
                            "serialised": base64::prelude::BASE64_STANDARD.encode(session.serialise().unwrap()),
                            "version": "1.0"
                        });

                        let js_value = serde_wasm_bindgen::to_value(&json)?;
                        store.add(&js_value, Some(&JsValue::from_str(&session_id))).await.map_err(|err| err.to_string())?;
                    }

                    Ok(JsValue::UNDEFINED)
                })
            }
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

                use sha2::Digest as _;
                let old_key = "test";
                let new_key = DatabaseKey::try_from(sha2::Sha256::digest(old_key).as_slice()).unwrap();

                let name = format!("{CRYPTOBOX_JS_DBNAME}-imported");
                let _ = core_crypto_keystore::connection::platform::open_and_migrate_pre_v4(&name, old_key).await;

                core_crypto_keystore::Connection::migrate_db_key_type_to_bytes(&name, old_key, &new_key).await.unwrap();

                let mut keystore = core_crypto_keystore::Connection::open_with_key(&name, &new_key).await.unwrap();
                keystore.new_transaction().await.unwrap();
                let Err(crate::Error::CryptoboxMigration(crate::CryptoboxMigrationError{
                    source: crate::CryptoboxMigrationErrorKind::ProvidedPathDoesNotExist(_),
                    ..
                })) = ProteusCentral::cryptobox_migrate(&keystore, "invalid path").await else {
                    panic!("ProteusCentral::cryptobox_migrate did not throw an error on invalid path");
                };

                ProteusCentral::cryptobox_migrate(&keystore, CRYPTOBOX_JS_DBNAME).await.unwrap();

                let mut proteus_central = ProteusCentral::try_new(&keystore).await.unwrap();

                // Identity check
                assert_eq!(proteus_central.fingerprint(), alice_fingerprint);

                // Session integrity check
                let alice_new_session_lock = proteus_central
                    .session(&session_id, &keystore)
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
                keystore.commit_transaction().await.unwrap();

                keystore.wipe().await.unwrap();
            }
        }
    }
}
