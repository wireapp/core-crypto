use std::{collections::HashMap, sync::Arc};

use core_crypto_keystore::{
    Database as CryptoKeystore,
    connection::FetchFromDatabase,
    entities::{ProteusIdentity, ProteusSession},
};
use proteus_wasm::{
    keys::{IdentityKeyPair, PreKeyBundle},
    message::Envelope,
    session::Session,
};

use crate::{
    CoreCrypto, Error, KeystoreError, LeafError, ProteusError, Result,
    group_store::{GroupStore, GroupStoreEntity, GroupStoreValue},
};

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
    pub async fn decrypt(&mut self, store: &mut core_crypto_keystore::Database, ciphertext: &[u8]) -> Result<Vec<u8>> {
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
        id: impl AsRef<[u8]> + Send,
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
            .find::<ProteusIdentity>(ProteusIdentity::ID)
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
        keystore: &core_crypto_keystore::Database,
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

        self.proteus_sessions
            .insert(session_id.as_bytes(), proteus_conversation);

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

        self.proteus_sessions
            .insert(session_id.as_bytes(), proteus_conversation);

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
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{ConnectionType, Database, DatabaseKey};

    use super::*;
    use crate::{
        CertificateBundle, ClientId, ClientIdentifier, CredentialType, Session,
        test_utils::{proteus_utils::*, x509::X509TestChain, *},
    };

    #[apply(all_cred_cipher)]
    async fn cc_can_init(case: TestContext) {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();
        let client_id = ClientId::from("alice").into();
        let db = Database::open(ConnectionType::Persistent(&path), &DatabaseKey::generate())
            .await
            .unwrap();

        let cc: CoreCrypto = Session::try_new(&db).await.unwrap().into();
        cc.init(client_id, &[case.ciphersuite().signature_algorithm()])
            .await
            .unwrap();
        let context = cc.new_transaction().await.unwrap();
        assert!(context.proteus_init().await.is_ok());
        assert!(context.proteus_new_prekey(1).await.is_ok());
        context.finish().await.unwrap();
        #[cfg(not(target_family = "wasm"))]
        drop(db_file);
    }

    #[apply(all_cred_cipher)]
    async fn cc_can_2_phase_init(case: TestContext) {
        use crate::{ClientId, Credential};

        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();
        let db = Database::open(ConnectionType::Persistent(&path), &DatabaseKey::generate())
            .await
            .unwrap();

        let cc: CoreCrypto = Session::try_new(&db).await.unwrap().into();
        let transaction = cc.new_transaction().await.unwrap();
        let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
        x509_test_chain.register_with_central(&transaction).await;
        assert!(transaction.proteus_init().await.is_ok());
        // proteus is initialized, prekeys can be generated
        assert!(transaction.proteus_new_prekey(1).await.is_ok());
        // 👇 and so a unique 'client_id' can be fetched from wire-server
        let client_id = ClientId::from("alice");
        let identifier = match case.credential_type {
            CredentialType::Basic => ClientIdentifier::Basic(client_id),
            CredentialType::X509 => {
                CertificateBundle::rand_identifier(&client_id, &[x509_test_chain.find_local_intermediate_ca()])
            }
            CredentialType::Unknown(_) => panic!("unknown credential types are unsupported"),
        };
        transaction
            .mls_init(identifier.clone(), &[case.ciphersuite()])
            .await
            .unwrap();

        let credential =
            Credential::from_identifier(&identifier, case.signature_scheme(), &cc.mls.crypto_provider).unwrap();
        cc.add_credential(credential).await.unwrap();

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

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn can_init() {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();
        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Database::open(ConnectionType::Persistent(&path), &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();
        let central = ProteusCentral::try_new(&keystore).await.unwrap();
        let identity = (*central.proteus_identity).clone();
        keystore.commit_transaction().await.unwrap();

        let keystore = core_crypto_keystore::Database::open(ConnectionType::Persistent(&path), &key)
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

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn can_talk_with_proteus() {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
        let (path, _) = tmp_db_file();

        let session_id = uuid::Uuid::new_v4().hyphenated().to_string();

        let key = DatabaseKey::generate();
        let mut keystore = core_crypto_keystore::Database::open(ConnectionType::Persistent(&path), &key)
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

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn can_produce_proteus_consumed_prekeys() {
        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
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
        #[cfg(not(target_family = "wasm"))]
        drop(db_file);
    }

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn auto_prekeys_are_sequential() {
        use core_crypto_keystore::entities::ProteusPrekey;
        const GAP_AMOUNT: u16 = 5;
        const ID_TEST_RANGE: std::ops::RangeInclusive<u16> = 1..=30;

        #[cfg(not(target_family = "wasm"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_family = "wasm")]
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
}
