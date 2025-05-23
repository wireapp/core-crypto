pub(crate) mod e2e_identity;
mod epoch_observer;
mod error;
pub(crate) mod id;
pub(crate) mod identifier;
pub(crate) mod identities;
pub(crate) mod key_package;
pub(crate) mod user_id;

use crate::{
    CoreCrypto, KeystoreError, LeafError, MlsError, MlsTransport, RecursiveError,
    group_store::GroupStore,
    mls::{
        self, HasSessionAndCrypto,
        conversation::ImmutableConversation,
        credential::{CredentialBundle, ext::CredentialExt},
    },
    prelude::{
        CertificateBundle, ClientId, ConversationId, HistorySecret, INITIAL_KEYING_MATERIAL_COUNT, MlsCiphersuite,
        MlsClientConfiguration, MlsCredentialType, identifier::ClientIdentifier,
        key_package::KEYPACKAGE_DEFAULT_LIFETIME,
    },
};
use async_lock::RwLock;
use core_crypto_keystore::{
    Connection, CryptoKeystoreError,
    connection::FetchFromDatabase,
    entities::{EntityFindParams, MlsCredential, MlsSignatureKeyPair},
};
pub use epoch_observer::EpochObserver;
pub(crate) use error::{Error, Result};
use identities::Identities;
use log::debug;
use mls_crypto_provider::{EntropySeed, MlsCryptoProvider, MlsCryptoProviderConfiguration};
use openmls::prelude::{Credential, CredentialType};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsCryptoProvider, crypto::OpenMlsCrypto, types::SignatureScheme};
use openmls_x509_credential::CertificateKeyPair;
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Arc;
use tls_codec::{Deserialize, Serialize};

/// A MLS Session enables a user device to communicate via the MLS protocol.
///
/// This closely maps to the `Client` term in [RFC 9720], but we avoid that term to avoid ambiguity;
/// `Client` is very overloaded with distinct meanings.
///
/// There is one `Session` per user per device. A session can contain many MLS groups/conversations.
///
/// It is cheap to clone a `Session` because everything heavy is wrapped inside an [Arc].
///
/// [RFC 9720]: https://www.rfc-editor.org/rfc/rfc9420.html
#[derive(Clone, derive_more::Debug)]
pub struct Session {
    pub(crate) inner: Arc<RwLock<Option<SessionInner>>>,
    pub(crate) crypto_provider: MlsCryptoProvider,
    pub(crate) transport: Arc<RwLock<Option<Arc<dyn MlsTransport + 'static>>>>,
    #[debug("EpochObserver")]
    pub(crate) epoch_observer: Arc<RwLock<Option<Arc<dyn EpochObserver + 'static>>>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl HasSessionAndCrypto for Session {
    async fn session(&self) -> mls::Result<Session> {
        Ok(self.clone())
    }

    async fn crypto_provider(&self) -> mls::Result<MlsCryptoProvider> {
        Ok(self.crypto_provider.clone())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SessionInner {
    id: ClientId,
    pub(crate) identities: Identities,
    keypackage_lifetime: std::time::Duration,
}

impl Session {
    /// Creates a new [Session].
    /// Takes a store path (i.e. Disk location of the embedded database, should be consistent between messaging sessions)
    /// And a root identity key (i.e. enclaved encryption key for this device)
    ///
    /// # Arguments
    /// * `configuration` - the configuration for the `MlsCentral`
    ///
    /// # Errors
    /// Failures in the initialization of the KeyStore can cause errors, such as IO, the same kind
    /// of errors can happen when the groups are being restored from the KeyStore or even during
    /// the client initialization (to fetch the identity signature). Other than that, `MlsError`
    /// can be caused by group deserialization or during the initialization of the credentials:
    /// * for x509 Credentials if the certificate chain length is lower than 2
    /// * for Basic Credentials if the signature key cannot be generated either by not supported
    ///   scheme or the key generation fails
    pub async fn try_new(configuration: MlsClientConfiguration) -> crate::mls::Result<Self> {
        // Init backend (crypto + rand + keystore)
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            db_key: configuration.database_key.clone(),
            in_memory: false,
            entropy_seed: configuration.external_entropy.clone(),
        })
        .await
        .map_err(MlsError::wrap("trying to initialize mls crypto provider object"))?;
        Self::new_with_backend(mls_backend, configuration).await
    }

    /// Same as the [Self::try_new] but instead, it uses an in memory KeyStore.
    /// Although required, the `store_path` parameter from the `MlsClientConfiguration` won't be used here.
    pub async fn try_new_in_memory(configuration: MlsClientConfiguration) -> crate::mls::Result<Self> {
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            db_key: configuration.database_key.clone(),
            in_memory: true,
            entropy_seed: configuration.external_entropy.clone(),
        })
        .await
        .map_err(MlsError::wrap(
            "trying to initialize mls crypto provider object (in memory)",
        ))?;
        Self::new_with_backend(mls_backend, configuration).await
    }

    async fn new_with_backend(
        mls_backend: MlsCryptoProvider,
        configuration: MlsClientConfiguration,
    ) -> crate::mls::Result<Self> {
        // We create the core crypto instance first to enable creating a transaction from it and
        // doing all subsequent actions inside a single transaction, though it forces us to clone
        // a few Arcs and locks.
        let client = Self {
            crypto_provider: mls_backend.clone(),
            inner: Default::default(),
            transport: Arc::new(None.into()),
            epoch_observer: Arc::new(None.into()),
        };

        let cc = CoreCrypto::from(client.clone());
        let context = cc
            .new_transaction()
            .await
            .map_err(RecursiveError::transaction("starting new transaction"))?;

        if let Some(id) = configuration.client_id {
            client
                .init(
                    ClientIdentifier::Basic(id),
                    configuration.ciphersuites.as_slice(),
                    &mls_backend,
                    configuration
                        .nb_init_key_packages
                        .unwrap_or(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .await
                .map_err(RecursiveError::mls_client("initializing mls client"))?
        }

        let central = cc.mls;
        context
            .init_pki_env()
            .await
            .map_err(RecursiveError::transaction("initializing pki environment"))?;
        context
            .finish()
            .await
            .map_err(RecursiveError::transaction("finishing transaction"))?;
        Ok(central)
    }

    /// Provide the implementation of functions to communicate with the delivery service
    /// (see [MlsTransport]).
    pub async fn provide_transport(&self, transport: Arc<dyn MlsTransport>) {
        self.transport.write().await.replace(transport);
    }

    /// Initializes the client.
    /// If the client's cryptographic material is already stored in the keystore, it loads it
    /// Otherwise, it is being created.
    ///
    /// # Arguments
    /// * `identifier` - client identifier ; either a [ClientId] or a x509 certificate chain
    /// * `ciphersuites` - all ciphersuites this client is supposed to support
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors can happen
    pub async fn init(
        &self,
        identifier: ClientIdentifier,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
        nb_key_package: usize,
    ) -> Result<()> {
        self.ensure_unready().await?;
        let id = identifier.get_id()?;

        let credentials = backend
            .key_store()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls credentials"))?;

        let credentials = credentials
            .into_iter()
            .filter(|mls_credential| mls_credential.id.as_slice() == id.as_slice())
            .map(|mls_credential| -> Result<_> {
                let credential = Credential::tls_deserialize(&mut mls_credential.credential.as_slice())
                    .map_err(Error::tls_deserialize("mls credential"))?;
                Ok((credential, mls_credential.created_at))
            })
            .collect::<Result<Vec<_>>>()?;

        if credentials.is_empty() {
            debug!(count = nb_key_package, ciphersuites:? = ciphersuites; "Generating client");
            self.generate(identifier, backend, ciphersuites, nb_key_package).await?;
        } else {
            let signature_schemes = ciphersuites
                .iter()
                .map(|cs| cs.signature_algorithm())
                .collect::<HashSet<_>>();
            let load_result = self.load(backend, id.as_ref(), credentials, signature_schemes).await;
            if let Err(Error::ClientSignatureNotFound) = load_result {
                debug!(count = nb_key_package, ciphersuites:? = ciphersuites; "Client signature not found. Generating client");
                self.generate(identifier, backend, ciphersuites, nb_key_package).await?;
            } else {
                load_result?;
            }
        };

        Ok(())
    }

    /// Resets the client to an uninitialized state.
    #[cfg(test)]
    pub(crate) async fn reset(&self) {
        let mut inner_lock = self.inner.write().await;
        *inner_lock = None;
    }

    pub(crate) async fn is_ready(&self) -> bool {
        let inner_lock = self.inner.read().await;
        inner_lock.is_some()
    }

    async fn ensure_unready(&self) -> Result<()> {
        if self.is_ready().await {
            Err(Error::UnexpectedlyReady)
        } else {
            Ok(())
        }
    }

    async fn replace_inner(&self, new_inner: SessionInner) {
        let mut inner_lock = self.inner.write().await;
        *inner_lock = Some(new_inner);
    }

    /// Get an immutable view of an `MlsConversation`.
    ///
    /// Because it operates on the raw conversation type, this may be faster than
    /// [crate::transaction_context::TransactionContext::conversation]. for transient and immutable
    /// purposes. For long-lived or mutable purposes, prefer the other method.
    pub async fn get_raw_conversation(&self, id: &ConversationId) -> Result<ImmutableConversation> {
        let raw_conversation = GroupStore::fetch_from_keystore(id, &self.crypto_provider.keystore(), None)
            .await
            .map_err(RecursiveError::root("getting conversation by id"))?
            .ok_or_else(|| LeafError::ConversationNotFound(id.clone()))?;
        Ok(ImmutableConversation::new(raw_conversation, self.clone()))
    }

    /// Returns the client's most recent public signature key as a buffer.
    /// Used to upload a public key to the server in order to verify client's messages signature.
    ///
    /// # Arguments
    /// * `ciphersuite` - a callback to be called to perform authorization
    /// * `credential_type` - of the credential to look for
    pub async fn public_key(
        &self,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> crate::mls::Result<Vec<u8>> {
        let cb = self
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential bundle"))?;
        Ok(cb.signature_key.to_public_vec())
    }

    pub(crate) fn new_basic_credential_bundle(
        id: &ClientId,
        sc: SignatureScheme,
        backend: &MlsCryptoProvider,
    ) -> Result<CredentialBundle> {
        let (sk, pk) = backend
            .crypto()
            .signature_key_gen(sc)
            .map_err(MlsError::wrap("generating a signature key"))?;

        let signature_key = SignatureKeyPair::from_raw(sc, sk, pk);
        let credential = Credential::new_basic(id.to_vec());
        let cb = CredentialBundle {
            credential,
            signature_key,
            created_at: 0,
        };

        Ok(cb)
    }

    pub(crate) fn new_x509_credential_bundle(cert: CertificateBundle) -> Result<CredentialBundle> {
        let created_at = cert
            .get_created_at()
            .map_err(RecursiveError::mls_credential("getting credetntial created at"))?;
        let (sk, ..) = cert.private_key.into_parts();
        let chain = cert.certificate_chain;

        let kp = CertificateKeyPair::new(sk, chain.clone()).map_err(MlsError::wrap("creating certificate key pair"))?;

        let credential = Credential::new_x509(chain).map_err(MlsError::wrap("creating x509 credential"))?;

        let cb = CredentialBundle {
            credential,
            signature_key: kp.0,
            created_at,
        };
        Ok(cb)
    }

    /// Checks if a given conversation id exists locally
    pub async fn conversation_exists(&self, id: &ConversationId) -> Result<bool> {
        match self.get_raw_conversation(id).await {
            Ok(_) => Ok(true),
            Err(Error::Leaf(LeafError::ConversationNotFound(_))) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Generates a random byte array of the specified size
    pub fn random_bytes(&self, len: usize) -> crate::mls::Result<Vec<u8>> {
        use openmls_traits::random::OpenMlsRand as _;
        self.crypto_provider
            .rand()
            .random_vec(len)
            .map_err(MlsError::wrap("generating random vector"))
            .map_err(Into::into)
    }

    /// Reports whether the local KeyStore believes that it can currently close.
    ///
    /// Beware TOCTOU!
    pub async fn can_close(&self) -> bool {
        self.crypto_provider.can_close().await
    }

    /// Closes the connection with the local KeyStore
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn close(self) -> crate::mls::Result<()> {
        self.crypto_provider
            .close()
            .await
            .map_err(MlsError::wrap("closing connection with keystore"))
            .map_err(Into::into)
    }

    /// see [mls_crypto_provider::MlsCryptoProvider::reseed]
    pub async fn reseed(&self, seed: Option<EntropySeed>) -> crate::mls::Result<()> {
        self.crypto_provider
            .reseed(seed)
            .map_err(MlsError::wrap("reseeding mls backend"))
            .map_err(Into::into)
    }

    // Initializes a raw MLS keypair without an associated client ID
    // Returns a random ClientId to bind later in [Session::init_with_external_client_id]
    //
    // # Arguments
    // * `ciphersuites` - all ciphersuites this client is supposed to support
    // * `backend` - the KeyStore and crypto provider to read identities from
    //
    // # Errors
    // KeyStore and OpenMls errors can happen
    pub(crate) async fn generate_raw_keypairs(
        &self,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> Result<Vec<ClientId>> {
        self.ensure_unready().await?;
        const TEMP_KEY_SIZE: usize = 16;

        let credentials = Self::find_all_basic_credentials(backend).await?;
        if !credentials.is_empty() {
            return Err(Error::IdentityAlreadyPresent);
        }

        use openmls_traits::random::OpenMlsRand as _;
        // Here we generate a provisional, random, uuid-like random Client ID for no purpose other than database/store constraints
        let mut tmp_client_ids = Vec::with_capacity(ciphersuites.len());
        for cs in ciphersuites {
            let tmp_client_id: ClientId = backend
                .rand()
                .random_vec(TEMP_KEY_SIZE)
                .map_err(MlsError::wrap("generating random client id"))?
                .into();

            let cb = Self::new_basic_credential_bundle(&tmp_client_id, cs.signature_algorithm(), backend)?;

            let sign_kp = MlsSignatureKeyPair::new(
                cs.signature_algorithm(),
                cb.signature_key.to_public_vec(),
                cb.signature_key
                    .tls_serialize_detached()
                    .map_err(Error::tls_serialize("signature key"))?,
                tmp_client_id.clone().into(),
            );
            backend
                .key_store()
                .save(sign_kp)
                .await
                .map_err(KeystoreError::wrap("save signature keypair in keystore"))?;

            tmp_client_ids.push(tmp_client_id);
        }

        Ok(tmp_client_ids)
    }

    // Finalizes initialization using a 2-step process of uploading first a public key and then associating a new Client ID to that keypair
    //
    // # Arguments
    // * `client_id` - The client ID you have fetched from the MLS Authentication Service
    // * `tmp_ids` - The temporary random client ids generated in the previous step [Session::generate_raw_keypairs]
    // * `ciphersuites` - To initialize the Client with
    // * `backend` - the KeyStore and crypto provider to read identities from
    //
    // **WARNING**: You have absolutely NO reason to call this if you didn't call [Session::generate_raw_keypairs] first. You have been warned!
    pub(crate) async fn init_with_external_client_id(
        &self,
        client_id: ClientId,
        tmp_ids: Vec<ClientId>,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> Result<()> {
        self.ensure_unready().await?;
        // Find all the keypairs, get the ones that exist (or bail), then insert new ones + delete the provisional ones
        let stored_skp = backend
            .key_store()
            .find_all::<MlsSignatureKeyPair>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls signature keypairs"))?;

        match stored_skp.len().cmp(&tmp_ids.len()) {
            std::cmp::Ordering::Less => return Err(Error::NoProvisionalIdentityFound),
            std::cmp::Ordering::Greater => return Err(Error::TooManyIdentitiesPresent),
            _ => {}
        }

        // we verify that the supplied temporary ids are all present in the keypairs we have in store
        let all_tmp_ids_exist = stored_skp
            .iter()
            .all(|kp| tmp_ids.contains(&kp.credential_id.as_slice().into()));
        if !all_tmp_ids_exist {
            return Err(Error::NoProvisionalIdentityFound);
        }

        let identities = stored_skp.iter().zip(ciphersuites);

        self.replace_inner(SessionInner {
            id: client_id.clone(),
            identities: Identities::new(stored_skp.len()),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
        .await;

        let id = &client_id;

        for (tmp_kp, &cs) in identities {
            let scheme = tmp_kp
                .signature_scheme
                .try_into()
                .map_err(|_| Error::InvalidSignatureScheme)?;
            let new_keypair =
                MlsSignatureKeyPair::new(scheme, tmp_kp.pk.clone(), tmp_kp.keypair.clone(), id.clone().into());

            let new_credential = MlsCredential {
                id: id.clone().into(),
                credential: tmp_kp.credential_id.clone(),
                created_at: 0,
            };

            // Delete the old identity optimistically
            backend
                .key_store()
                .remove::<MlsSignatureKeyPair, &[u8]>(&new_keypair.pk)
                .await
                .map_err(KeystoreError::wrap("removing mls signature keypair"))?;

            let signature_key = SignatureKeyPair::tls_deserialize(&mut new_keypair.keypair.as_slice())
                .map_err(Error::tls_deserialize("signature key"))?;
            let cb = CredentialBundle {
                credential: Credential::new_basic(new_credential.credential.clone()),
                signature_key,
                created_at: 0, // this is fine setting a default value here, this will be set in `save_identity` to the current timestamp
            };

            // And now we save the new one
            self.save_identity(&backend.keystore(), Some(id), cs.signature_algorithm(), cb)
                .await?;
        }

        Ok(())
    }

    /// Generates a brand new client from scratch
    pub(crate) async fn generate(
        &self,
        identifier: ClientIdentifier,
        backend: &MlsCryptoProvider,
        ciphersuites: &[MlsCiphersuite],
        nb_key_package: usize,
    ) -> Result<()> {
        self.ensure_unready().await?;
        let id = identifier.get_id()?;
        let signature_schemes = ciphersuites
            .iter()
            .map(|cs| cs.signature_algorithm())
            .collect::<HashSet<_>>();
        self.replace_inner(SessionInner {
            id: id.into_owned(),
            identities: Identities::new(signature_schemes.len()),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
        .await;

        let identities = identifier.generate_credential_bundles(backend, signature_schemes)?;

        for (sc, id, cb) in identities {
            self.save_identity(&backend.keystore(), Some(&id), sc, cb).await?;
        }

        let guard = self.inner.read().await;
        let SessionInner { identities, .. } = guard.as_ref().ok_or(Error::MlsNotInitialized)?;

        if nb_key_package != 0 {
            for ciphersuite in ciphersuites.iter().copied() {
                let ciphersuite_signature_scheme = ciphersuite.signature_algorithm();
                for credential_bundle in identities.iter().filter_map(|(signature_scheme, credential_bundle)| {
                    (signature_scheme == ciphersuite_signature_scheme).then_some(credential_bundle)
                }) {
                    let credential_type = credential_bundle.credential.credential_type().into();
                    self.request_key_packages(nb_key_package, ciphersuite, credential_type, backend)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Loads the client from the keystore.
    pub(crate) async fn load(
        &self,
        backend: &MlsCryptoProvider,
        id: &ClientId,
        mut credentials: Vec<(Credential, u64)>,
        signature_schemes: HashSet<SignatureScheme>,
    ) -> Result<()> {
        self.ensure_unready().await?;
        let mut identities = Identities::new(signature_schemes.len());

        // ensures we load credentials in chronological order
        credentials.sort_by_key(|(_, timestamp)| *timestamp);

        let stored_signature_keypairs = backend
            .key_store()
            .find_all::<MlsSignatureKeyPair>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls signature keypairs"))?;

        for signature_scheme in signature_schemes {
            let signature_keypair = stored_signature_keypairs
                .iter()
                .find(|skp| skp.signature_scheme == (signature_scheme as u16));

            let signature_key = if let Some(kp) = signature_keypair {
                SignatureKeyPair::tls_deserialize(&mut kp.keypair.as_slice())
                    .map_err(Error::tls_deserialize("signature keypair"))?
            } else {
                let (private_key, public_key) = backend
                    .crypto()
                    .signature_key_gen(signature_scheme)
                    .map_err(MlsError::wrap("generating signature key"))?;
                let keypair = SignatureKeyPair::from_raw(signature_scheme, private_key, public_key.clone());
                let raw_keypair = keypair
                    .tls_serialize_detached()
                    .map_err(Error::tls_serialize("raw keypair"))?;
                let store_keypair =
                    MlsSignatureKeyPair::new(signature_scheme, public_key, raw_keypair, id.as_slice().into());
                backend
                    .key_store()
                    .save(store_keypair.clone())
                    .await
                    .map_err(KeystoreError::wrap("storing keypairs in keystore"))?;
                SignatureKeyPair::tls_deserialize(&mut store_keypair.keypair.as_slice())
                    .map_err(Error::tls_deserialize("signature keypair"))?
            };

            for (credential, created_at) in &credentials {
                match credential.mls_credential() {
                    openmls::prelude::MlsCredentialType::Basic(_) => {
                        if id.as_slice() != credential.identity() {
                            return Err(Error::WrongCredential);
                        }
                    }
                    openmls::prelude::MlsCredentialType::X509(cert) => {
                        let spk = cert
                            .extract_public_key()
                            .map_err(RecursiveError::mls_credential("extracting public key"))?
                            .ok_or(LeafError::InternalMlsError)?;
                        if signature_key.public() != spk {
                            return Err(Error::WrongCredential);
                        }
                    }
                };
                let cb = CredentialBundle {
                    credential: credential.clone(),
                    signature_key: signature_key.clone(),
                    created_at: *created_at,
                };
                identities.push_credential_bundle(signature_scheme, cb).await?;
            }
        }
        self.replace_inner(SessionInner {
            id: id.clone(),
            identities,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
        .await;
        Ok(())
    }

    /// Restore from an external [`HistorySecret`].
    pub(crate) async fn restore_from_history_secret(&self, history_secret: HistorySecret) -> Result<()> {
        self.ensure_unready().await?;

        // store the client id (with some other stuff)
        self.replace_inner(SessionInner {
            id: history_secret.client_id.clone(),
            identities: Identities::new(1),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
        .await;

        // store the key package
        let key_package = history_secret
            .key_package
            .store(&self.crypto_provider)
            .await
            .map_err(MlsError::wrap("storing key package encapsulation"))?;

        let keystore = self.crypto_provider.key_store();

        // store the credential bundle (with some other stuff)
        self.save_identity(
            keystore,
            Some(&history_secret.client_id),
            key_package.ciphersuite().signature_algorithm(),
            history_secret.credential_bundle,
        )
        .await?;

        Ok(())
    }

    async fn find_all_basic_credentials(backend: &MlsCryptoProvider) -> Result<Vec<Credential>> {
        let store_credentials = backend
            .key_store()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls credentialss"))?;
        let mut credentials = Vec::with_capacity(store_credentials.len());
        for store_credential in store_credentials.into_iter() {
            let credential = Credential::tls_deserialize(&mut store_credential.credential.as_slice())
                .map_err(Error::tls_deserialize("credential"))?;
            if !matches!(credential.credential_type(), CredentialType::Basic) {
                continue;
            }
            credentials.push(credential);
        }

        Ok(credentials)
    }

    pub(crate) async fn save_identity(
        &self,
        keystore: &Connection,
        id: Option<&ClientId>,
        signature_scheme: SignatureScheme,
        mut credential_bundle: CredentialBundle,
    ) -> Result<CredentialBundle> {
        let mut guard = self.inner.write().await;
        let SessionInner {
            id: existing_id,
            identities,
            ..
        } = guard.as_mut().ok_or(Error::MlsNotInitialized)?;

        let id = id.unwrap_or(existing_id);

        let credential = credential_bundle
            .credential
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("credential bundle"))?;
        let credential = MlsCredential {
            id: id.clone().into(),
            credential,
            created_at: 0,
        };

        let credential = keystore
            .save(credential)
            .await
            .map_err(KeystoreError::wrap("saving credential"))?;

        let sign_kp = MlsSignatureKeyPair::new(
            signature_scheme,
            credential_bundle.signature_key.to_public_vec(),
            credential_bundle
                .signature_key
                .tls_serialize_detached()
                .map_err(Error::tls_serialize("signature keypair"))?,
            id.clone().into(),
        );
        keystore.save(sign_kp).await.map_err(|e| match e {
            CryptoKeystoreError::AlreadyExists => Error::CredentialBundleConflict,
            _ => KeystoreError::wrap("saving mls signature key pair")(e).into(),
        })?;

        // set the creation date of the signature keypair which is the same for the CredentialBundle
        credential_bundle.created_at = credential.created_at;

        identities
            .push_credential_bundle(signature_scheme, credential_bundle.clone())
            .await?;

        Ok(credential_bundle)
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub async fn id(&self) -> Result<ClientId> {
        match self.inner.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { id, .. }) => Ok(id.clone()),
        }
    }

    /// Returns whether this client is E2EI capable
    pub async fn is_e2ei_capable(&self) -> bool {
        match self.inner.read().await.deref() {
            None => false,
            Some(SessionInner { identities, .. }) => identities
                .iter()
                .any(|(_, cred)| cred.credential().credential_type() == CredentialType::X509),
        }
    }

    pub(crate) async fn get_most_recent_or_create_credential_bundle(
        &self,
        backend: &MlsCryptoProvider,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Result<Arc<CredentialBundle>> {
        match ct {
            MlsCredentialType::Basic => {
                self.init_basic_credential_bundle_if_missing(backend, sc).await?;
                self.find_most_recent_credential_bundle(sc, ct).await
            }
            MlsCredentialType::X509 => self
                .find_most_recent_credential_bundle(sc, ct)
                .await
                .map_err(|e| match e {
                    Error::CredentialNotFound(_) => LeafError::E2eiEnrollmentNotDone.into(),
                    _ => e,
                }),
        }
    }

    pub(crate) async fn init_basic_credential_bundle_if_missing(
        &self,
        backend: &MlsCryptoProvider,
        sc: SignatureScheme,
    ) -> Result<()> {
        let existing_cb = self
            .find_most_recent_credential_bundle(sc, MlsCredentialType::Basic)
            .await;
        if matches!(existing_cb, Err(Error::CredentialNotFound(_))) {
            let id = self.id().await?;
            debug!(id:% = &id; "Initializing basic credential bundle");
            let cb = Self::new_basic_credential_bundle(&id, sc, backend)?;
            self.save_identity(&backend.keystore(), None, sc, cb).await?;
        }
        Ok(())
    }

    pub(crate) async fn save_new_x509_credential_bundle(
        &self,
        keystore: &Connection,
        sc: SignatureScheme,
        cb: CertificateBundle,
    ) -> Result<CredentialBundle> {
        let id = cb
            .get_client_id()
            .map_err(RecursiveError::mls_credential("getting client id"))?;
        let cb = Self::new_x509_credential_bundle(cb)?;
        self.save_identity(keystore, Some(&id), sc, cb).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::ClientId;
    use crate::test_utils::*;
    use crate::transaction_context::test_utils::EntitiesCount;
    use core_crypto_keystore::connection::{DatabaseKey, FetchFromDatabase};
    use core_crypto_keystore::entities::*;
    use mls_crypto_provider::MlsCryptoProvider;
    use wasm_bindgen_test::*;

    impl Session {
        // test functions are not held to the same documentation standard as proper functions
        #![allow(missing_docs)]

        pub async fn random_generate(
            &self,
            case: &crate::test_utils::TestContext,
            signer: Option<&crate::test_utils::x509::X509Certificate>,
            provision: bool,
        ) -> Result<()> {
            self.reset().await;
            let user_uuid = uuid::Uuid::new_v4();
            let rnd_id = rand::random::<usize>();
            let client_id = format!("{}:{rnd_id:x}@members.wire.com", user_uuid.hyphenated());
            let identity = match case.credential_type {
                MlsCredentialType::Basic => ClientIdentifier::Basic(client_id.as_str().into()),
                MlsCredentialType::X509 => {
                    let signer = signer.expect("Missing intermediate CA");
                    CertificateBundle::rand_identifier(&client_id, &[signer])
                }
            };
            let nb_key_package = if provision {
                crate::prelude::INITIAL_KEYING_MATERIAL_COUNT
            } else {
                0
            };
            let backend = self.crypto_provider.clone();
            self.generate(identity, &backend, &[case.ciphersuite()], nb_key_package)
                .await?;
            Ok(())
        }

        pub async fn find_keypackages(&self, backend: &MlsCryptoProvider) -> Result<Vec<openmls::prelude::KeyPackage>> {
            use core_crypto_keystore::CryptoKeystoreMls as _;
            let kps = backend
                .key_store()
                .mls_fetch_keypackages::<openmls::prelude::KeyPackage>(u32::MAX)
                .await
                .map_err(KeystoreError::wrap("fetching mls keypackages"))?;
            Ok(kps)
        }

        pub(crate) async fn init_x509_credential_bundle_if_missing(
            &self,
            backend: &MlsCryptoProvider,
            sc: SignatureScheme,
            cb: CertificateBundle,
        ) -> Result<()> {
            let existing_cb = self
                .find_most_recent_credential_bundle(sc, MlsCredentialType::X509)
                .await
                .is_err();
            if existing_cb {
                self.save_new_x509_credential_bundle(&backend.keystore(), sc, cb)
                    .await?;
            }
            Ok(())
        }

        pub(crate) async fn generate_one_keypackage(
            &self,
            backend: &MlsCryptoProvider,
            cs: MlsCiphersuite,
            ct: MlsCredentialType,
        ) -> Result<openmls::prelude::KeyPackage> {
            let cb = self
                .find_most_recent_credential_bundle(cs.signature_algorithm(), ct)
                .await?;
            self.generate_one_keypackage_from_credential_bundle(backend, cs, &cb)
                .await
        }

        /// Count the entities
        pub async fn count_entities(&self) -> EntitiesCount {
            let keystore = self.crypto_provider.keystore();
            let credential = keystore.count::<MlsCredential>().await.unwrap();
            let encryption_keypair = keystore.count::<MlsEncryptionKeyPair>().await.unwrap();
            let epoch_encryption_keypair = keystore.count::<MlsEpochEncryptionKeyPair>().await.unwrap();
            let enrollment = keystore.count::<E2eiEnrollment>().await.unwrap();
            let group = keystore.count::<PersistedMlsGroup>().await.unwrap();
            let hpke_private_key = keystore.count::<MlsHpkePrivateKey>().await.unwrap();
            let key_package = keystore.count::<MlsKeyPackage>().await.unwrap();
            let pending_group = keystore.count::<PersistedMlsPendingGroup>().await.unwrap();
            let pending_messages = keystore.count::<MlsPendingMessage>().await.unwrap();
            let psk_bundle = keystore.count::<MlsPskBundle>().await.unwrap();
            let signature_keypair = keystore.count::<MlsSignatureKeyPair>().await.unwrap();
            EntitiesCount {
                credential,
                encryption_keypair,
                epoch_encryption_keypair,
                enrollment,
                group,
                hpke_private_key,
                key_package,
                pending_group,
                pending_messages,
                psk_bundle,
                signature_keypair,
            }
        }
    }
    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_generate_session(case: TestContext) {
        let [alice] = case.sessions().await;
        let key = DatabaseKey::generate();
        let backend = MlsCryptoProvider::try_new_in_memory(&key).await.unwrap();
        let x509_test_chain = if case.is_x509() {
            let x509_test_chain = crate::test_utils::x509::X509TestChain::init_empty(case.signature_scheme());
            x509_test_chain.register_with_provider(&backend).await;
            Some(x509_test_chain)
        } else {
            None
        };
        backend.new_transaction().await.unwrap();
        let session = alice.session().await;
        session
            .random_generate(
                &case,
                x509_test_chain.as_ref().map(|chain| chain.find_local_intermediate_ca()),
                false,
            )
            .await
            .unwrap();
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_externally_generate_client(mut case: TestContext) {
        let [alice] = case.sessions().await;
        if !case.is_basic() {
            return;
        }
        let tmp_dir = case.tmp_dir().await;
        Box::pin(async move {
            let key = DatabaseKey::generate();
            let backend = MlsCryptoProvider::try_new(tmp_dir, &key).await.unwrap();
            backend.new_transaction().await.unwrap();
            // phase 1: generate standalone keypair
            let client_id: ClientId = b"whatever:my:client:is@world.com".to_vec().into();
            let alice = alice.session().await;
            alice.reset().await;
            // TODO: test with multi-ciphersuite. Tracking issue: WPB-9601
            let handles = alice
                .generate_raw_keypairs(&[case.ciphersuite()], &backend)
                .await
                .unwrap();

            let mut identities = backend
                .keystore()
                .find_all::<MlsSignatureKeyPair>(EntityFindParams::default())
                .await
                .unwrap();

            assert_eq!(identities.len(), 1);

            let prov_identity = identities.pop().unwrap();

            // Make sure we are actually returning the clientId
            // TODO: test with multi-ciphersuite. Tracking issue: WPB-9601
            let prov_client_id: ClientId = prov_identity.credential_id.as_slice().into();
            assert_eq!(&prov_client_id, handles.first().unwrap());

            // phase 2: pretend we have a new client ID from the backend, and try to init the client this way
            alice
                .init_with_external_client_id(client_id.clone(), handles.clone(), &[case.ciphersuite()], &backend)
                .await
                .unwrap();

            // Make sure both client id and PK are intact
            assert_eq!(alice.id().await.unwrap(), client_id);
            let cb = alice
                .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
                .await
                .unwrap();
            let client_id: ClientId = cb.credential().identity().into();
            assert_eq!(&client_id, handles.first().unwrap());
        })
        .await
    }
}
