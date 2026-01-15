use zeroize::{Zeroize, ZeroizeOnDrop};

// This trait import is required for the `Entity` macro to work properly.
// Apparently its use in the macro is hidden from the code which checks whether
// it's being used.
// Also we can't use an `expect` attribute here because of the unfulfilled expectation,
// which is proper as we do in fact use it, so... it's a bit of a mess.
#[allow(unused_imports)]
use crate::traits::EntityBase as _;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    traits::{BorrowPrimaryKey, Entity, KeyType, OwnedKeyType, PrimaryKey},
};

/// Entity representing a persisted `MlsGroup`
#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
#[entity(collection_name = "mls_groups")]
#[sensitive]
pub struct PersistedMlsGroup {
    #[entity(id, hex, column = "id_hex")]
    pub id: Vec<u8>,
    pub state: Vec<u8>,
    pub parent_id: Option<Vec<u8>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait PersistedMlsGroupExt: Entity + BorrowPrimaryKey
where
    for<'a> &'a <Self as BorrowPrimaryKey>::BorrowedPrimaryKey: KeyType,
{
    fn parent_id(&self) -> Option<&[u8]>;

    async fn parent_group(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Option<Self>> {
        let Some(parent_id) = self.parent_id() else {
            return Ok(None);
        };

        let parent_id = OwnedKeyType::from_bytes(parent_id)
            .ok_or(CryptoKeystoreError::InvalidPrimaryKeyBytes(Self::COLLECTION_NAME))?;
        Self::get(conn, &parent_id).await
    }

    async fn child_groups(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        // A perfect opportunity for refactoring in WPB-22945
        // when we do that, we no longer need varying implementations according to wasm or not,
        // so both `parent_group` and this method should just be implemented directly on `PersistedMlsGroup`.
        let entities = Self::load_all(conn).await?;

        // for whatever reason rustc needs each of these distinct bindings to prove to itself that the lifetimes work
        // out
        let id = self.borrow_primary_key();
        let id = id.bytes();
        let id = id.as_ref();

        Ok(entities
            .into_iter()
            .filter(|entity| entity.parent_id().map(|parent_id| parent_id == id).unwrap_or_default())
            .collect())
    }
}

/// Entity representing a temporarily persisted `MlsGroup`
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct PersistedMlsPendingGroup {
    #[sensitive]
    pub id: Vec<u8>,
    #[sensitive]
    pub state: Vec<u8>,
    #[sensitive]
    pub parent_id: Option<Vec<u8>>,
    pub custom_configuration: Vec<u8>,
}

/// [`MlsPendingMessage`]s have no distinct primary key;
/// they must always be accessed via [`MlsPendingMessage::find_all_by_conversation_id`] and
/// cleaned up with [`MlsPendingMessage::delete_by_conversation_id`]
///
/// However, we have to fake a primary key type in order to support
/// `KeystoreTransaction::remove_pending_messages_by_conversation_id`. Additionally we need the same one in WASM, where
/// it's necessary for item-level encryption.
///
/// This implementation is fairly inefficient and hopefully temporary. But it at least implements the correct semantics.
#[derive(ZeroizeOnDrop)]
pub struct MlsPendingMessagePrimaryKey {
    pub(crate) foreign_id: Vec<u8>,
    message: Vec<u8>,
}

impl MlsPendingMessagePrimaryKey {
    /// Construct a partial mls pending message primary key from only the conversation id.
    ///
    /// This does not in fact uniquely identify a single pending message--it should always uniquely
    /// identify exactly 0 pending messages--but we have to have it so that we can search and delete
    /// by conversation id within transactions.
    pub(crate) fn from_conversation_id(conversation_id: impl AsRef<[u8]>) -> Self {
        Self {
            foreign_id: conversation_id.as_ref().to_owned(),
            message: Vec::new(),
        }
    }
}

impl From<&MlsPendingMessage> for MlsPendingMessagePrimaryKey {
    fn from(value: &MlsPendingMessage) -> Self {
        Self {
            foreign_id: value.foreign_id.clone(),
            message: value.message.clone(),
        }
    }
}

impl KeyType for MlsPendingMessagePrimaryKey {
    fn bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        // run-length encoding: 32 bits of size for each field, followed by the field
        let fields = [&self.foreign_id, &self.message];
        let mut key = Vec::with_capacity(
            ((u32::BITS / u8::BITS) as usize * fields.len()) + self.foreign_id.len() + self.message.len(),
        );
        for field in fields {
            key.extend((field.len() as u32).to_le_bytes());
            key.extend(field.as_slice());
        }
        key.into()
    }
}

impl OwnedKeyType for MlsPendingMessagePrimaryKey {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // run-length decoding: 32 bits of size for each field, followed by the field
        let (len, bytes) = bytes.split_at_checked(4)?;
        let len = u32::from_le_bytes(len.try_into().ok()?);
        let (foreign_id, bytes) = bytes.split_at_checked(len as _)?;

        let (len, bytes) = bytes.split_at_checked(4)?;
        let len = u32::from_le_bytes(len.try_into().ok()?);
        let (message, bytes) = bytes.split_at_checked(len as _)?;

        bytes.is_empty().then(|| Self {
            foreign_id: foreign_id.to_owned(),
            message: message.to_owned(),
        })
    }
}

/// Entity representing a buffered message
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct MlsPendingMessage {
    #[sensitive]
    pub foreign_id: Vec<u8>,
    pub message: Vec<u8>,
}

impl PrimaryKey for MlsPendingMessage {
    type PrimaryKey = MlsPendingMessagePrimaryKey;
    fn primary_key(&self) -> Self::PrimaryKey {
        self.into()
    }
}

/// Entity representing a buffered commit.
///
/// There should always exist either 0 or 1 of these in the store per conversation.
/// Commits are buffered if not all proposals they reference have yet been received.
///
/// We don't automatically zeroize on drop because the commit data is still encrypted at this point;
/// it is not risky to leave it in memory.
#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[entity(collection_name = "mls_buffered_commits")]
pub struct StoredBufferedCommit {
    #[entity(id, hex, column = "conversation_id_hex")]
    #[sensitive]
    conversation_id: Vec<u8>,
    commit_data: Vec<u8>,
}

impl StoredBufferedCommit {
    /// Create a new `Self` from conversation id and the commit data.
    pub fn new(conversation_id: Vec<u8>, commit_data: Vec<u8>) -> Self {
        Self {
            conversation_id,
            commit_data,
        }
    }

    pub fn conversation_id(&self) -> &[u8] {
        &self.conversation_id
    }

    pub fn commit_data(&self) -> &[u8] {
        &self.commit_data
    }

    pub fn into_commit_data(self) -> Vec<u8> {
        self.commit_data
    }
}

/// Entity representing a persisted `Credential`
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct StoredCredential {
    /// Note: this is not a unique identifier, but the session id this credential belongs to.
    #[sensitive]
    pub session_id: Vec<u8>,
    #[sensitive]
    pub credential: Vec<u8>,
    pub created_at: u64,
    pub ciphersuite: u16,
    #[sensitive]
    pub public_key: Vec<u8>,
    #[sensitive]
    pub private_key: Vec<u8>,
}

/// Entity representing a persisted `HpkePrivateKey` (related to LeafNode Private keys that the client is aware of)
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
#[sensitive]
pub struct StoredHpkePrivateKey {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

/// Entity representing a persisted `HpkePrivateKey` (related to LeafNode Private keys that the client is aware of)
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
#[sensitive]
pub struct StoredEncryptionKeyPair {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

/// Entity representing a list of [StoredEncryptionKeyPair]
#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
#[entity(collection_name = "mls_epoch_encryption_keypairs")]
pub struct StoredEpochEncryptionKeypair {
    #[entity(hex, column = "id_hex")]
    pub id: Vec<u8>,
    #[sensitive]
    pub keypairs: Vec<u8>,
}

/// Entity representing a persisted `SignatureKeyPair`
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
#[sensitive]
pub struct StoredPskBundle {
    pub psk_id: Vec<u8>,
    pub psk: Vec<u8>,
}

/// Entity representing a persisted `KeyPackage`
#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
#[entity(collection_name = "mls_keypackages")]
pub struct StoredKeypackage {
    #[entity(id, hex, column = "keypackage_ref_hex")]
    pub keypackage_ref: Vec<u8>,
    #[sensitive]
    pub keypackage: Vec<u8>,
}

/// Entity representing an enrollment instance used to fetch a x509 certificate and persisted when
/// context switches and the memory it lives in is about to be erased
#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
#[entity(collection_name = "e2ei_enrollment", no_upsert)]
pub struct StoredE2eiEnrollment {
    pub id: Vec<u8>,
    pub content: Vec<u8>,
}

/// OIDC refresh token used in E2EI
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct E2eiRefreshToken {
    pub content: Vec<u8>,
}

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct E2eiAcmeCA {
    pub content: Vec<u8>,
}

#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
pub struct E2eiIntermediateCert {
    // key to identify the CA cert; Using a combination of SKI & AKI extensions concatenated like so is suitable:
    // `SKI[+AKI]`
    #[entity(id)]
    pub ski_aki_pair: String,
    pub content: Vec<u8>,
}

#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
pub struct E2eiCrl {
    #[entity(id)]
    pub distribution_point: String,
    pub content: Vec<u8>,
}
