use zeroize::Zeroize;

use crate::{
    CryptoKeystoreResult, Sha256Hash,
    traits::{EntityBase, EntityGetBorrowed as _, KeyType, OwnedKeyType, PrimaryKey, SearchableEntity as _},
};

/// This type exists so that we can efficiently search for the children of a given group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::From, derive_more::Into, derive_more::AsRef)]
pub struct ParentGroupId<'a>(&'a [u8]);

impl<'a> KeyType for ParentGroupId<'a> {
    fn bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        self.0.into()
    }
}

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
    #[entity(unencrypted_wasm)]
    pub parent_id: Option<Vec<u8>>,
}

impl PersistedMlsGroup {
    /// Get the parent group of this group.
    pub async fn parent_group(
        &self,
        conn: &mut <Self as EntityBase>::ConnectionType,
    ) -> CryptoKeystoreResult<Option<Self>> {
        let Some(parent_id) = self.parent_id.as_deref() else {
            return Ok(None);
        };

        Self::get_borrowed(conn, parent_id).await
    }

    /// Get all children of this group.
    pub async fn child_groups(
        &self,
        conn: &mut <Self as EntityBase>::ConnectionType,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let parent_id = self.id.as_slice();
        Self::find_all_matching(conn, &parent_id.into()).await
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

/// Typesafe reference to a conversation id.
///
/// [`MlsPendingMessage`]s have no distinct primary key; they must always be accessed via
/// collective accessors. This type makes that possible.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, derive_more::AsRef, derive_more::Deref, derive_more::From,
)]
pub struct ConversationId<'a>(&'a [u8]);

impl<'a> KeyType for ConversationId<'a> {
    fn bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        self.0.into()
    }
}

/// [`MlsPendingMessage`]s have no distinct primary key;
/// they must always be accessed via the [`SearchableEntity`][crate::traits::SearchableEntity] and
/// [`DeletableBySearchKey`][crate::traits::DeletableBySearchKey] traits.
///
/// However the keystore's support of internal transactions demands a primary key:
/// ultimately that structure boils down to `Map<CollectionName, Map<PrimaryKey, Entity>>`, so anything other
/// than a full primary key just breaks things.
///
/// We use `xxhash3` as a fast hash implementation, and take 128 bits of hash to ensure
/// that the chance of a collision is effectively 0.
pub struct MlsPendingMessagePrimaryKey(u128);

impl From<&MlsPendingMessage> for MlsPendingMessagePrimaryKey {
    fn from(value: &MlsPendingMessage) -> Self {
        let mut hasher = twox_hash::xxhash3_128::Hasher::new();
        hasher.write(&value.foreign_id);
        hasher.write(&value.message);
        Self(hasher.finish_128())
    }
}

impl KeyType for MlsPendingMessagePrimaryKey {
    fn bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        self.0.to_be_bytes().as_slice().to_owned().into()
    }
}

impl OwnedKeyType for MlsPendingMessagePrimaryKey {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let array = bytes.try_into().ok()?;
        Some(Self(u128::from_be_bytes(array)))
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

/// This type exists so that we can efficiently search for credentials by a variety of metrics at the database level.
///
/// This includes some but not all of the fields in `core_crypto::CredentialFindFilters`: those that are actually stored
/// in the database, and do not require deserializing the `credential` field.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct CredentialFindFilters<'a> {
    /// Hash of public key to search for.
    pub hash: Option<Sha256Hash>,
    /// Public key to search for
    pub public_key: Option<&'a [u8]>,
    /// Session / Client id to search for
    pub session_id: Option<&'a [u8]>,
    /// Ciphersuite to search for
    pub ciphersuite: Option<u16>,
    /// unix timestamp (seconds) of point of earliest validity to search for
    pub earliest_validity: Option<u64>,
}

impl<'a> KeyType for CredentialFindFilters<'a> {
    fn bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        postcard::to_stdvec(self)
            .expect("serializing these filters cannot fail")
            .into()
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
