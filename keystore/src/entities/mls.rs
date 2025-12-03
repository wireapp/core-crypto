use zeroize::Zeroize;

use crate::{CryptoKeystoreResult, Entity, EntityBase, connection::TransactionWrapper};

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
    #[id(hex, column = "id_hex")]
    pub id: Vec<u8>,
    pub state: Vec<u8>,
    pub parent_id: Option<Vec<u8>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait PersistedMlsGroupExt: Entity
where
    <Self as Entity>::PrimaryKey: Eq,
{
    fn parent_id(&self) -> Option<&<Self as Entity>::PrimaryKey>;

    async fn parent_group(
        &self,
        conn: &mut <Self as EntityBase>::ConnectionType,
    ) -> CryptoKeystoreResult<Option<Self>> {
        let Some(parent_id) = self.parent_id() else {
            return Ok(None);
        };

        <Self as Entity>::get(conn, parent_id).await
    }

    async fn child_groups(&self, conn: &mut <Self as EntityBase>::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        let self_id = self.primary_key();

        // What a great use for in-db searching: WPB-20844
        let mut entities = <Self as Entity>::load_all(conn).await?;
        entities.retain(|entity| entity.parent_id().is_some_and(|parent_id| *parent_id == self_id));
        Ok(entities)
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

/// Entity representing a buffered message
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct MlsPendingMessage {
    #[sensitive]
    pub foreign_id: Vec<u8>,
    pub message: Vec<u8>,
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
    // we'd ideally just call this field `conversation_id`, but as of right now the
    // Entity macro does not yet support id columns not named `id`
    #[id(hex, column = "conversation_id_hex")]
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
    pub id: Vec<u8>,
    #[sensitive]
    pub credential: Vec<u8>,
    pub created_at: u64,
    pub ciphersuite: u16,
    #[sensitive]
    pub public_key: Vec<u8>,
    #[sensitive]
    pub secret_key: Vec<u8>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait MlsCredentialExt: Entity {
    async fn delete_by_credential(tx: &TransactionWrapper<'_>, credential: Vec<u8>) -> CryptoKeystoreResult<()>;
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
    #[id(hex, column = "id_hex")]
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
    #[id(hex, column = "keypackage_ref_hex")]
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
    #[id]
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
    #[id]
    pub distribution_point: String,
    pub content: Vec<u8>,
}
