use zeroize::Zeroize;

use crate::{
    CryptoKeystoreResult,
    traits::{EntityBase, EntityGetBorrowed as _, KeyType, SearchableEntity as _},
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
