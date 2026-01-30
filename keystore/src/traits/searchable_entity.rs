use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    traits::{Entity, EntityDatabaseMutation, KeyType},
};

/// Entities implementing `SearchableEntity` have a distinct search key which
/// can produce multiple items.
///
/// Effectively, this is a way at the type-system level to implement `WHERE`-clause
/// searching.
///
/// This trait can potentially be implemented multiple times per entity, in case there are
/// a variety of interesting searches.
///
/// While the trait design does not require it, implementations should take advantage of
/// database features such as indices to ensure that searching by a search key is efficient.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait SearchableEntity<SearchKey: KeyType>: Entity {
    /// Find all entities matching the search key.
    ///
    /// The specific meaning of "matching" the search key will depend on the entity in question,
    /// but generally the search key will have one or more fields which effectively act
    /// as a `WHERE`-clause for the search.
    async fn find_all_matching(
        conn: &mut Self::ConnectionType,
        search_key: &SearchKey,
    ) -> CryptoKeystoreResult<Vec<Self>>;

    /// `true` when this entity instance matches the search key.
    ///
    /// The specific meaning of "matching" the search key will depend on the entity in question,
    /// but generally the search key will have one or more fields which must equal some fields
    /// on the entity.
    fn matches(&self, search_key: &SearchKey) -> bool;
}

/// Entities implementing `DeletableBySearchKey` can be deleted by that search key.
///
/// This is a way at the type-system level to implement `WHERE`-clause deletion.
///
/// This trait can potentially be implemented multiple times per entity, in case there
/// are a variety of interesting searches.
///
/// While the trait design does not require it, implementations should take advantage of
/// database features such as indices to ensure that deletion by a search key is efficient.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait DeletableBySearchKey<'a, SearchKey: KeyType>:
    SearchableEntity<SearchKey> + EntityDatabaseMutation<'a>
{
    /// Delete all entities matching the search key.
    ///
    /// The specific meaning of "matching" the search key will depend on the entity
    /// in question, it should always have the same meaning for this implementation
    /// and the equivalent [`SearchableEntity`] implementation.
    async fn delete_all_matching(tx: &Self::Transaction, search_key: &SearchKey) -> CryptoKeystoreResult<()>;
}
