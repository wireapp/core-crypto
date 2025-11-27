// For now while we're just adding new entity traits, these imports will be unused.
// In the future they should be reexported at the crate level and this module should become private.
// It only exists for the moment to ensure that everything compiles.
#![expect(unused)]

mod entity;
mod entity_base;
#[cfg(target_family = "wasm")]
mod entity_encryption_ext;
mod entity_transaction_ext;
mod fetch_from_database;
mod key_type;
mod unique_entity;

pub use entity::{Entity, EntityGetBorrowed};
pub use entity_base::EntityBase;
#[cfg(target_family = "wasm")]
pub use entity_encryption_ext::EntityEncryptionExt;
pub use entity_transaction_ext::{EntityTransactionDeleteBorrowed, EntityTransactionExt};
pub use fetch_from_database::FetchFromDatabase;
pub use key_type::KeyType;
pub use unique_entity::{UniqueEntity, UniqueEntityExt};
