// For now while we're just adding new entity traits, these imports will be unused.
// In the future they should be reexported at the crate level and this module should become private.
// It only exists for the moment to ensure that everything compiles.
#![expect(unused)]

mod entity;
mod entity_base;
mod entity_database_mutation;
mod fetch_from_database;
mod item_encryption;
mod key_type;
mod unique_entity;

pub use entity::{BorrowPrimaryKey, Entity};
pub use entity_base::EntityBase;
pub use entity_database_mutation::{EntityDatabaseMutation, EntityDeleteBorrowed};
pub use fetch_from_database::FetchFromDatabase;
pub use item_encryption::{DecryptData, Decryptable, Decrypting, EncryptData, Encrypting};
pub use key_type::KeyType;
pub use unique_entity::{UniqueEntity, UniqueEntityExt, UniqueEntityImplementationHelper};
