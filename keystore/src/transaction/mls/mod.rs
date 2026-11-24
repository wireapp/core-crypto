//! openmls's storage, on top of our tables.
//!
//! openmls passes keys and values as generic `Serialize`/`Deserialize` types. Values are stored as their postcard
//! serialization. Keys which the schema stores as bytes elsewhere, such as a group id that is also a conversation
//! id, are stored as their raw bytes (see [`convert`](crate::connection::convert)), so the two line up.
//!
//! - [`storage`]: the [`Storage`] type, and the ways it reaches the tables.
//! - [`provider`]: openmls's `StorageProvider`, implemented on [`Storage`].
//! - [`group_state`]: converting a group's state between openmls's types and the bytes [`group_state_sql`] stores.
//! - [`group_state_sql`]: the SQL for a group's state.

mod group_state;
mod group_state_sql;
mod provider;
mod storage;
#[cfg(test)]
mod tests;

pub(crate) use self::storage::MigrationStorage;
pub use self::storage::{MlsReadConnection, MlsStorage, Storage};
