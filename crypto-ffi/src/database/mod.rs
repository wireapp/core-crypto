//! This module contains the [Database] struct acting as a core crypto keystore and the [DatabaseKey] used to open it.

mod key;

pub(super) use key::*;
pub use key::{DatabaseKey, migrate_database_key_type_to_bytes, update_database_key};
