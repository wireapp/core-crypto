//! This module contains code that is used to execute workload in rust between migrations. Any version number
//! corresponds to the migration AFTER which it is run.

pub(super) mod v16;
pub(super) mod v18;
pub(super) mod v19;
pub(super) mod v28;
pub(super) mod v31;
pub(super) mod v34;
