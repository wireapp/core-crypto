//! This module contains all behaviour of a transaction context connected to end-to-end identity.

pub(crate) mod conversation_state;
pub mod enabled;
mod error;
mod init_certificates;

pub use error::{Error, Result};
