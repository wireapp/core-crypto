//! FFI bindings for core-crypto.
//!
//! Actual implementation happens in the `core-crypto` crate. This crate is about setting up all the necessary
//! annotations, wrappers, etc necessary to package those types, items, and methods for FFI via uniffi and wasm-bindgen.

// No public item in this crate should lack documentation.
#![cfg_attr(not(test), deny(missing_docs))]

uniffi::setup_scaffolding!("core_crypto_ffi");

mod bundles;
mod bytes_wrapper;
mod ciphersuite;
mod client_id;
mod configuration;
mod core_crypto;
mod core_crypto_context;
mod credential_type;
mod crl;
mod database;
mod decrypted_message;
mod e2ei;
mod ephemeral;
mod error;
mod identity;
mod metadata;
mod proteus;

pub use bundles::{
    commit::CommitBundle, group_info::GroupInfoBundle, proteus_auto_prekey::ProteusAutoPrekeyBundle,
    welcome::WelcomeBundle,
};
pub use ciphersuite::{ciphersuite_default, ciphersuite_from_u16, Ciphersuite};
pub use client_id::ClientId;
pub use configuration::{ConversationConfiguration, CustomConfiguration, WirePolicy};
#[cfg(not(target_family = "wasm"))]
pub use core_crypto::{command::transaction_helper::TransactionHelper, core_crypto_new};
pub use core_crypto::{
    command::CoreCryptoCommand,
    conversation::ConversationId,
    epoch_observer::EpochObserver,
    logger::{set_logger, set_max_log_level, CoreCryptoLogLevel, CoreCryptoLogger},
    mls_transport::{MlsTransport, MlsTransportData, MlsTransportResponse},
    CoreCryptoFfi,
};
pub(crate) use core_crypto::{
    conversation::{conversation_id_coerce_maybe_arc, ConversationIdMaybeArc},
    e2ei::identities::UserIdentities,
};
pub use core_crypto_context::CoreCryptoContext;
pub use credential_type::CredentialType;
pub use crl::CrlRegistration;
pub use database::{
    in_memory_database, migrate_database_key_type_to_bytes, open_database, update_database_key, Database, DatabaseKey,
};
pub use decrypted_message::{BufferedDecryptedMessage, DecryptedMessage};
pub use e2ei::{
    acme_challenge::AcmeChallenge, acme_directory::AcmeDirectory, enrollment::E2eiEnrollment,
    new_acme_authz::NewAcmeAuthz, new_acme_order::NewAcmeOrder, E2eiConversationState,
};
pub use ephemeral::{core_crypto_history_client, HistorySecret};
#[cfg(feature = "proteus")]
pub use error::proteus::ProteusError;
pub use error::{mls::MlsError, CoreCryptoError, CoreCryptoResult};
pub use identity::{
    wire::{DeviceStatus, WireIdentity},
    x509::X509Identity,
};
pub use metadata::{build_metadata, version, BuildMetadata};
