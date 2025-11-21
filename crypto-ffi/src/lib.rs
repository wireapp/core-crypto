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
mod credential;
mod credential_ref;
mod credential_type;
mod crl;
mod database;
mod decrypted_message;
mod e2ei;
mod ephemeral;
mod error;
mod identity;
mod key_package;
mod metadata;
mod proteus;
mod signature_scheme;

pub use bundles::{
    commit::CommitBundle, group_info::GroupInfoBundle, proteus_auto_prekey::ProteusAutoPrekeyBundle,
    welcome::WelcomeBundle,
};
pub use ciphersuite::{Ciphersuite, ciphersuite_default, ciphersuite_from_u16};
pub use client_id::ClientId;
pub use configuration::{ConversationConfiguration, CustomConfiguration, WirePolicy};
pub use core_crypto::{
    CoreCryptoFfi,
    command::CoreCryptoCommand,
    conversation::ConversationId,
    epoch_observer::EpochObserver,
    logger::{CoreCryptoLogLevel, CoreCryptoLogger, set_logger, set_max_log_level},
    mls_transport::{MlsTransport, MlsTransportData, MlsTransportResponse},
};
#[cfg(not(target_family = "wasm"))]
pub use core_crypto::{command::transaction_helper::TransactionHelper, core_crypto_new};
pub(crate) use core_crypto::{
    conversation::{ConversationIdMaybeArc, conversation_id_coerce_maybe_arc},
    e2ei::identities::UserIdentities,
};
pub use core_crypto_context::CoreCryptoContext;
pub use credential::Credential;
#[cfg(not(target_family = "wasm"))]
pub use credential::credential_basic;
pub use credential_ref::CredentialRef;
pub use credential_type::CredentialType;
pub use crl::CrlRegistration;
pub use database::{
    Database, DatabaseKey, in_memory_database, migrate_database_key_type_to_bytes, open_database, update_database_key,
};
pub use decrypted_message::{BufferedDecryptedMessage, DecryptedMessage};
pub use e2ei::{
    E2eiConversationState, acme_challenge::AcmeChallenge, acme_directory::AcmeDirectory, enrollment::E2eiEnrollment,
    new_acme_authz::NewAcmeAuthz, new_acme_order::NewAcmeOrder,
};
pub use ephemeral::{HistorySecret, core_crypto_history_client};
#[cfg(feature = "proteus")]
pub use error::proteus::ProteusError;
pub use error::{CoreCryptoError, CoreCryptoResult, mls::MlsError};
pub use identity::{
    wire::{DeviceStatus, WireIdentity},
    x509::X509Identity,
};
pub use key_package::{Keypackage, KeypackageRef};
pub(crate) use key_package::{KeypackageMaybeArc, KeypackageRefMaybeArc};
pub use metadata::{BuildMetadata, build_metadata, version};
pub use signature_scheme::SignatureScheme;
