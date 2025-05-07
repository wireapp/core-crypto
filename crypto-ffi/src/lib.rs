#[cfg(doc)]
pub mod bindings;

#[cfg(not(target_family = "wasm"))]
uniffi::setup_scaffolding!("core_crypto_ffi");

mod bundles;
mod ciphersuite;
mod client_id;
mod configuration;
mod core_crypto;
mod core_crypto_context;
mod credential_type;
mod crl;
mod database_key;
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
pub use ciphersuite::{Ciphersuite, Ciphersuites};
pub use client_id::{ClientId, FfiClientId};
pub use configuration::{ConversationConfiguration, CustomConfiguration, WirePolicy};
pub use core_crypto::{
    CoreCrypto,
    command::CoreCryptoCommand,
    e2ei::E2eiDumpedPkiEnv,
    epoch_observer::EpochObserver,
    logger::{CoreCryptoLogLevel, CoreCryptoLogger},
    mls_transport::{MlsTransport, MlsTransportResponse},
};
#[cfg(not(target_family = "wasm"))]
pub use core_crypto::{
    command::transaction_helper::TransactionHelper,
    core_crypto_deferred_init, core_crypto_new,
    logger::{set_logger, set_logger_only, set_max_log_level},
};
pub(crate) use core_crypto::{conversation::ConversationId, e2ei::identities::UserIdentities};
pub use core_crypto_context::CoreCryptoContext;
pub use credential_type::CredentialType;
pub use crl::{CrlRegistration, NewCrlDistributionPoints};
pub use database_key::{DatabaseKey, migrate_db_key_type_to_bytes};
pub use decrypted_message::{BufferedDecryptedMessage, DecryptedMessage};
pub use e2ei::{
    E2eiConversationState, acme_challenge::AcmeChallenge, acme_directory::AcmeDirectory, enrollment::E2eiEnrollment,
    new_acme_authz::NewAcmeAuthz, new_acme_order::NewAcmeOrder,
};
pub use ephemeral::HistorySecret;
#[cfg(not(target_family = "wasm"))]
pub use ephemeral::core_crypto_history_client;
#[cfg(feature = "proteus")]
pub use error::proteus::ProteusError;
pub use error::{CoreCryptoError, CoreCryptoResult, mls::MlsError};
pub use identity::{
    wire::{DeviceStatus, WireIdentity},
    x509::X509Identity,
};
pub use metadata::{BuildMetadata, build_metadata, version};
