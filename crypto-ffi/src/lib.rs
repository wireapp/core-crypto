cfg_if::cfg_if! {
    if #[cfg(target_family = "wasm")] {
        mod wasm;
        pub use self::wasm::*;
    } else {
        mod generic;
        pub use self::generic::*;
    }
}

#[cfg(doc)]
pub mod bindings;

#[cfg(not(target_family = "wasm"))]
uniffi::setup_scaffolding!("core_crypto_ffi");

mod bundles;
mod ciphersuite;
mod client_id;
mod configuration;
mod core_crypto;
mod credential_type;
mod crl;
mod database_key;
mod decrypted_message;
mod e2ei;
mod error;
mod identity;
mod metadata;
mod proteus;

pub use bundles::{
    commit::CommitBundle, group_info::GroupInfoBundle, proposal::ProposalBundle,
    proteus_auto_prekey::ProteusAutoPrekeyBundle, welcome::WelcomeBundle,
};
#[cfg(target_family = "wasm")]
pub(crate) use ciphersuite::lower_ciphersuites;
pub use ciphersuite::{Ciphersuite, Ciphersuites};
pub use client_id::{ClientId, FfiClientId};
pub use configuration::{ConversationConfiguration, CustomConfiguration, WirePolicy};
pub(crate) use core_crypto::conversation::ConversationId;
pub use core_crypto::{
    CoreCrypto,
    e2ei::E2eiDumpedPkiEnv,
    logger::{CoreCryptoLogLevel, CoreCryptoLogger},
    mls_transport::{MlsTransport, MlsTransportResponse},
};
#[cfg(not(target_family = "wasm"))]
pub use core_crypto::{
    core_crypto_deferred_init, core_crypto_new,
    logger::{set_logger, set_logger_only, set_max_log_level},
};
pub use credential_type::CredentialType;
pub use crl::{CrlRegistration, NewCrlDistributionPoints};
pub use database_key::{DatabaseKey, migrate_db_key_type_to_bytes};
pub use decrypted_message::{BufferedDecryptedMessage, DecryptedMessage};
pub use e2ei::{
    E2eiConversationState, acme_challenge::AcmeChallenge, acme_directory::AcmeDirectory, enrollment::E2eiEnrollment,
    new_acme_authz::NewAcmeAuthz, new_acme_order::NewAcmeOrder,
};
#[cfg(feature = "proteus")]
pub use error::proteus::ProteusError;
pub use error::{CoreCryptoResult, core_crypto::CoreCryptoError, mls::MlsError};
#[cfg(target_family = "wasm")]
pub use error::{WasmCryptoResult, internal::InternalError};
pub use identity::{
    wire::{DeviceStatus, WireIdentity},
    x509::X509Identity,
};
pub use metadata::{BuildMetadata, build_metadata, version};
