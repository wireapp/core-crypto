#[macro_export]
macro_rules! proteus_impl {
    ($body:block or throw $err_type:ty) => {
        {
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                #[allow(clippy::redundant_closure_call)]
                $body
            } else {
                return <$err_type>::Err(core_crypto::Error::FeatureDisabled("proteus").into());
            }
        }
        }
    };
    ($body:block) => {
        proteus_impl!($body or throw ::std::result::Result<_, _>)
    };
}

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
mod error;
mod identity;
mod metadata;

pub use bundles::{
    commit::CommitBundle, group_info::GroupInfoBundle, proposal::ProposalBundle,
    proteus_auto_prekey::ProteusAutoPrekeyBundle, welcome::WelcomeBundle,
};
#[cfg(target_family = "wasm")]
pub(crate) use ciphersuite::lower_ciphersuites;
pub use ciphersuite::{Ciphersuite, Ciphersuites};
pub use client_id::{ClientId, FfiClientId};
pub use configuration::{ConversationConfiguration, CustomConfiguration, WirePolicy};
pub use core_crypto::CoreCrypto;
pub use core_crypto::logger::{CoreCryptoLogLevel, CoreCryptoLogger};
#[cfg(not(target_family = "wasm"))]
pub use core_crypto::logger::{set_logger, set_logger_only, set_max_log_level};
pub use core_crypto::mls_transport::{MlsTransport, MlsTransportResponse};
#[cfg(not(target_family = "wasm"))]
pub use core_crypto::{core_crypto_deferred_init, core_crypto_new};
pub use credential_type::CredentialType;
pub use crl::{CrlRegistration, NewCrlDistributionPoints};
pub use database_key::{DatabaseKey, migrate_db_key_type_to_bytes};
pub use decrypted_message::{BufferedDecryptedMessage, DecryptedMessage};
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
