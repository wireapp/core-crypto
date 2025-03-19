// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

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
mod decrypted_message;
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
pub use core_crypto::CoreCrypto;
pub use core_crypto::logger::{CoreCryptoLogLevel, CoreCryptoLogger};
#[cfg(not(target_family = "wasm"))]
pub use core_crypto::logger::{set_logger, set_logger_only, set_max_log_level};
pub use core_crypto::mls_transport::{MlsTransport, MlsTransportResponse};
#[cfg(not(target_family = "wasm"))]
pub use core_crypto::{core_crypto_deferred_init, core_crypto_new};
pub use credential_type::CredentialType;
pub use crl::{CrlRegistration, NewCrlDistributionPoints};
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
