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

mod ciphersuite;
mod client_id;
mod credential_type;
mod crl;
mod error;
mod metadata;

#[cfg(target_family = "wasm")]
pub(crate) use ciphersuite::lower_ciphersuites;
pub use ciphersuite::{Ciphersuite, Ciphersuites};
pub use client_id::{ClientId, FfiClientId};
pub use credential_type::CredentialType;
pub use crl::{CrlRegistration, NewCrlDistributionPoints};
#[cfg(feature = "proteus")]
pub use error::proteus::ProteusError;
pub use error::{CoreCryptoResult, core_crypto::CoreCryptoError, mls::MlsError};
#[cfg(target_family = "wasm")]
pub use error::{WasmCryptoResult, internal::InternalError};
pub use metadata::{BuildMetadata, build_metadata, version};
