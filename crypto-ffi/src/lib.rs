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

macro_rules! proteus_impl {
    ($errcode_dest:expr => $body:block or throw $err_type:ty) => {{
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                #[allow(clippy::redundant_closure_call)]
                let result = (async move { $body }).await;

                cfg_if::cfg_if! {
                    if #[cfg(target_family = "wasm")] {
                        if let Err(CoreCryptoError(WasmError::CryptoError(e))) = &result {
                            let errcode = e.proteus_error_code();
                            if errcode > 0 {
                                let mut ec = $errcode_dest.write().await;
                                *ec = errcode;
                            }
                        }

                        result
                    } else {
                        if let Err(CoreCryptoError::CryptoError { error: e }) = &result {
                            let errcode = e.proteus_error_code();
                            if errcode > 0 {
                                $errcode_dest.store(errcode, std::sync::atomic::Ordering::SeqCst);
                            }
                        }

                        CoreCryptoResult::Ok(result?)
                    }
                }
            } else {
                return <$err_type>::Err(core_crypto::CryptoError::ProteusSupportNotEnabled("proteus".into()).into());
            }
        }
    }};
    ($body:block or throw $err_type:ty) => {{
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                $body
            } else {
                return <$err_type>::Err(core_crypto::CryptoError::ProteusSupportNotEnabled("proteus".into()).into());
            }
        }
    }};

    ($body:block) => {
        proteus_impl!($body or throw ::std::result::Result<_, _>)
    };

    ($errcode_dest:expr => $body:block) => {
        proteus_impl!($errcode_dest => $body or throw ::std::result::Result<_, _>)
    };
}

cfg_if::cfg_if! {
    if #[cfg(target_family = "wasm")] {
        mod wasm;
        pub use self::wasm::*;
    } else {
        uniffi::setup_scaffolding!("core_crypto_ffi");

        mod generic;
        pub use self::generic::*;
    }
}

#[cfg(doc)]
pub mod bindings;
