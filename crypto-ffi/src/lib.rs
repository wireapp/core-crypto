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
    ($self:ident => $body:block or throw $err_type:ty) => {{
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                let result = { $body };
                match result {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        $self.proteus_last_error_code.store(e.proteus_error_code(), std::sync::atomic::Ordering::Relaxed);
                        Err(e)
                    }
                }
            } else {
                return <$err_type>::Err(CryptoError::ProteusSupportNotEnabled("proteus".into()).into());
            }
        }
    }};
    ($body:block or throw $err_type:ty) => {{
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                $body
            } else {
                return <$err_type>::Err(CryptoError::ProteusSupportNotEnabled("proteus".into()).into());
            }
        }
    }};

    ($body:block) => {
        proteus_impl!($body or throw ::std::result::Result<_, _>)
    };

    ($self:ident => $body:block) => {
        proteus_impl!($self => $body or throw ::std::result::Result<_, _>)
    };
}

cfg_if::cfg_if! {
    if #[cfg(target_family = "wasm")] {
        mod wasm;
        pub use self::wasm::*;
    } else {
        mod generic;
        pub use self::generic::*;


        #[cfg(feature = "mobile")]
        uniffi_macros::include_scaffolding!("CoreCrypto");
    }
}

#[cfg(doc)]
pub mod bindings;
