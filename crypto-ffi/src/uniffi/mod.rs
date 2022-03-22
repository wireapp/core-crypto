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

uniffi_macros::include_scaffolding!("CoreCrypto");

mod uniffi_support;

use std::collections::HashMap;

use core_crypto::prelude::*;
pub use core_crypto::CryptoError;

pub fn init_with_path_and_key(path: &str, key: &str, client_id: &str) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    Ok(std::sync::Arc::new(CoreCrypto::new(path, key, client_id)?))
}

pub fn version() -> String {
    crate::VERSION.to_string()
}
