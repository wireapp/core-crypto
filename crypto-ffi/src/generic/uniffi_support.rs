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

#[allow(dead_code)]
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

use core_crypto::prelude::*;

pub fn init_with_path_and_key<'a, 'b>(
    path: &'a str,
    key: &'a str,
    client_id: &'a str,
    entropy_seed: Option<Vec<u8>>,
) -> CryptoResult<std::sync::Arc<crate::CoreCrypto<'b>>> {
    Ok(std::sync::Arc::new(crate::CoreCrypto::new(
        path,
        key,
        client_id,
        entropy_seed,
    )?))
}

pub fn version() -> String {
    VERSION.to_string()
}

impl crate::UniffiCustomTypeConverter for core_crypto::prelude::ClientId {
    type Builtin = Vec<u8>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_vec()
    }
}

impl crate::UniffiCustomTypeConverter for core_crypto::prelude::ConversationId {
    type Builtin = Vec<u8>;
    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.to_vec())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj
    }
}
