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

pub fn version() -> String {
    VERSION.to_string()
}

impl crate::UniffiCustomTypeConverter for crate::ClientId {
    type Builtin = Vec<u8>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(Self(core_crypto::prelude::ClientId::from(val)))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.to_vec()
    }
}

impl crate::UniffiCustomTypeConverter for crate::Ciphersuite {
    type Builtin = u16;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        CiphersuiteName::try_from(val)
            .map(Into::into)
            .map_err(|_| CryptoError::ImplementationError.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        (&obj.0).into()
    }
}

impl crate::UniffiCustomTypeConverter for crate::Ciphersuites {
    type Builtin = Vec<u16>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        val.iter().try_fold(Self(vec![]), |mut acc, c| -> uniffi::Result<Self> {
            let cs = CiphersuiteName::try_from(*c)
                .map(Into::into)
                .map_err(|_| CryptoError::ImplementationError)?;
            acc.0.push(cs);
            Ok(acc)
        })
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.into_iter().map(|c| (&c).into()).collect()
    }
}
