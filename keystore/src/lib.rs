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

mod error;
pub use error::*;

pub mod connection;
pub mod entities;

cfg_if::cfg_if! {
    if #[cfg(feature = "mls-keystore")] {
        mod mls;
        pub use self::mls::CryptoKeystoreMls;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "proteus-keystore")] {
        mod proteus;
        pub use self::proteus::CryptoKeystoreProteus;
    }
}

#[cfg(feature = "memory-cache")]
#[allow(dead_code)]
const LRU_CACHE_CAP: usize = 100;

pub use connection::Connection;
