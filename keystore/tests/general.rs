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

pub use rstest::*;
pub use rstest_reuse::{self, *};

mod common;

#[cfg(test)]
pub mod tests {

    use crate::common::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_storage_types)]
    #[wasm_bindgen_test]
    pub async fn can_create_and_init_store(store: CryptoKeystore) {
        let store = store.await;
        teardown(store).await;
    }

    #[cfg(feature = "ios-wal-compat")]
    #[cfg_attr(not(target_family = "wasm"), async_std::test)]
    async fn can_preserve_wal_compat_for_ios() {
        let store1 = setup("ios-wal-compat", false).await;
        store1.close().await.unwrap();
        let store2 = setup("ios-wal-compat-2", true).await;
        store2.close().await.unwrap();
        let store1 = setup("ios-wal-compat", false).await;
    }
}
