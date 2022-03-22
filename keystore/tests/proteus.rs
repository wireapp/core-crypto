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

mod common;

#[cfg(all(test, feature = "proteus-keystore"))]
pub mod tests {
    use crate::common::*;
    use proteus::keys::{PreKey, PreKeyId};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    pub fn can_add_read_delete_prekey() {
        use core_crypto_keystore::CryptoKeystoreProteus as _;
        let mut store = setup("proteus");
        let prekey_id = PreKeyId::new(28273);
        let prekey = PreKey::new(prekey_id);
        store.store_prekey(&prekey).unwrap();
        use proteus::session::PreKeyStore as _;
        let _ = store.prekey(prekey_id).unwrap().unwrap();
        let _ = proteus::session::PreKeyStore::remove(&mut store, prekey.key_id).unwrap();
        teardown(store);
    }
}
