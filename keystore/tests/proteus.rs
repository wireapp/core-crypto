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

#[cfg(feature = "proteus-keystore")]
mod tests {
    use crate::common::*;
    use core_crypto_keystore::{
        entities::{EntityBase, ProteusPrekey}, MissingKeyErrorKind,
    };
    use proteus_wasm::keys::{PreKey, PreKeyId};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn proteus_entities_have_correct_error_kinds() {
        assert_eq!(
            ProteusPrekey::to_missing_key_err_kind(),
            MissingKeyErrorKind::ProteusPrekey
        );
    }

    #[apply(all_storage_types)]
    #[wasm_bindgen_test]
    pub async fn can_add_read_delete_prekey_traits(mut context: KeystoreTestContext) {
        use core_crypto_keystore::CryptoKeystoreProteus as _;
        use proteus_traits::PreKeyStore as _;

        let store = context.store_mut();

        let prekey_id = PreKeyId::new(28273u16);
        let prekey = PreKey::new(prekey_id);

        store
            .proteus_store_prekey(prekey_id.value(), &prekey.serialise().unwrap())
            .await
            .unwrap();

        assert!(store.prekey(prekey_id.value()).await.unwrap().is_some());

        proteus_traits::PreKeyStore::remove(store, prekey.key_id.value())
            .await
            .unwrap();
    }
}
