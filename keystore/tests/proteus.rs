pub use rstest::*;
pub use rstest_reuse::{self, *};

mod common;

#[cfg(feature = "proteus-keystore")]
mod tests {
    use crate::common::*;
    use core_crypto_keystore::{
        MissingKeyErrorKind,
        entities::{EntityBase, ProteusPrekey},
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
