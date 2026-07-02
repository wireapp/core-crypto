pub use rstest::*;
pub use rstest_reuse::{self, *};

mod common;

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::common::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_storage_types)]
    pub async fn can_create_and_init_store(_context: KeystoreTestContext) {
        // just runs the setup and teardown, which creates the store and wipes it afterward.
    }

    #[cfg(target_os = "ios")]
    #[cfg_attr(not(target_os = "unknown"), macro_rules_attribute::apply(smol_macros::test))]
    async fn can_preserve_wal_compat_for_ios() {
        let store1 = setup("ios-wal-compat", false).await;
        drop(store1);
        let store2 = setup("ios-wal-compat-2", true).await;
        drop(store2);
        let _store1 = setup("ios-wal-compat", false).await;
    }
}
