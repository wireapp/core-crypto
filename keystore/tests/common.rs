#![allow(dead_code)]

use core_crypto_keystore::CryptoKeystore;

const TEST_ENCRYPTION_KEY: &str = "test1234";

fn get_file_path(name: &str) -> String {
    format!("./test.{}.edb", name)
}

pub fn setup(name: &str) -> core_crypto_keystore::CryptoKeystore {
    let mut store =
        CryptoKeystore::open_with_key(get_file_path(name), TEST_ENCRYPTION_KEY).unwrap();
    store.run_migrations().unwrap();
    store
}

pub fn teardown(store: CryptoKeystore) {
    store.delete_database_but_please_be_sure().unwrap();
}
