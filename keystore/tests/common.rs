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

#![allow(dead_code)]

use core_crypto_keystore::CryptoKeystore;

const TEST_ENCRYPTION_KEY: &str = "test1234";

fn get_file_path(name: &str) -> String {
    format!("./test.{}.edb", name)
}

pub fn setup(name: &str) -> core_crypto_keystore::CryptoKeystore {
    let mut store = CryptoKeystore::open_with_key(get_file_path(name), TEST_ENCRYPTION_KEY).unwrap();
    store.run_migrations().unwrap();
    store
}

pub fn teardown(store: CryptoKeystore) {
    store.delete_database_but_please_be_sure().unwrap();
}
