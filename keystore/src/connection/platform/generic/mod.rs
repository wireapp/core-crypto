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

use std::ops::Deref;

use crate::CryptoKeystoreResult;
use crate::connection::{DatabaseConnection, DatabaseConnectionRequirements};
use async_lock::{Mutex, MutexGuard};
use blocking::unblock;
use rusqlite::{Transaction, functions::FunctionFlags};

refinery::embed_migrations!("src/connection/platform/generic/migrations");

pub struct TransactionWrapper<'conn> {
    transaction: Transaction<'conn>,
}

impl TransactionWrapper<'_> {
    // this is async just to conform with the wasm impl
    pub(crate) async fn commit_tx(self) -> CryptoKeystoreResult<()> {
        // It's really not ideal to do potentially-heavy IO such as committing a transaction
        // within the async context, because Rust async depends on inserting cooperative yields
        // in appropriate places, and blocking functions simply do not have those. This is going
        // to bind up the whole async executor every time we try to commit the transaction, for
        // the entire duration of the execution of the transaction.
        //
        // We can't even do `unblock(|| transaction.commit())` here becase `Transaction: !Send`.
        //
        // Hopefully either WPB-14326, WPB-14327, or WPB-15766 will open a path to a unified
        // async database which can give us better performance characteristics than this.
        self.transaction.commit().map_err(Into::into)
    }
}

impl<'conn> From<Transaction<'conn>> for TransactionWrapper<'conn> {
    fn from(transaction: Transaction<'conn>) -> Self {
        TransactionWrapper { transaction }
    }
}

impl<'conn> Deref for TransactionWrapper<'conn> {
    type Target = Transaction<'conn>;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

// SAFETY: This is **UNSAFE**. Transactions are intentionally `!Send`,
// and we do nothing to provide guarantees which would make them safe to share between threads.
// See https://github.com/rusqlite/rusqlite/issues/697 for discussion on this.
//
// Unfortunately, everything breaks for now if we simply remove this. This is going to take
// non-trivial work to fix. See https://wearezeta.atlassian.net/browse/WPB-15767.
unsafe impl Send for TransactionWrapper<'_> {}
// SAFETY: This is **UNSAFE**. See above.
unsafe impl Sync for TransactionWrapper<'_> {}

#[derive(Debug)]
pub struct SqlCipherConnection {
    conn: Mutex<rusqlite::Connection>,
    path: String,
}

// SAFETY: An `Arc` is unnecessary as `SqlCipherConnection: !Clone`, and there is a `Mutex`
// internally which ensures unique access.
unsafe impl Send for SqlCipherConnection {}
// SAFETY: An `Arc` is unnecessary as `SqlCipherConnection: !Clone`, and there is a `Mutex`
// internally which ensures unique access.
unsafe impl Sync for SqlCipherConnection {}

impl SqlCipherConnection {
    fn init_with_key(path: &str, key: &str) -> CryptoKeystoreResult<Self> {
        #[allow(unused_mut)]
        let mut conn = rusqlite::Connection::open(path)?;
        cfg_if::cfg_if! {
            if #[cfg(feature = "log-queries")] {
                fn log_query(q: &str) {
                    log::info!("{}", q);
                }

                conn.trace(Some(log_query));
            }
        }

        conn.pragma_update(None, "key", key)?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(feature = "ios-wal-compat")]
        Self::handle_ios_wal_compat(&conn, path)?;

        // Enable WAL journaling mode
        conn.pragma_update(None, "journal_mode", "wal")?;

        // Disable FOREIGN KEYs - The 2 step blob writing process invalidates foreign key checks unfortunately
        conn.pragma_update(None, "foreign_keys", "OFF")?;

        let conn = Mutex::new(conn);

        let mut conn = Self {
            path: path.into(),
            conn,
        };
        conn.run_migrations()?;

        Ok(conn)
    }

    fn init_with_key_in_memory(_path: &str, key: &str) -> CryptoKeystoreResult<Self> {
        #[allow(unused_mut)]
        let mut conn = rusqlite::Connection::open("")?;
        cfg_if::cfg_if! {
            if #[cfg(feature = "log-queries")] {
                fn log_query(q: &str) {
                    log::info!("{}", q);
                }

                conn.trace(Some(log_query));
            }
        }
        conn.pragma_update(None, "key", key)?;

        // Disable FOREIGN KEYs - The 2 step blob writing process invalidates foreign key checks unfortunately
        conn.pragma_update(None, "foreign_keys", "OFF")?;

        let conn = Mutex::new(conn);

        let mut conn = Self { path: "".into(), conn };

        // Need to run migrations also in memory to make sure expected tables exist.
        conn.run_migrations()?;

        Ok(conn)
    }

    pub async fn conn(&self) -> MutexGuard<rusqlite::Connection> {
        self.conn.lock().await
    }

    pub fn conn_blocking(&self) -> MutexGuard<rusqlite::Connection> {
        self.conn.lock_blocking()
    }

    pub async fn wipe(self) -> CryptoKeystoreResult<()> {
        if self.path.is_empty() {
            return Ok(());
        }

        let path = self.path.clone();

        unblock(|| self.close()).await?;
        async_fs::remove_file(&path).await?;
        Ok(())
    }

    fn close(self) -> CryptoKeystoreResult<()> {
        let conn = self.conn.into_inner();
        conn.close().map_err(|(_, e)| e.into())
    }

    /// To prevent iOS from killing backgrounded apps using a WAL-journaled file,
    /// we need to leave the first 32 bytes as plaintext, this way, iOS can see the
    /// `SQLite Format 3\0` magic bytes and identify the file as a SQLite database
    /// and when it does so, it treats this file "specially" and avoids killing the app
    /// when doing background work
    /// See more: https://github.com/sqlcipher/sqlcipher/issues/255
    #[cfg(feature = "ios-wal-compat")]
    fn handle_ios_wal_compat(conn: &rusqlite::Connection, path: &str) -> CryptoKeystoreResult<()> {
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
        const LEGACY_ACCT_NAME: &str = "keystore_salt";
        const WIRE_SERVICE_NAME: &str = "wire.com";
        use security_framework::passwords as ios_keychain;
        use sha2::Digest as _;

        #[allow(non_upper_case_globals)]
        // This is to make sure that macOS/iOS keychain items that we create (see above for the *why*)
        // are accessible in the background through a `kSecAttrAccessibleAfterFirstUnlock` attribute
        // More on the topic: https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility
        // More here on the specific attribute: https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlock?language=swift
        fn mark_password_as_accessible(key: &str) -> security_framework::base::Result<()> {
            use core_foundation::{
                base::TCFType,
                dictionary::CFDictionary,
                string::{CFString, CFStringRef},
            };
            use security_framework::base::Error;
            use security_framework_sys::{
                base::errSecSuccess,
                item::{kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword},
            };

            // Import raw symbols from CoreFoundation
            //
            // SAFETY: we promise that these symbols will appear when we link this
            unsafe extern "C" {
                pub static kSecAttrAccessibleAfterFirstUnlock: CFStringRef;
                pub static kSecAttrAccessible: CFStringRef;
            }

            macro_rules! wrap_under_get_rule {
                ($external_ref:expr) => {
                    // SAFETY: The method `CFString::wrap_under_get_rule` is required by rustc to be marked as unsafe
                    // because accessing any static item via FFI is intrinsically unsafe. For this reason, we can't
                    // just create a safe wrapper function here; rustc immediately flags it with an [E0133] because it
                    // needs that FFI static item to be its parameter.
                    //
                    // There isn't safety documentation anywhere in the CFString or TCFType documentation, and
                    // the implementation does only [basic checks], so we can assume that the main property we
                    // need to uphold is "the reference is not null".
                    //
                    // [E0133]: https://doc.rust-lang.org/stable/error_codes/E0133.html
                    // [basic checks]: https://github.com/servo/core-foundation-rs/blob/core-foundation-v0.10.0/core-foundation/src/lib.rs#L91-L95
                    unsafe { CFString::wrap_under_get_rule($external_ref) }
                };
            }

            // Create a query that matches a:
            let query_params = CFDictionary::from_CFType_pairs(&[
                // Class GenericPassword
                (
                    wrap_under_get_rule!(kSecClass),
                    wrap_under_get_rule!(kSecClassGenericPassword).as_CFType(),
                ),
                // with Service = "wire.com"
                (
                    wrap_under_get_rule!(kSecAttrService),
                    CFString::from(WIRE_SERVICE_NAME).as_CFType(),
                ),
                // Holding account name = `key` (in the following form: `keystore_salt_[sha256(file_path)]`)
                (wrap_under_get_rule!(kSecAttrAccount), CFString::from(key).as_CFType()),
            ]);

            // And now we ask to update the following properties:
            let payload_params = CFDictionary::from_CFType_pairs(&[(
                // Keychain Accessibility setting
                // See: https://developer.apple.com/documentation/security/ksecattraccessible
                wrap_under_get_rule!(kSecAttrAccessible),
                // Set to AccessibleAfterFirstUnlock (i.e. is accessible after the first post-boot unlock)
                wrap_under_get_rule!(kSecAttrAccessibleAfterFirstUnlock).as_CFType(),
            )]);

            // Update the item in the keychain
            //
            // SAFETY: As before, the main source of unsafety here appears to simply be that this is an FFI function
            // and nobody has constructed a safe wrapper aroud it. And sure, we can't trust the safety properties that
            // external code has. But on the other hand, we can't not call this function. So the unsafe block should be fine.
            match unsafe {
                security_framework_sys::keychain_item::SecItemUpdate(
                    query_params.as_concrete_TypeRef(),
                    payload_params.as_concrete_TypeRef(),
                )
            } {
                errSecSuccess => Ok(()),
                err => Err(Error::from_code(err)),
            }
        }

        let mut path_hash = sha2::Sha256::default();
        path_hash.update(path.as_bytes());
        let keychain_key = format!("{LEGACY_ACCT_NAME}_{}", hex::encode(&path_hash.finalize()));

        // Old version compat fix
        if let Ok(salt) = ios_keychain::get_generic_password(WIRE_SERVICE_NAME, LEGACY_ACCT_NAME) {
            ios_keychain::set_generic_password(WIRE_SERVICE_NAME, &keychain_key, salt.as_slice())?;
            ios_keychain::delete_generic_password(WIRE_SERVICE_NAME, LEGACY_ACCT_NAME)?;
        }

        match ios_keychain::get_generic_password(WIRE_SERVICE_NAME, &keychain_key) {
            Ok(salt) => {
                conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(salt)))?;
            }
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {
                let salt = conn.pragma_query_value(None, "cipher_salt", |r| r.get::<_, String>(0))?;
                let mut bytes = [0u8; 16];
                hex::decode_to_slice(salt, &mut bytes)
                    .map_err(|e| crate::CryptoKeystoreError::HexSaltDecodeError(e))?;

                ios_keychain::set_generic_password(WIRE_SERVICE_NAME, &keychain_key, &bytes)?;
            }
            Err(e) => return Err(e.into()),
        }

        // We're doing it here to make sure we retroactively mark database salts as accessible
        mark_password_as_accessible(&keychain_key)?;

        const CIPHER_PLAINTEXT_BYTES: u32 = 32;
        conn.pragma_update(None, "cipher_plaintext_header_size", CIPHER_PLAINTEXT_BYTES)?;
        conn.pragma_update(None, "user_version", 2u32)?;

        Ok(())
    }

    fn run_migrations(&mut self) -> CryptoKeystoreResult<()> {
        let mut conn = self.conn_blocking();
        conn.create_scalar_function("sha256_blob", 1, FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
            let input_blob = ctx.get::<Vec<u8>>(0)?;
            Ok(crate::sha256(&input_blob))
        })?;
        let report = migrations::runner().run(&mut *conn).map_err(Box::new)?;
        if let Some(version) = report.applied_migrations().iter().map(|m| m.version()).max() {
            conn.pragma_update(None, "schema_version", version)?;
        }

        Ok(())
    }
}

impl DatabaseConnectionRequirements for SqlCipherConnection {}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'a> DatabaseConnection<'a> for SqlCipherConnection {
    type Connection = MutexGuard<'a, rusqlite::Connection>;

    async fn open(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        let key = key.to_string();
        Ok(unblock(move || Self::init_with_key(&name, &key)).await?)
    }

    async fn open_in_memory(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        let key = key.to_string();
        Ok(unblock(move || Self::init_with_key_in_memory(&name, &key)).await?)
    }

    async fn close(self) -> CryptoKeystoreResult<()> {
        unblock(|| self.close()).await
    }

    async fn wipe(self) -> CryptoKeystoreResult<()> {
        self.wipe().await?;
        Ok(())
    }
}
