use core_foundation::{
    base::TCFType,
    dictionary::CFDictionary,
    string::{CFString, CFStringRef},
};
use security_framework::base::Error;
use security_framework::passwords as ios_keychain;
use security_framework_sys::{
    base::errSecSuccess,
    item::{kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword},
};
use sha2::Digest as _;

use crate::CryptoKeystoreResult;

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const WIRE_SERVICE_NAME: &str = "wire.com";

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

// To prevent iOS from killing backgrounded apps using a WAL-journaled file,
// we need to leave the first 32 bytes as plaintext, this way, iOS can see the
// `SQLite Format 3\0` magic bytes and identify the file as a SQLite database
// and when it does so, it treats this file "specially" and avoids killing the app
// when doing background work
// See more: https://github.com/sqlcipher/sqlcipher/issues/255
pub fn handle_ios_wal_compat(conn: &rusqlite::Connection, path: &str) -> CryptoKeystoreResult<()> {
    let digest = sha2::Sha256::digest(path);
    let keychain_key = format!("keystore_salt_{}", hex::encode(digest));

    match ios_keychain::get_generic_password(WIRE_SERVICE_NAME, &keychain_key) {
        Ok(salt) => {
            conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(salt)))?;
        }
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {
            let salt = conn.pragma_query_value(None, "cipher_salt", |r| r.get::<_, String>(0))?;
            let mut bytes = [0u8; 16];
            hex::decode_to_slice(salt, &mut bytes).map_err(|e| crate::CryptoKeystoreError::HexSaltDecodeError(e))?;

            ios_keychain::set_generic_password(WIRE_SERVICE_NAME, &keychain_key, &bytes)?;
        }
        Err(e) => return Err(e.into()),
    }

    // We're doing it here to make sure we retroactively mark database salts as accessible
    mark_password_as_accessible(&keychain_key)?;

    // Do not encrypt first 32 bytes of the database, so the header can be read by iOS.
    conn.pragma_update(None, "cipher_plaintext_header_size", 32)?;

    // This is needed to trigger a write of the first database page, which is necessary due
    // to us changing cipher_plaintext_header_size.
    conn.pragma_update(None, "user_version", 2u32)?;

    Ok(())
}

#[allow(non_upper_case_globals)]
// This is to make sure that macOS/iOS keychain items that we create (see above for the *why*)
// are accessible in the background through a `kSecAttrAccessibleAfterFirstUnlock` attribute
// More on the topic: https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility
// More here on the specific attribute: https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlock?language=swift
fn mark_password_as_accessible(key: &str) -> security_framework::base::Result<()> {
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
