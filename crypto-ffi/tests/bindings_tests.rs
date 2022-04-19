#[cfg(feature = "mobile")]
uniffi_macros::build_foreign_language_testcases!(
    ["src/CoreCrypto.udl",],
    [
        "bindings/kt/wire/CoreCrypto.test.kt",
        "bindings/swift/Tests/CoreCryptoTests/CoreCryptoTests.swift"
    ]
);
