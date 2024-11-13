# Wire CoreCrypto FFI

FFI bindings for CoreCrypto

Targets:

- iOS (via [UniFFI](https://github.com/mozilla/uniffi-rs))
- Android (via [UniFFI](https://github.com/mozilla/uniffi-rs))
- WASM (via [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen))

## Tests

- for WASM are [here](bindings/js/test/CoreCrypto.test.ts)
- for Kotlin are [here](bindings/jvm/src/test) but are not executed by the CI
- there are no Swift tests