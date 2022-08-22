# Wire CoreCrypto FFI

FFI bindings for CoreCrypto

Targets:

* iOS (via [UniFFI](https://github.com/mozilla/uniffi-rs))
* Android (via [UniFFI](https://github.com/mozilla/uniffi-rs))
* WASM (via [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen))

## Limitations

### iOS

The package can be imported with Swift package manager, but due to limitations from SPM it has to
be imported locally. Before using it, the package must be built. That can be done with `cargo make create-swift-package`.
This will generate the binary lib needed to iOS simulators and devices. When/if a package registry is created
or if a dependency can be declared as a zip, a proper release will be generated.
