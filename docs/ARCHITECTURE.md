# CoreCrypto Architecture

## Components

* Keystore: Encrypted Keystore powered by SQLCipher on all platforms except WASM. WASM uses an IndexedDB-backed, encrypted store with AES256-GCM
* MlsProvider: RustCrypto + Keystore MLS provider
* CoreCrypto: Abstracts MLS & Proteus in a unified API (Proteus isn't supported as of 0.2.0)
* CoreCryptoFFI: FFI bindings for C, iOS, Android and WASM

----------

## Keystore

### Purpose

The keystore's purpose is to securely store the Client's keying material on-device.

As such, its requirements are:

* Some sort of persistent data storage layer
* Encryption at-rest of the persisted keying material
* Compatibility with target libraries storage traits (i.e. OpenMLS & Proteus)

### Implementation

On most platforms, the keystore relies on [SQLCipher](https://www.zetetic.net/sqlcipher/) to persist & encrypt data
On WebAssembly (TS/JS bindings for the web & electron), the keystore calls into the browser's `IndexedDB` to persist data and AES256-GCM to encrypt data (via `RustCrypto`).

### Status

* The keystore's persistence on WASM isn't finished yet.
* The keystore's implementation of encryption at rest on WASM isn't validated nor audited so paper cuts expected.


----------

## MlsProvider

### Purpose

Interfacing with the `OpenMLSCryptoProvider` trait to allow `OpenMLS` to call into our keystore

### Implementation

Just implementing a single trait and instanciating the relevant structs, namely the crypto provider from `RustCrypto` and our `Keystore`

### Status

* The provider currently forces an in-memory keystore for WASM. This will be disabled once the persistence works.

----------

## CoreCrypto

### Purpose

Implements and abstracts differences between protocols (MLS, Proteus), and also erases the API inconsistences in those APIs.
CoreCrypto basically aims at being as simple as possible, erasing protocol specifics and manipulating "layman" entities.


### Implementation

Based around a `Central` concept (see `MlsCentral` in `lib.rs`), where a single object holds ownership over what is needed at runtime.

A couple of other concepts are used:

* Central: Represents the entry point of the instantiated state of the library once the necessary initialization is done. Takes care of finding/creating the local Client, restoring persisted conversations etc.
* Client: Represents the local client (i.e. user device) that has the ability to produce local keying material.
* Member: Represents a remote client (i.e. conversation member) without the ability to produce keying material.
* Conversation: Represents a conversation group (i.e. n `Session`s on Proteus, and a `MlsGroup` on OpenMLS) in which the local Client is taking part.

----------

## CoreCryptoFFI

### Purpose

Allows other programming languages and platforms to embed and interact with `CoreCrypto`

### Implementation

* For iOS and Android, [UniFFI](https://github.com/mozilla/uniffi-rs) is used to produce the relevant Kotlin and Swift bindings
* For JS/TS, a WebAssembly binary is produced using [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen) and [wasm-pack](https://rustwasm.github.io/wasm-pack/)
* For other platforms, there's currently an (incomplete) C-API. Please note that its safety guarantees have not been tested thoroughly.
