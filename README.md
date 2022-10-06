# Wire CoreCrypto

[![Wire logo](https://github.com/wireapp/wire/blob/master/assets/header-small.png?raw=true)](https://wire.com/jobs/)

This repository is part of the source code of Wire. You can find more information at [wire.com](https://wire.com) or by contacting opensource@wire.com.

You can find the published source code at [github.com/wireapp/wire](https://github.com/wireapp/wire).

For licensing information, see the attached LICENSE file and the list of third-party licenses at [wire.com/legal/licenses/](https://wire.com/legal/licenses/).

No license is granted to the Wire trademark and its associated logos, all of which will continue to be owned exclusively by Wire Swiss GmbH. Any use of the Wire trademark and/or its associated logos is expressly prohibited without the express prior written consent of Wire Swiss GmbH.

## Parts

* CoreCrypto: Abstracts MLS & Proteus in a unified API
* CoreCryptoFFI: FFI bindings for iOS, Android and WASM
* Keystore: Encrypted Keystore powered by SQLCipher on all platforms except WASM. WASM uses an IndexedDB-backed, encrypted store with AES256-GCM
* MlsProvider: RustCrypto + Keystore MLS provider

See [ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Usage

### [API Docs](https://wireapp.github.io/core-crypto/core_crypto/)

## Building

### General Requirements

- rust: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
- cargo-make: [https://sagiegurari.github.io/cargo-make/](https://sagiegurari.github.io/cargo-make/)

### Android

Install Android SDK and Build-Tools for API level 30+

NOTE: If you are building on macOS you'll need to setup $ANDROID_SDK_ROOT path variable manually:
```ignore
export ANDROID_SDK_ROOT=~/Android/Sdk
```
Install android rust targets
```ignore
rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi i686-linux-android
```

### iOS

Install Xcode & it's commandline tools: [https://developer.apple.com/xcode/](https://developer.apple.com/xcode/)

Install iOS rust targets

```ignore
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
```

### MacOS

Install macOS rust targets
```ignore
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
```

### Linux

If cross-compiling from macOS you'll need install: [https://github.com/messense/homebrew-macos-cross-toolchains](https://github.com/messense/homebrew-macos-cross-toolchains)

Install linux targets

```ignore
rustup target add x86_64-unknown-linux-gnu
```

### WASM

* Install [wasm-pack](https://rustwasm.github.io/wasm-pack/)
* Install the wasm32-unknown-unknown toolchain `rustup target add wasm32-unknown-unknown`
* Install node.js (recommended way is via [Volta](https://volta.sh/))

### Bindings

Build bindings for Android, JVM, iOS and WASM

```ignore
cd crypto-ffi 

# builds bindings and targets for the JVM (macOS / Linux)
cargo make "copy-jvm-resources"

# builds bindings and targets for Android
cargo make "copy-android-resources"

# builds iOS framework
cargo make "create-swift-package"

# builds wasm binary
cargo make wasm
```

## Publishing

### Changelog

* Update <CHANGELOG.tpl> accordingly
* run `cargo xtask documentation changelog` to update <CHANGELOG.md> with the git-conventional history

### Android / JVM

You can publish the JVM and Android bindings to maven using gradle after you'be build the corresponding target.

```ignore
cd kotlin
./gradlew :jvm:publishToMavenLocal
./gradlew :android:publishToMavenLocal
```

### JS / WASM

Given that you are logged in NPM and can publish to `@wireapp/core-crypto`, you can just `npm publish` to push a new version
