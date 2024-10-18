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

> [!important]
> If you are building on macOS you'll need to setup `$ANDROID_SDK_ROOT` path variable manually:
> ```ignore
> export ANDROID_SDK_ROOT=~/Android/Sdk
> ```

Install android rust targets:
```ignore
rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi i686-linux-android
```
Build:
```ignore
cd crypto-ffi
cargo make android
cd bindings
./gradlew android:build
```

### iOS

Install Xcode & its command-line tools: [https://developer.apple.com/xcode/](https://developer.apple.com/xcode/).

Install iOS rust targets:
```ignore
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
```

Build:
```ignore
cd crypto-ffi
cargo make ios
# Additionally, if you want to export a .XCFramework:
cargo make ios-create-xcframework
```

### MacOS

Install macOS rust targets:
```ignore
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

### Linux

> [!note]
> If cross-compiling from macOS, you'll need to install
> [https://github.com/messense/homebrew-macos-cross-toolchains](https://github.com/messense/homebrew-macos-cross-toolchains).

Install Linux targets:
```ignore
rustup target add x86_64-unknown-linux-gnu
```

### WASM

Make sure you have all prerequisites:
* Install [wasm-pack](https://rustwasm.github.io/wasm-pack/)
* Install the `wasm32-unknown-unknown` toolchain: `rustup target add wasm32-unknown-unknown`
* Install node.js (recommended way is via [Volta](https://volta.sh/))
* Install Bun (follow the instructions on [Bun's website](https://bun.sh/))

Build:
```ignore
cd crypto-ffi
cargo make wasm
```

### Bindings

Build bindings for Android, JVM, iOS and WASM

```ignore
cd crypto-ffi

# builds bindings and targets for the JVM (macOS / Linux)
cargo make jvm

# builds bindings and targets for Android
cargo make android

# builds iOS framework
cargo make ios-create-xcframework

# builds wasm binary & TS bindings
cargo make wasm
```

## Testing

### General testing

```ignore
# Install cargo-nextest if you haven't done so, it yields some substantial speedup
cargo install cargo-nextest
cargo nextest run
```

#### Run core crypto tests on WASM target

If you haven't already, install the target and wasm-pack:

```ignore
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

If you want to test for chrome, [get chromedriver](https://getwebdriver.com/chromedriver) or the webdriver for the
browser you want to test for, respectively.

Then, to run tests for a crate in the workspace do

```ignore
wasm-pack test --headless --chrome ./<crate-folder-to-test>
```

#### Addendum: testing all ciphersuites

> [!warning]
> This takes quite a while.

```ignore
cargo nextest run --features test-all-cipher
```

### Platform-specific testing

### Kotlin/Android

* Take the steps to compile for Kotlin/Android
* Then:
```ignore
cd crypto-ffi/bindings
./gradlew test
```

### Swift/iOS

*No E2E testing is available as of now on Swift.*

### WASM/Web

* Take the steps to compile for WASM/Web
* Then:
```ignore
cd crypto-ffi
bun test
```

## Benchmarks
There are benches implemented in [`crypto/benches`](crypto/benches/) for several operations on mls groups with varying sizes or proteus.
Parameters like minimum or maximum group sizes and step sizes are defined in [`crypto/benches/utils/mod.rs`](crypto/benches/utils/mod.rs).

### Executing Benches
To execute the benches, e.g. for creating commits, run
```bash
cargo bench --bench=commit -- --quick
```
where `commit` is the name of the bench specified in [`crypto/Cargo.toml`](crypto/Cargo.toml), and the corresponding file in [`crypto/benches`](crypto/benches/).
In case you're interested in higher accuracy, and willing to trade it for execution speed, omit the `--quick` flag.
If you need reporting plots, remove the `.without_plots()` call in  [`crypto/benches/utils/mod.rs`](crypto/benches/utils/mod.rs).
The reports generated by criterion will be located in `target/criterion`.

## Git workflow

* The `main` branch is used as the everyday development branch.
* No merge commits. Always rebase on top of `main`.
* Release branches are named `release/<series>`, e.g. `release/1.x`, `release/2.x`.
* Release branches contain fixes relevant to their specific release series and are never merged to `main`.
* Release branches always branch off their first major release tag. For example,
  the output of `git merge-base main release/2.x` must be a commit pointed to by tag `v2.0.0`.
* Release branches are created lazily, that is, only when the first fix needs to be applied and released
  for a specific release series.
* Use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) -- those are picked up by the changelog generator.
* If there is a JIRA ticket related to the change, you should mention it in either the PR title or the commit(s),
  with the following format: `[TICKET_ID]`.
* Sign your [commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
  and [tags](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-tags).
* Remove branches from the remote once you don't need them anymore.


## Publishing

### Versioning

The versioning scheme used is [SemVer AKA Semantic Versioning](https://semver.org).

### Making a new release

1. Make a branch based on `main` to prepare for release (`git checkout -b prepare-release/X.Y.Z`)
1. Run `cargo xtask release bump [major|minor|patch|rc|pre] --dry-run`, check if it's the expected result
1. If all seems fine, re-run the previous command without the `--dry-run` argument.
   This will bump the versions of:
    - all workspace member crates
    - `package.json`
    - `crypto-ffi/bindings/gradle.properties`
1. Generate the relevant changelog section:
   ```bash
   git cliff --bump --unreleased
   ```
   and add it to the top of `CHANGELOG.md`.
   Make sure the version number generated by `git cliff` matches the release version.
1. If there are any release highlights, add them as the first subsection below release title:
   ```markdown
   ## v1.0.2 - 2024-08-16

   ### Highlights

   - foo
   - bar
   - baz
   ```
1. Make sure the changes look reasonable and complete; you can use the previous release as a reference
1. Push your `prepare-release/X.Y.Z` branch and create a PR for it
1. Get it reviewed, then merge it into `main` and remove the `prepare-release/X.Y.Z` branch from the remote
1. Now, pull your local `main`: `git checkout main && git pull`
1. Create the release tag: `git tag -s vX.Y.Z`
1. Push the new tag: `git push origin tag vX.Y.Z`
1. Create a new release on github, copying the relevant section from `CHANGELOG.md`
1. Voilà!


### Publishing Android / JVM bindings

Publishing Android / JVM bindings happens automatically by a github workflow when a release tag is pushed.

If you would like to publish the bindings to a local maven cache, run:
```ignore
cd crypto-ffi/bindings/android
./gradlew :jvm:publishToMavenLocal
./gradlew :android:publishToMavenLocal
```

### Publishing JS / WASM bindings

Publishing JS / WASM bindings happens automatically by a github workflow when a release tag is pushed.

If you would like to publish to `@wireapp/core-crypto` manually, log into NPM and
just run `npm publish`.
