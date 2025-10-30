# Wire CoreCrypto

This repository is part of the source code of Wire. You can find more information at [wire.com](https://wire.com) or by contacting opensource@wire.com.

You can find the published source code at [github.com/wireapp/wire](https://github.com/wireapp/wire).

For licensing information, see the attached LICENSE file and the list of third-party licenses at [wire.com/legal/licenses/](https://wire.com/legal/licenses/).

No license is granted to the Wire trademark and its associated logos, all of which will continue to be owned exclusively by Wire Swiss GmbH. Any use of the Wire trademark and/or its associated logos is expressly prohibited without the express prior written consent of Wire Swiss GmbH.

## Parts

- CoreCrypto: Abstracts MLS & Proteus in a unified API
- CoreCryptoFFI: FFI bindings for iOS, Android and WASM
- Keystore: Encrypted Keystore powered by SQLCipher on all platforms except WASM. WASM uses an IndexedDB-backed, encrypted store with AES256-GCM
- MlsProvider: RustCrypto + Keystore MLS provider

See [ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Usage

### [API Docs](https://wireapp.github.io/core-crypto/)

## Building

### General Requirements

- rust: <https://rustup.rs/>
- GNU make: <https://www.gnu.org/software/make/> (min version: 4.3)

If you're using macOS, you'll also need to install GNU sed:

```sh,ignore
brew install gnu-sed make
```

and add aliases to your shell configuration file: `alias sed=gsed`, `aliase make=gmake` (e.g. to `~/.zshenv` if you're using zsh).

#### Pre-commit

- Install the [`pre-commit` framework](https://pre-commit.com/)
- Run `pre-commit install` to initialize the pre-commit hooks

### Android

[Install Android SDK](https://developer.android.com/studio) and Build-Tools for API level 30+

> [!IMPORTANT]
> If you are building on macOS you'll need to setup `$ANDROID_SDK_ROOT` path variable manually:
>
> ```ignore
> export ANDROID_SDK_ROOT=~/Android/Sdk
> ```

[Install the Android NDK](https://developer.android.com/studio/projects/install-ndk)

Install android rust targets:

```ignore
rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi
```

Build:

```ignore
make android
```

### iOS

Install Xcode & its command-line tools: [https://developer.apple.com/xcode/](https://developer.apple.com/xcode/).

Install iOS rust targets:

```ignore
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

Build:

```ignore
make ios
# Additionally, if you want to export a .XCFramework:
make ios-create-xcframework
```

### MacOS

Install macOS rust targets:

```ignore
rustup target add aarch64-apple-darwin
```

### Linux

> [!NOTE]
> If cross-compiling from macOS, you'll need to install
> [https://github.com/messense/homebrew-macos-cross-toolchains](https://github.com/messense/homebrew-macos-cross-toolchains).

Install Linux targets:

```ignore
rustup target add x86_64-unknown-linux-gnu
```

### WASM

Make sure you have all prerequisites:

- Install [wasm-pack](https://rustwasm.github.io/wasm-pack/)
- Install the `wasm32-unknown-unknown` toolchain: `rustup target add wasm32-unknown-unknown`
- Install node.js (recommended way is via [Volta](https://volta.sh/))
- Install Bun (follow the instructions on [Bun's website](https://bun.sh/))
- Install wasm-bindgen-cli

Build:

```ignore
make ts
```

### Bindings

Build bindings for Android, JVM, iOS and WASM

```ignore
# builds bindings and targets for the JVM (macOS / Linux)
make jvm

# builds bindings and targets for Android
make android

# builds iOS framework
make ios-create-xcframework

# builds wasm binary & TS bindings
make ts
```

## Testing

### General testing

```ignore
# Install cargo-nextest if you haven't done so, it yields some substantial speedup
cargo install cargo-nextest
cargo nextest run
```

### Run core crypto internal tests on WASM target

If you haven't already, install the target and wasm-pack:

```sh
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

> [!WARNING]
> This takes quite a while.

```ignore
cargo nextest run --features test-all-cipher
```

### Platform-specific tests for Kotlin/JVM

```sh
make jvm-test
```

### Platform-specific tests for Android

```sh
make android-test
```

### Swift/iOS

*No E2E testing is available as of now on Swift.*

### Platform-specific tests for WASM/Web

```sh
make ts-test
```

Note the `CC_TEST_LOG_LEVEL` environment variable. At 1 it emits browser console logs; at 2 it also emits CoreCrypto logs.

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
If you need reporting plots, remove the `.without_plots()` call in [`crypto/benches/utils/mod.rs`](crypto/benches/utils/mod.rs).
The reports generated by criterion will be located in `target/criterion`.

## Git workflow

- The `main` branch is used as the everyday development branch.
- No merge commits. Always rebase on top of `main`.
- Release branches are named `release/<series>`, e.g. `release/1.x`, `release/2.x`.
- Release branches contain fixes relevant to their specific release series and are never merged to `main`.
- Release branches always branch off their first major release tag. For example,
  the output of `git merge-base main release/2.x` must be a commit pointed to by tag `v2.0.0`.
- Release branches are created lazily, that is, only when the first fix needs to be applied and released
  for a specific release series.
- Use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) -- those are picked up by the changelog generator.
- If there is a JIRA ticket related to the change, you should mention it in either the PR title or the commit(s),
  with the following format: `[TICKET_ID]`.
- Sign your [commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
  and [tags](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-tags).
- Remove branches from the remote once you don't need them anymore.

## Publishing

### Versioning

The versioning scheme used is [SemVer AKA Semantic Versioning](https://semver.org).

### Making a new release

1. Make a branch based on `main` to prepare for release (`git checkout -b prepare-release/X.Y.Z`)
1. Run `sh scripts/update-versions.sh X.Y.Z` to update the versions of
   - all workspace member crates
   - `package.json`
   - `crypto-ffi/bindings/gradle.properties`
     Make sure the result of the script run is correct.
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
1. In [index.md](docs/index.md), copy the commented-out table row from the bottom of the file to the appropriate place
   in the table, ordering by version number, descending. Search and replace the first 5 occurrences of `x.x.x` with `X.Y.Z`.
1. Make sure the changes look reasonable and complete; you can use the previous release as a reference
1. Push your `prepare-release/X.Y.Z` branch and create a PR for it
1. Get it reviewed, then merge it into `main` and remove the `prepare-release/X.Y.Z` branch from the remote
1. Now, pull your local `main`: `git checkout main && git pull`
1. Create the release tag: `git tag -s vX.Y.Z`
1. Push the new tag: `git push origin tag vX.Y.Z`
1. Create a new release on github, copying the relevant section from `CHANGELOG.md`
1. Voilà!

#### Consider when making a release from a release branch

1. Isolate the changes to [index.md](docs/index.md) and `CHANGELOG.md` from the release commit itself
1. After the release is finished, cherry-pick the changes to [index.md](docs/index.md) and `CHANGELOG.md` and get them into `main`
1. For release series `4.x` and newer, docs upload happens automatically.
   If you released from the series `3.x` or older, you need to trigger docs upload manually:
   1. On GitHub, go to the [docs workflow](https://github.com/wireapp/core-crypto/actions/workflows/docs.yml)
   1. Click the `Run workflow` button
   1. In the `Use workflow from` dropdown, choose `release/5.x`, in `Tag to checkout` provide your release tag

### Publishing Android / JVM bindings

Publishing Android / JVM bindings happens automatically by a github workflow when a release tag is pushed.

If you would like to publish the bindings to a local Maven cache, run:

```ignore
cd crypto-ffi/bindings
./gradlew :jvm:publishToMavenLocal
./gradlew :android:publishToMavenLocal
```

### Publishing JS / WASM bindings

Publishing JS / WASM bindings happens automatically by a github workflow when a release tag is pushed.

If you would like to publish to `@wireapp/core-crypto` manually, log into NPM and
just run `bun publish`.
