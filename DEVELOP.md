# How to work on CoreCrypto

## Environment

<https://github.com/wireapp/core-crypto#building>

### Git workflow

* No merge commits. Always rebase on top of `develop`.
* Use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) - Those are picked up by the changelog generator
* For JIRA tickets you can add them to either the titles of PRs or the commits themselves with the following format: `[TICKET_ID]`

### Versioning

The versioning scheme used is [SemVer AKA Semantic Versioning][semver].

## What is it?

Basically, CoreCrypto is a (big) wrapper around `OpenMLS` that tries to erase the API and uphold proper invariants.
We also take care of storage of key material on all platforms (see [docs/KEYSTORE_IMPLEMENTATION.md](docs/KEYSTORE_IMPLEMENTATION.md)).
Another piece that is quite important is our implementation of E2EI (End-to-end-identity), see internal documents for this.

## Contributing

### Adding new APIs

1. Make your changes wherever applicable
2. Make sure your new API is available on `MlsCentral`, while respecting encapsulation
    - For example, adding `MlsConversation::hello()` would mean exposing a new `MlsCentral::conversation_hello(conversation_id: ConversationId)`
3. Expose your new API on both `crypto-ffi/src/[generic|wasm].rs`
4. Add the new APIs respecting the appropriate calling conventions defined in [docs/FFI.md](docs/FFI.md) to
    - Kotlin/Android: `crypto-ffi/bindings/jvm/src/main/com/wire/crypto/client/[CoreCryptoCentral|E2eiClient|MLSClient].kt`
    - Swift/iOS: `crypto-ffi/bindings/swift/Sources/CoreCrypto/CoreCrypto.swift`
    - TypeScript/Web: `crypto-ffi/bindings/js/CoreCrypto.ts`
5. Do not forget the docs in the bindings in particular! Those are the docs that will be displayed in consumers' editors.

## Compiling

### Checking if the code is correct wrt rust compiler

`cargo check`

### Compiling for Kotlin/Android

```
cd crypto-ffi
cargo make android
cd bindings
./gradlew android:build
```

### Compiling for Swift/iOS

```
cd crypto-ffi
cargo make ios
# Additionally, if you want to export a .XCFramework:
cargo make ios-create-xcframework
```

### Compiling for WASM/Web

```
cd crypto-ffi
cargo make wasm
```

## Testing

### General testing

```
# Install cargo-nextest if you haven't done so, it yields some substantial speedup:
cargo install cargo-nextest
cargo nextest run
```

#### Addendum: testing all ciphersuites

Warning: This takes quite a while.

```
cargo nextest run --features test-all-cipher
```

### Platform-specific testing

### Kotlin/Android

* Take the steps to compile for Kotlin/Android
* Then

```
cd crypto-ffi/bindings
./gradlew test
```

### Swift/iOS

*No E2E testing is available as of now on Swift*

### WASM/Web


* Take the steps to compile for WASM/Web
* Then

```
cd crypto-ffi
bun test
```

## Publishing

**Important: you MUST follow proper [SemVer conventions][semver]!** - This helps our consumer teams quickly estimate the workload to integrate our changes and plan accordingly.

*NB: As of the time of writing (23/05/2024), CoreCrypto is trapped in "prerelease-hell" to allow ourselves to emit breaking changes before a stable 1.0.0 without increasing the major version.*

1. Run `cargo xtask release bump [major|minor|patch|rc|pre] --dry-run`, check if it's the expected result
2. If all seems fine, re-run the previous command without the `--dry-run` argument
3. Make a release branch started from `develop` (`git checkout -b release/X.Y.Z`)
4. Edit `CHANGELOG.tpl` with the contents of the release.
    - Copy the git-conventional block from the previous release to your new release, modify the version tag
    - Remove the `unreleased=true` from the previous release
    - Try to write some human concise documentation so that client teams understand the changes at a glance
5. Run `cargo xtask documentation changelog` to generate the corresponding `CHANGELOG.md`
6. Push your `release/X.Y.Z` branch and create a PR for it
7. Get it reviewed, then merge it into `develop`
8. Now, pull your local develop `git checkout develop && git pull`
9. Update the `main` branch `git checkout main && git pull && git rebase -i develop`
10. Create your tag `git tag vX.Y.Z`
11. Push the branch and the new tag `git push && git push --tags`
12. Voilà!

Most of this could be automated further but for now, please use this release process to make sure things stay consistent.


[semver]: https://semver.org/
