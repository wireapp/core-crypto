# Changelog

Platform support legends:

* ✅ = tier 1 support. Things just work.
* ⚠️ = tier 2 support. Things compile but *might* not work as expected. Basically works but with papercuts
    * Note: the papercuts will majorly be with the build process. Things might be very rough to integrate as no polish at all has been given yet.
* ❌ = tier 3 support. It doesn't work just yet, but we plan to make it work.

## [0.6.0-rc.5] - 2023-01-25

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- [**breaking**] Added conversation id to clientIsExistingGroupUser callback
- Increment IndexedDB store version when crate version changes

### Features

- Added support for Proteus error codes

### Miscellaneous Tasks

- Moved codecov from tarpaulin to llvm-cov
- Updated RustCrypto primitives & git dep in xtask

</details>

* **BREAKING**: Changed the signature of the `client_is_existing_group_user` callback to add the group id as the first argument
    * Before: `client_is_existing_group_user(client_id: ClientId, existing_clients: Vec<ClientId>) -> bool`
    * After: `client_is_existing_group_user(conversation_id: ConversationId, client_id: ClientId, existing_clients: Vec<ClientId>) -> bool`
* Added support for Proteus error codes
    * On WASM, the JS Error contains a `proteusError` method that returns the error code as an integer. If there's no error it returns 0.
    * On other platforms, the FFI has gained a `proteus_last_error_code` method.
* Fixed a bug where the keystore would not execute its IndexedDB upgrade handler on WASM, leading to older stores and/or new tables not being structurally consistent
* Updated RustCrypto dependencies
* Tooling: moved code coverage CI from Tarpaulin to LLVM-Cov
    * This lowered the execution time of our codecov CI from ~25-30 minutes down to ~15-20 minutes
    * This leads to more accurate code coverage as well - along with some false negatives such as `#[derive]` statements


## [0.6.0-rc.4] - 2023-01-20

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Aarch64-apple-ios-sim target not compiling  ([#213](https://github.com/wireapp/core-crypto/issues/213))
- Cryptobox import now throws errors on missing/incorrect store

### Features

- Expose end to end identity web API
- Add end to end identity bindings

### Miscellaneous Tasks

- 0.6.0-rc.4 release
- Updated base64, lru and spinoff deps
- Added WebDriver-based WASM test runner
- Xtask improvements
- Fix 1.66 clippy warnings
- Update base64 to 0.20
- Fixed wrong documentation link in TS bindings docs
- Update UniFFI to 0.22
- Kotlin FFI docs + makefile fixes for other platforms


### Bug Fixes

- Added missing Proteus APIs and docs

### Miscellaneous Tasks

- Release v0.6.0-rc.3


### Bug Fixes

- Functional Android NDK 21 CI
- Publish android CI
- Unreachable pub makes docs build fail

### Miscellaneous Tasks

- Release v0.6.0-rc.2
- Fix advisory stuff


### Bug Fixes

- Broken Proteus implementation
- Prevent application messages signed by expired KeyPackages
- Fix cryptobox import on WASM [CL-119]
- Incorrect TS return types [CL-118]

### Features

- Expose a 'WrongEpoch' error whenever one attempts to decrypt a message in the wrong epoch
- Add 'restore_from_disk' to enable using multiple MlsCentral instances in iOS extensions
- Add specialized error when trying to break forward secrecy
- Add 'out_of_order_tolerance' & 'maximum_forward_distance' to configuration without exposing them and verify they are actually applied
- [**breaking**] Change 'client_id' in CoreCrypto constructor from a String to a byte array to remain consistent across the API
- Expose proteus prekey fingerprint - CL-107

### Miscellaneous Tasks

- Release v0.6.0-rc.1
- Use NDK 21 for android artifacts - CL-111

### Testing

- Ensure we are immune to duplicate commits and out of order commit/proposal


### Features

- Expose proteus session fingerprints (local and remote) - CL-108
- Support deferred MLS initialization for proteus purposes [CL-106]

### Miscellaneous Tasks

- Remove C-FFI


### Bug Fixes

- [**breaking**] Incorrect handling of enums across WASM FFI
- Commits could lead to inconsistent state in keystore in case PGS serialization fails
- Make tags have semantic versioning names and downgrading to swift 5.5 - CL-49
- Publication of swift packages

### Features

- Expose session exists through the ffi - CL-101

### Miscellaneous Tasks

- Fix new clippy test warnings in 1.65
- Fix new clippy warnings in 1.65

### Testing

- Ensure everything keeps working when pure ciphertext format policy is selected


### Bug Fixes

- Change the internal type of the public group info to Vec<u8> so we don't have extra bytes in the serialized message - FS-1127

### Miscellaneous Tasks

- Adding actions to check bindings and to publish swift package - CL-49
- Add action to publish jvm/android packages and change rust toolchain in ci ([#157](https://github.com/wireapp/core-crypto/issues/157))
- Add support for Proteus within interop runner


### Bug Fixes

- 'join_by_external_commit' returns a non TLS serialized conversation id

### Features

- [**breaking**] Expose a 'PublicGroupStateBundle' struct used in 'CommitBundle' variants
- [**breaking**] Remove all the final_* methods returning a TLS encoded CommitBundle
- Returning if decrypted message changed the epoch - CL-92 ([#152](https://github.com/wireapp/core-crypto/issues/152))
- Exporting secret key derived from the group and client ids from the members - CL-97 - CL-98 ([#142](https://github.com/wireapp/core-crypto/issues/142))
- Added API to generate Proteus prekeys
- Fixed Cryptobox import for WASM
- Added support for migrating Cryptobox data
- Added FFI for CoreCrypto-Proteus
- Added support for Proteus
- Validate received external commits making sure the sender's user already belongs to the MLS group and has the right role
- [**breaking**] Rename callback~~`client_id_belongs_to_one_of`~~ into `client_is_existing_group_user`
- [**breaking**] External commit returns a bundle containing the PGS
- [**breaking**] Add `clear_pending_group_from_external_commit` to cleanly abort an external commit. Also renamed `group_state` argument into `public_group_state` wherever found which can be considered a breaking change in some languages
- [**breaking**] Rename `MlsConversationInitMessage#group` into `MlsConversationInitMessage#conversation_id` because it was misleading about the actual returned value

### Miscellaneous Tasks

- Apply suggestions from code review
- Updated bundled FFI files
- Added Proteus testing infra
- Added missing docs
- Nits, fmt & cargo-deny tweak
- Add m1 support for the jvm bindings ([#139](https://github.com/wireapp/core-crypto/issues/139))
- Remove unneeded `map_err(CryptoError::from)`
- Remove useless code

### Testing

- Fix external commit tests allowing member to rejoin a group by external commit
- Add a default impl for 'TestCase', very useful when one has to debug on IntelliJ
- Parameterize ciphers
- Ensure external senders can be inferred when joining by external commit or welcome
- Fix rcgen failing on WASM due to some unsupported elliptic curve methods invoked at compile time
- Ensure external commit are retriable


### Bug Fixes

- Wire-server sends a base64 encoded ed25519 key afterall. Consumers are in charge of base64 decoding it and pass it to core-crypto
- TS Ciphersuite enum not correctly exported

### Documentation

- Add installation instructions for e2e runner on macos

### Miscellaneous Tasks

- Release v0.5.2


### Bug Fixes

- Incorrect null handing in Typescript wrapper for 'commitPendingProposals'
- External_senders public key was not TLS deserialized causing rejection of external remove proposals

### Documentation

- Better explanation of what DecryptedMessage#proposals contains

### Miscellaneous Tasks

- Release v0.5.1
- Added E2E interop testing tool


### Bug Fixes

- NPM publish workflow missing npm ci + wrong method names in TS bindings
- NPM publish workflow missing npm i
- Rollback openmls & chrono in order to release 0.5.0
- Pin openmls without vulnerable chrono
- Wee_alloc memory leak + NPM publish issue
- Unreachable pub struct breaks docgen
- Fixed iOS SQLCipher salt handling within keychain
- [**breaking**] Changed misleading callback API and docs
- [**breaking**] Added missing TS API to set CoreCrypto callbacks
- Force software implementation for sha2 on target architectures not supporting hardware implementation (i686 & armv7 in our case)

### Documentation

- Add forgotten 0.4.0 changelog

### Features

- [**breaking**] 'commit_pending_proposals' now returns an optional CommitBundle when there is no pending proposals to commit

### Miscellaneous Tasks

- Release v0.5.0 Redux
- Update UniFFI to 0.20
- Release v0.5.0
- Update node version from 12 to 16 LTS
- Update dependencies
- Remove es2020-specific operators and target es2020 only
- Updated changelog


### Bug Fixes

- Uniffi breaking changes in patch release and ffi error due to unused `TlsMemberAddedMessages`


### Bug Fixes

- Ensure durable methods are well tested and actually durable

### Features

- Commits and group creation return a TLS serialized CommitBundle. The latter also contains a PublicGroupStateBundle to prepare future evolutions
- [**breaking**] 'decrypt_message' returns the sender client id
- Use 128 bytes of padding when encrypting messages instead of 16 previously
- Add function to return current epoch of a group [CL-80] ([#96](https://github.com/wireapp/core-crypto/issues/96))
- Adding a wrapper for the swift API and initial docs [CL-62] ([#89](https://github.com/wireapp/core-crypto/issues/89))
- Add '#[durable]' macro to verify the method is tolerant to crashes and persists the MLS group in keystore
- Expose 'clear_pending_commit' method
- Allow rollbacking a proposal
- [**breaking**] Expose 'clear_pending_commit' method
- [**breaking**] Allow rollbacking a proposal

### Miscellaneous Tasks

- Migrate benchmarks to async and write some for core crypto operations
- Fixed WASM E2E tests

### Testing

- Add reminder for x509 certificate tests


### Miscellaneous Tasks

- Release v0.3.1


### Bug Fixes

- Clippy fix impl eq
- Libgcc swizzling for android was removed
- Cleaned up FFI names for clearer intent
- Caught up WASM api with the internal API changes
- Doctests were failing because included markdown snippets were parsed and compiled
- Defer validation that a callback has to be set for validating external add proposal after incoming proposal identified as such
- Updated RustCrypto dependencies to match hpke-rs requirements
- Group was not persisted after decrypting an application message
- UniFFI wrong type defs
- Aes_gcm compilation issue
- WASM persistence & CoreCrypto Async edition
- 'client_keypackages' does not require mutable access on 'mls_client'
- Add_member/remove_member IoError
- Incorrect number of keypackages returned
- Added support for MLS Group persistence [CL-5]

### Documentation

- Added bindings docs where appropriate + generated gh-pages
- Fix Client struct documentation
- Improving docs of Core-Crypto - [CL-50] ([#60](https://github.com/wireapp/core-crypto/issues/60))

### Features

- Review external add proposal validation and remove 'InvalidProposalType' error
- Remove required KeyPackage when creating an external add proposal
- Remove commits auto-merge behaviour
- Expose GroupInfo after commit operation
- Use draft-16 implementation of external sender. Expose a correct type through ffi for remove key
- Add API to wipe specific group from core crypto [CL-55] ([#81](https://github.com/wireapp/core-crypto/issues/81))
- Adding validation to external proposal [CL-51] ([#71](https://github.com/wireapp/core-crypto/issues/71))
- Decrypting a commit now also return a delay when there are pending proposals
- Decrypting a commit now also return a delay when there are pending proposals
- 'commit_delay' now uses openmls provided leaf index instead of computing it ourselves. It is also now infallible.
- Ensure consistent state
- [**breaking**] Add commit delay when a message with prending proposals is processed [CL-52] ([#67](https://github.com/wireapp/core-crypto/issues/67))
- Added KeyPackage Pruning
- Added support for external entropy seed
- Join by external commit support - CL-47 ([#57](https://github.com/wireapp/core-crypto/issues/57))
- Added Entity testing to keystore
- External remove proposal support
- Supports and validates x509 certificates as credential
- Expose function to self update the key package to FFI and Wasm #CL-17 ([#48](https://github.com/wireapp/core-crypto/issues/48))
- Added support for wasm32-unknown-unknown target
- Support external add proposal
- Added method to leave a conversation
- Enforce (simple) invariants on MlsCentralConfiguration
- Expose add/update/remove proposal

### Miscellaneous Tasks

- Bump WASM bundle version to 0.3.0
- Added Changelog generator
- Fix nits on CHANGELOG-HUMAN.md
- Add changelog generator configuration + human changelog
- Disable crate publishing + UniFFI catchup
- Rename 'group_info' into 'public_group_state' to remain consistent with draft-12
- Remove 'SelfKeypackageNotFound' error which is not used
- Fix some clippy lints
- Remove 'group()' test helper and inlined it
- Fix cli compilation and update it a bit
- Removed CryptoError variant `CentralConfigurationError`
- Avoid cloning credential
- Use shorthand for not using generics in conversation
- Factorize group accessors in conversation.rs
- Fix some clippy warnings
- Remove .idea in sample anroid app
- Remove unnecessary path prefixes imports
- Remove useless mutable borrow in Client methods
- Add Intellij files to gitignore
- Bump jvm and android version
- Add jvm linux support

### Performance

- Avoid cloning conversation extra members when creating the former

### Refactor

- Moved run_with_* test utils in a test_utils mod
- Use shorthand for generics in Central
- Factorize keystore update when group state change from a conversation pov

### Testing

- Add tests for 'commit_pending_proposals'
- Verify that commit operation are returning a valid welcome if any
- Use Index trait to access conversation from Central instead of duplicate accessor
- Use central instead of conversation
- Fix minor clippy lints in tests
- Apply clippy suggestions on test sources
- Reorganize tests in conversation.rs
- Nest conversation tests in dedicated modules
- Verify adding a keypackage to a ConversationMember


### Bug Fixes

- Set correct path to toolchain depending on platform & copy bindings
- Fix broken tests
- Tests fix
- Fixed iOS WAL behavior for SQLite-backed stores
- Fix Keystore trait having update method removed
- Clippy + fmt pass on core-crypto
- Fmt + clippy pass
- Migrations were incorrectly defined

### Features

- Add android project
- Add tasks for building and copying jvm resources
- Add jvm project
- WIP hand-written ts bindings
- Generate Swift & Kotlin bindings 🎉
- Updated deps
- Added salt in keychain management instead of flat AES-encrypted file
- Added WIP DS mockup based on QUIC
- Added ability to create conversations (!!!)
- Added api support for in-memory keystore
- Added in-memory faculties for keystore
- Added benches for the MLS key management
- Added benches & fixed performance issues
- Added integration tests + fixes
- Implemented LRU cache for keystore
- Added support for Proteus PreKeys
- Progress + fix store compilation to WASM

### Miscellaneous Tasks

- Configure wire maven repository
- Clean up gradle files

</details>

* First bytes of end to end identity exposed. Thanks to the ACME protocol, it allows requesting a x509 certificate from an authority and then use it to create a MLS Credential.
* Fixed `cargo-make` Makefile.toml to allow building JVM bindings whatever the platform you're running
    * This is done by adding tests to the relevant tasks, allowing to conditionally execute them.
* Added a Makefile task to build the `core_crypto_ffi` Kotlin binding docs (via Dokka) and integrate them into the doc package
* Updated UniFFI to 0.22
* Other minor improvements on internal build/release tools (mainly our `cargo xtask` command)
* **Semi-breaking**: Behavior change on `ProteusCentral::import_cryptobox` (aka Cryptobox import).
    * WASM: If the provided store `path` is missing or doesn't have the expected tables, we now throw a `CryptoboxMigrationError::ProvidedPathDoesNotExist` error
    * Other platforms: If the provided cryptobox folder at `path` is missing, we now throw a `CryptoboxMigrationError::ProvidedPathDoesNotExist` error
    * Likewise, on all platforms, if the Cryptobox Identity is not present, we now throw a `CryptoboxMigrationError::IdentityNotFound` error and abort the process
* Tooling: Added a custom WASM test runner based on WebDriver (BiDi interactive test progress reporting in progress still)

## [0.6.0-rc.3] - 2022-12-15

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Added missing Proteus APIs and docs

### Miscellaneous Tasks

- Release v0.6.0-rc.3

</details>

* Added missing Proteus APIs to bindings and FFI:
    * `proteus_new_prekey_auto`: generates a new PreKeyBundle with an automatically incremented ID
        * To do this, CoreCrypto finds the first "free" ID within the `0..u16::MAX` range and creates a PreKey using this ID.
* Added missing documentation when it comes to Proteus eager Session persistence.
    * Previously undocumented change, but since `0.6.0-rc.1`, CoreCrypto eagerly persists Proteus Sessions (much like it does with MLS groups) when needed:
        * Decrypting or Encrypting messages, as ratcheting key material can be produced and as such must be persisted
            * We'll add a more "manual" API later on if you want to control when data is persisted (because it is performance heavy)
        * Initializing Sessions through PreKeyBundles or incoming Messages


## [0.6.0-rc.2] - 2022-12-15

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Functional Android NDK 21 CI
- Publish android CI
- Unreachable pub makes docs build fail

### Miscellaneous Tasks

- Release v0.6.0-rc.2
- Fix advisory stuff

</details>

* This release contains nothing. It's only there to fix the faulty Android release CI.

## [0.6.0-rc.1] - 2022-12-14

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Broken Proteus implementation
- Prevent application messages signed by expired KeyPackages
- Fix cryptobox import on WASM [CL-119]
- Incorrect TS return types [CL-118]

### Features

- Expose a 'WrongEpoch' error whenever one attempts to decrypt a message in the wrong epoch
- Add 'restore_from_disk' to enable using multiple MlsCentral instances in iOS extensions
- Add specialized error when trying to break forward secrecy
- Add 'out_of_order_tolerance' & 'maximum_forward_distance' to configuration without exposing them and verify they are actually applied
- [**breaking**] Change 'client_id' in CoreCrypto constructor from a String to a byte array to remain consistent across the API
- Expose proteus prekey fingerprint - CL-107

### Miscellaneous Tasks

- Release v0.6.0-rc.1
- Use NDK 21 for android artifacts - CL-111

### Testing

- Ensure we are immune to duplicate commits and out of order commit/proposal

</details>

* Fixed a compilation issue related to the `sha1` crate's ASM
* Added a `restore_from_disk` API to enable using CoreCrypto from various instances
* Various internal improvements to testing to increase resistance to uncommon scenarios
* Proteus:
    * Expose proteus prekey fingerprint
    * Fixed the TypeScript exposed types
    * Fixed Cryptobox import
    * Fixed broken Proteus implementation that led to decryption errors after key import
* MLS:
    * Expose a `WrongEpoch` error
    * Added an error when trying to break PFS
    * **BREAKING**: Tweaked the configuration format, removed and added some options

## [0.6.0-pre.5] - 2022-11-10

<details>
    <summary>git-conventional changelog</summary>

### Features

- Expose proteus session fingerprints (local and remote) - CL-108
- Support deferred MLS initialization for proteus purposes [CL-106]

### Miscellaneous Tasks

- Remove C-FFI

</details>

* chore: Get rid of the C-FFI
* feature: Added support for deferred MLS initialization
* Proteus:
    * Expose Proteus session Fingerprints (local & remote)


## [0.6.0-pre.4] - 2022-11-07

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- [**breaking**] Incorrect handling of enums across WASM FFI
- Commits could lead to inconsistent state in keystore in case PGS serialization fails
- Make tags have semantic versioning names and downgrading to swift 5.5 - CL-49
- Publication of swift packages

### Features

- Expose session exists through the ffi - CL-101

### Miscellaneous Tasks

- Fix new clippy test warnings in 1.65
- Fix new clippy warnings in 1.65

### Testing

- Ensure everything keeps working when pure ciphertext format policy is selected

</details>

* fix: Publication of swift packages [CL-49] by @augustocdias in https://github.com/wireapp/core-crypto/pull/165
* fix: Make tags have semantic versioning names and downgrading to swift 5.5 - CL-49 by @augustocdias in https://github.com/wireapp/core-crypto/pull/166
* feat: Expose session exists through the ffi - CL-101 by @augustocdias in https://github.com/wireapp/core-crypto/pull/167
* chore: fix new clippy warnings in 1.65 by @beltram in https://github.com/wireapp/core-crypto/pull/170
* fix: consistent commits by @beltram in https://github.com/wireapp/core-crypto/pull/169
* fix!: Incorrect handling of enums across WASM FFI [CL-104] by @OtaK in https://github.com/wireapp/core-crypto/pull/168
* test: pure ciphertext by @beltram in https://github.com/wireapp/core-crypto/pull/160
* Release 0.6.0-pre.4 by @augustocdias in https://github.com/wireapp/core-crypto/pull/171


**Full Changelog**: https://github.com/wireapp/core-crypto/blob/develop/CHANGELOG.md

## [0.6.0-pre.3] - 2022-11-01

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Change the internal type of the public group info to Vec<u8> so we don't have extra bytes in the serialized message - FS-1127

### Miscellaneous Tasks

- Adding actions to check bindings and to publish swift package - CL-49
- Add action to publish jvm/android packages and change rust toolchain in ci ([#157](https://github.com/wireapp/core-crypto/issues/157))
- Add support for Proteus within interop runner

</details>

* Move github action for rust to a maintained one. (More info: https://github.com/actions-rs/toolchain/issues/216)

## [0.6.0-pre.2] - 2022-10.21

<details>
    <summary>git-conventional changelog</summary>

</details>

* Enable proteus support

## [0.6.0-pre.1] - 2022-10.21

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- 'join_by_external_commit' returns a non TLS serialized conversation id

### Features

- [**breaking**] Expose a 'PublicGroupStateBundle' struct used in 'CommitBundle' variants
- [**breaking**] Remove all the final_* methods returning a TLS encoded CommitBundle
- Returning if decrypted message changed the epoch - CL-92 ([#152](https://github.com/wireapp/core-crypto/issues/152))
- Exporting secret key derived from the group and client ids from the members - CL-97 - CL-98 ([#142](https://github.com/wireapp/core-crypto/issues/142))
- Added API to generate Proteus prekeys
- Fixed Cryptobox import for WASM
- Added support for migrating Cryptobox data
- Added FFI for CoreCrypto-Proteus
- Added support for Proteus
- Validate received external commits making sure the sender's user already belongs to the MLS group and has the right role
- [**breaking**] Rename callback~~`client_id_belongs_to_one_of`~~ into `client_is_existing_group_user`
- [**breaking**] External commit returns a bundle containing the PGS
- [**breaking**] Add `clear_pending_group_from_external_commit` to cleanly abort an external commit. Also renamed `group_state` argument into `public_group_state` wherever found which can be considered a breaking change in some languages
- [**breaking**] Rename `MlsConversationInitMessage#group` into `MlsConversationInitMessage#conversation_id` because it was misleading about the actual returned value

### Miscellaneous Tasks

- Apply suggestions from code review
- Updated bundled FFI files
- Added Proteus testing infra
- Added missing docs
- Nits, fmt & cargo-deny tweak
- Add m1 support for the jvm bindings ([#139](https://github.com/wireapp/core-crypto/issues/139))
- Remove unneeded `map_err(CryptoError::from)`
- Remove useless code

### Testing

- Fix external commit tests allowing member to rejoin a group by external commit
- Add a default impl for 'TestCase', very useful when one has to debug on IntelliJ
- Parameterize ciphers
- Ensure external senders can be inferred when joining by external commit or welcome
- Fix rcgen failing on WASM due to some unsupported elliptic curve methods invoked at compile time
- Ensure external commit are retriable

</details>

* Add Apple M1 support for the JVM bindings
* Rename callback `client_id_belongs_to_one_of`
* Added Proteus compatibility layer support
* Added API to export secret key derived from the group and client ids from the members
* Change CommitBundle signature
    * The `decrypt` API now returns if the decrypted message changed the epoch
* Members can now rejoin group by external commits
    * Validate received external commits
    * Added `clear_pending_group_from_external_commit`
    * External commit returns a bundle containing the PGS


## [0.5.2] - 2022-27-09

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Wire-server sends a base64 encoded ed25519 key afterall. Consumers are in charge of base64 decoding it and pass it to core-crypto
- TS Ciphersuite enum not correctly exported

### Documentation

- Add installation instructions for e2e runner on macos

### Miscellaneous Tasks

- Release v0.5.2

</details>

* Fix: supplied backend's removal key was not TLS serialized but base64 encoded. In this release, it is up to consumer
to base64 decode the key and supply it to core-crypto
* Fix: Typescript enumerations could not be used by value

## [0.5.1] - 2022-21-09

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Incorrect null handing in Typescript wrapper for 'commitPendingProposals'
- External_senders public key was not TLS deserialized causing rejection of external remove proposals

### Documentation

- Better explanation of what DecryptedMessage#proposals contains

### Miscellaneous Tasks

- Release v0.5.1
- Added E2E interop testing tool

</details>

* Fix: supplied backend's removal key (used for verifying external remove proposals) was not TLS deserialized
* Fix: incorrect null handing in Typescript wrapper for 'commitPendingProposals' causing an error when there was no proposal to commit
* New test runner for running interoperability tests between various core-crypto clients.
Currently, only native & WASM are supported. Most of all, those tests can be run in our Continuous Integration.

## [0.5.0] - 2022-14-09

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- NPM publish workflow missing npm ci + wrong method names in TS bindings
- NPM publish workflow missing npm i
- Rollback openmls & chrono in order to release 0.5.0
- Pin openmls without vulnerable chrono
- Wee_alloc memory leak + NPM publish issue
- Unreachable pub struct breaks docgen
- Fixed iOS SQLCipher salt handling within keychain
- [**breaking**] Changed misleading callback API and docs
- [**breaking**] Added missing TS API to set CoreCrypto callbacks
- Force software implementation for sha2 on target architectures not supporting hardware implementation (i686 & armv7 in our case)

### Documentation

- Add forgotten 0.4.0 changelog

### Features

- [**breaking**] 'commit_pending_proposals' now returns an optional CommitBundle when there is no pending proposals to commit

### Miscellaneous Tasks

- Release v0.5.0 Redux
- Update UniFFI to 0.20
- Release v0.5.0
- Update node version from 12 to 16 LTS
- Update dependencies
- Remove es2020-specific operators and target es2020 only
- Updated changelog

</details>

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ✅ (⚠️)
* aarch64-linux-android ✅ (⚠️)
* i686-linux-android ✅ (⚠️)
* x86_64-linux-android ✅ (⚠️)
* aarch64-apple-ios ✅
* aarch64-apple-ios-sim ✅
* x86_64-apple-ios ✅
* wasm32-unknown-unknown ✅

Note: all the platforms marked with (⚠️) above will get a round of polish for the build process & documentation in the next release.

* **[BREAKING]**: `commit_pending_proposals` now returns an optional `CommitBundle`
    * This was made to handle the case where there are no queued proposals to commit and this method would be called, causing the operation to fail.
* **[BREAKING]**: Changed the API for callbacks for clarity
    * This also contains documentation changes that make the use and intent of callbacks easier to understand.
* Fixed the iOS-specific database salt handling to allow using several databases on the same device.
* TypeScript bindings:
    * Removed the use of ES2020-specific operators (`??` Null-coalescing operator) to allow downstream to compile without transpiling.
    * Added callbacks API
    * Removed the usage of `wee_alloc` allocator as it leaks memory: https://github.com/rustwasm/wee_alloc/issues/106
* Kotlin & Swift bindings:
    * Upgraded UniFFI to 0.20 which now generates a correct callback interface in `camelCase` instead of erroneous `snake_case`.
        * Note that you will have to adapt to the aforementioned breaking changes to the callback API anyway so this just makes it a bit nicer

## [0.4.2] - 2022-09-05

<details>
    <summary>git-conventional changelog</summary>

</details>

* Fixes runtime issues on Android caused by the [sha2](https://github.com/RustCrypto/hashes/tree/master/sha2) crate.

## [0.4.1] - 2022-09-01

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Uniffi breaking changes in patch release and ffi error due to unused `TlsMemberAddedMessages`

</details>

* Fixes build issues for mobile target

## [0.4.0] - 2022-08-31

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Ensure durable methods are well tested and actually durable

### Features

- Commits and group creation return a TLS serialized CommitBundle. The latter also contains a PublicGroupStateBundle to prepare future evolutions
- [**breaking**] 'decrypt_message' returns the sender client id
- Use 128 bytes of padding when encrypting messages instead of 16 previously
- Add function to return current epoch of a group [CL-80] ([#96](https://github.com/wireapp/core-crypto/issues/96))
- Adding a wrapper for the swift API and initial docs [CL-62] ([#89](https://github.com/wireapp/core-crypto/issues/89))
- Add '#[durable]' macro to verify the method is tolerant to crashes and persists the MLS group in keystore
- Expose 'clear_pending_commit' method
- Allow rollbacking a proposal
- [**breaking**] Expose 'clear_pending_commit' method
- [**breaking**] Allow rollbacking a proposal

### Miscellaneous Tasks

- Migrate benchmarks to async and write some for core crypto operations
- Fixed WASM E2E tests

### Testing

- Add reminder for x509 certificate tests

</details>

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ✅ (⚠️)
* aarch64-linux-android ✅ (⚠️)
* i686-linux-android ✅ (⚠️)
* x86_64-linux-android ✅ (⚠️)
* aarch64-apple-ios ✅
* aarch64-apple-ios-sim ✅
* x86_64-apple-ios ✅
* wasm32-unknown-unknown ✅

Note: all the platforms marked with (⚠️) above will get a round of polish for the build process & documentation in the next release.

### CoreCrypto

* Allow rollbacking proposals. Now every method for creating a proposal also returns a proposal reference
(unique identifier) one can use later on to `clear_pending_proposal`
* Add `clear_pending_proposal` to wipe out local pending proposals
* Add `clear_pending_commit` to wipe out local pending commit
* Add `conversation_epoch` to get the current conversation's MLS epoch
* Now `decrypt_message` returns the sender client_id when the message is an application message. To use in calling.
* Durability: Now all the mutable operations are checked for durability i.e. would a process crash turn the application
into an inconsistent state. It boils down to verifying that we persist the MLS group in the keystore after every
operation mutating it
* Added a clean and documented Swift wrapper and tasks to build it more easily
* use 128 bytes of padding when encrypting messages instead of 16 previously
* Add some commit methods `final_add_clients_to_conversation`, `final_remove_clients_from_conversation`,
`final_update_keying_material` & `final_commit_pending_proposals` which return a TLS serialized CommitBundle. It cannot
be used now since wire-server does not yet have an endpoint for supplying it. It can be used to test the endpoint.
In the end, the `final_` prefix will removed and the not prefixed methods will be deprecated.
* Benchmarks have been improved and now also cover MLS operations


## [0.3.1] - 2022-08-16

<details>
    <summary>git-conventional changelog</summary>

### Miscellaneous Tasks

- Release v0.3.1

</details>

Maintenance release to prepare for the next release

* Pinned all git dependencies via git tags to avoid breakage in the future


## [0.3.0] - 2022-08-12

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Clippy fix impl eq
- Libgcc swizzling for android was removed
- Cleaned up FFI names for clearer intent
- Caught up WASM api with the internal API changes
- Doctests were failing because included markdown snippets were parsed and compiled
- Defer validation that a callback has to be set for validating external add proposal after incoming proposal identified as such
- Updated RustCrypto dependencies to match hpke-rs requirements
- Group was not persisted after decrypting an application message
- UniFFI wrong type defs
- Aes_gcm compilation issue
- WASM persistence & CoreCrypto Async edition
- 'client_keypackages' does not require mutable access on 'mls_client'
- Add_member/remove_member IoError
- Incorrect number of keypackages returned
- Added support for MLS Group persistence [CL-5]

### Documentation

- Added bindings docs where appropriate + generated gh-pages
- Fix Client struct documentation
- Improving docs of Core-Crypto - [CL-50] ([#60](https://github.com/wireapp/core-crypto/issues/60))

### Features

- Review external add proposal validation and remove 'InvalidProposalType' error
- Remove required KeyPackage when creating an external add proposal
- Remove commits auto-merge behaviour
- Expose GroupInfo after commit operation
- Use draft-16 implementation of external sender. Expose a correct type through ffi for remove key
- Add API to wipe specific group from core crypto [CL-55] ([#81](https://github.com/wireapp/core-crypto/issues/81))
- Adding validation to external proposal [CL-51] ([#71](https://github.com/wireapp/core-crypto/issues/71))
- Decrypting a commit now also return a delay when there are pending proposals
- Decrypting a commit now also return a delay when there are pending proposals
- 'commit_delay' now uses openmls provided leaf index instead of computing it ourselves. It is also now infallible.
- Ensure consistent state
- [**breaking**] Add commit delay when a message with prending proposals is processed [CL-52] ([#67](https://github.com/wireapp/core-crypto/issues/67))
- Added KeyPackage Pruning
- Added support for external entropy seed
- Join by external commit support - CL-47 ([#57](https://github.com/wireapp/core-crypto/issues/57))
- Added Entity testing to keystore
- External remove proposal support
- Supports and validates x509 certificates as credential
- Expose function to self update the key package to FFI and Wasm #CL-17 ([#48](https://github.com/wireapp/core-crypto/issues/48))
- Added support for wasm32-unknown-unknown target
- Support external add proposal
- Added method to leave a conversation
- Enforce (simple) invariants on MlsCentralConfiguration
- Expose add/update/remove proposal

### Miscellaneous Tasks

- Bump WASM bundle version to 0.3.0
- Added Changelog generator
- Fix nits on CHANGELOG-HUMAN.md
- Add changelog generator configuration + human changelog
- Disable crate publishing + UniFFI catchup
- Rename 'group_info' into 'public_group_state' to remain consistent with draft-12
- Remove 'SelfKeypackageNotFound' error which is not used
- Fix some clippy lints
- Remove 'group()' test helper and inlined it
- Fix cli compilation and update it a bit
- Removed CryptoError variant `CentralConfigurationError`
- Avoid cloning credential
- Use shorthand for not using generics in conversation
- Factorize group accessors in conversation.rs
- Fix some clippy warnings
- Remove .idea in sample anroid app
- Remove unnecessary path prefixes imports
- Remove useless mutable borrow in Client methods
- Add Intellij files to gitignore
- Bump jvm and android version
- Add jvm linux support

### Performance

- Avoid cloning conversation extra members when creating the former

### Refactor

- Moved run_with_* test utils in a test_utils mod
- Use shorthand for generics in Central
- Factorize keystore update when group state change from a conversation pov

### Testing

- Add tests for 'commit_pending_proposals'
- Verify that commit operation are returning a valid welcome if any
- Use Index trait to access conversation from Central instead of duplicate accessor
- Use central instead of conversation
- Fix minor clippy lints in tests
- Apply clippy suggestions on test sources
- Reorganize tests in conversation.rs
- Nest conversation tests in dedicated modules
- Verify adding a keypackage to a ConversationMember

</details>

This second major release focuses on expanding our platform support and featureset

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ✅ (⚠️)
* aarch64-linux-android ✅ (⚠️)
* i686-linux-android ✅ (⚠️)
* x86_64-linux-android ✅ (⚠️)
* aarch64-apple-ios ✅ (⚠️)
* aarch64-apple-ios-sim ✅ (⚠️)
* x86_64-apple-ios ✅ (⚠️)
* wasm32-unknown-unknown ✅

Note: all the platforms marked with (⚠️) above will get a round of polish for the build process & documentation in the next release.

### CoreCrypto

* Majorly improved documentation across all crates. Documentation for the `main` branch can be found here. The `HEAD` of this branch should only be a tagged version.
    * This documentation is available here: <https://wireapp.github.io/core-crypto/core_crypto/>
* Moved the codebase to `async`
    * This was a requirement to make everything work on the WASM target, as we cannot block the JavaScript runtime without making the browsers freeze up completely
    * As a consequence, we forked `openmls` to [wireapp/openmls](https://github.com/wireapp/openmls)
        * Our incremental changes, including the `async` rewrite of `openmls` is located [here](https://github.com/wireapp/openmls/pull/4)
* Added support for MLS Group Persistence, as this was preventing clients from continuing use of their joined groups (oops!)
* **All methods creating a commit e.g. `add_clients_to_conversation` now require to call `commit_accepted` when Delivery Service responds `200 OK`. Otherwise, it might indicate there was a `409 CONFLICT`, i.e. another client sent a commit for current epoch before and got accepted. In that case, do nothing and let things get reconciled in `decrypt_message`**
* Added support for lifetime-expired Keypackage pruning
* Added support for external CSPRNG entropy pool seeding
* Dropped the `openmls-rust-crypto-provider` in favour of our `mls-crypto-provider` with support for more ciphersuites and updated dependencies
    * As a consequence, we forked `hpke-rs` to [wireapp/hpke-rs](https://github.com/wireapp/hpke-rs)
        * Our changes can be found [here](https://github.com/wireapp/hpke-rs/tree/fix/updated-deps)
    * Ciphersuite support details:
        * `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ✅
        * `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` ✅
        * `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` ✅
        * `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` ❌
            * There is no suitable `ed448` rust crate yet
        * `MLS_256_DHKEMP521_AES256GCM_SHA512_P521` ❌
            * `p521` RustCrypto crate is a WIP and not ready just yet. It shouldn't take too long though.
        * `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448` ❌
            * There is no suitable `ed448` rust crate yet
        * `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` ✅

* Expanded the API to include:
    * Conversations:
        * Ability to wipe
        * Ability to leave
        * Ability to force clients to update their keying material (i.e. self-update)
    * Support for MLS proposals
        * Exposed methods to create `Add` / `Remove` / `Update` proposals
    * Support for MLS external commits
        * Added ability to export MLS Public Group State for a given conversation
            * A `PublicGroupState` is also returned everytime you create a commit. This comes from the need to keep the MLS Delivery Service up to date on the `PublicGroupState` so that external commits can be made by other clients.
        * Added support for creating an external commit to join a conversation (`join_by_external_commit`)
    * Support for MLS external Add (`new_external_add_proposal`) and Remove Proposal (`new_external_remove_proposal`).
    * Support for X.509 credentials
    * Added a commit delay hint to prevent clients from rushing to commit to the server - which would cause epoch conflicts and high load
        * Returned in `decrypt_message`
* Changed most `message` fields to be named `commit`, as this would cause less confusion for consumers. Those fields always contained MLS commits and should be treated as such.
* All commit methods now return a `CommitBundle` struct containing
      * the commit message
      * an optional `Welcome` if there were pending add proposals
      * a `PublicGroupState` to upload to the Delivery Service
    * `decrypt_message` now returns a `DecryptedMessage` struct containing:
      * an optional application message
      * optional pending proposals renewed for next epoch to fan out
      * a `is_active` boolean indicating if the decrypted commit message caused the client to be removed from the group
      * the aforementioned commit delay

### FFI

* Added WASM bindings support to target `wasm32-unknown-unknown` as a new tier 1 target.
    * Added a full-fledged TypeScript wrapper with a full documentation to abstract the wasm-specific issues.
    * This now means that CoreCrypto is also now a NPM package. It is currently published at [@otak/core-crypto](https://www.npmjs.com/package/@otak/core-crypto)
* Incremental improvements to the Kotlin & Swift UniFFI bindings
    * Caught up the bindings' API to match our internal CoreCrypto APIs
* Added a C-FFI for maybe future work involving other targets than Kotlin & Swift


### Keystore

* Added support for WASM through an AES-GCM256-encrypted IndexedDB backend
    * This introduced a major refactoring to structure the code around having different backends depending on the platform.

## [0.2.0] - 2022-03-22

<details>
    <summary>git-conventional changelog</summary>

</details>

Initial stable release with a reduced featureset

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ⚠️
* aarch64-linux-android ⚠️
* i686-linux-android ⚠️
* x86_64-linux-android ⚠️
* aarch64-apple-ios ⚠️
* aarch64-apple-ios-sim ⚠️
* x86_64-apple-ios ⚠️
* wasm32-unknown-unknown ❌

This release contains the following features:

### CoreCrypto

* Client abstraction
    * Handles creating/retrieving the locally stored client identity automatically
* Conversation handling
    * Ability to create conversations
    * Message encryption/decryption
    * Ability to add/remove users from a conversation
* Encrypted-at-rest Keystore for persistence of client keying material and keypackages

### FFI

* Added Swift and Kotlin bindings through UniFFI

### Keystore

* Added support for Proteus PreKeys
* Fixed iOS-specific WAL behavior to preserve backgrounding capabilities
    * See the comment at `https://wireapp.github.io/core-crypto/src/core_crypto_keystore/connection/platform/generic/mod.rs#99` for more details
* Fix for migrations being incorrectly defined


