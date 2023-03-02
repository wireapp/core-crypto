# Changelog

Platform support legends:

* ✅ = tier 1 support. Things just work.
* ⚠️ = tier 2 support. Things compile but *might* not work as expected. Basically works but with papercuts
    * Note: the papercuts will majorly be with the build process. Things might be very rough to integrate as no polish at all has been given yet.
* ❌ = tier 3 support. It doesn't work just yet, but we plan to make it work.

## [0.7.0] - 2023-03-??

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.7.0" unreleased=true}}
</details>

* **[BREAKING]** `wipe_conversation` is now automatically called when a commit removing the local client is recieved.
* **[BREAKING]** Huge internal change on how we cache MLS groups and Proteus sessions in memory
    * This affects some APIs that became async on the TS bindings
    * Our previous `HashMap`-based cache could grow indefinitely in the case of massive accounts with many, many groups/conversations, each containing a ton of clients. This replaces this memory store by a LRU cache having the following properties:
        * Limited by number of entries AND occupied memory
            * Defaults for memory: All the available system memory on other platforms / 100MB on WASM
            * Defaults for number of entries:
                * 100 MLS groups
                * 200 Proteus sessions
        * Flow for retrieving a value
            1. Check the LRU store if the value exists, if yes, it's promoted as MRU (Most Recently Used) and returned
            2. If not found, it might have been evicted, so we search the keystore
            3. If found in the keystore, the value is placed as MRU and returned
                * Special case: we evict the store as much as needed to fit the new MRU value in this case. This is designed to infaillible.
            5. If not found, we return a `None` value
    * This approach potentially allows to have an unlimited number of groups/sessions as long as a single item does not exceed the maximum memory limit.
    * As a consequence of the internal mutability requirements of the new map and the automatic keystore fetches, many if not all APIs are now `async`. This does not concern the Mobile FFI.

## [0.6.3] - 2023-02-17

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.3"}}
</details>

* Improve compatbillity with older linux versions when running core-crypto-jvm by building on Ubuntu LTS (22.04).

## [0.6.2] - 2023-02-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.2"}}
</details>

* Fixed a bug in the TypeScript bindings where the `DecryptedMessage` bundle could have `commitDelay` set to `undefined` when it should be 0
    * This could happen in the case of external proposals where the system would determine that the proposals should be immediately committed

## [0.6.1] - 2023-02-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.1" }}
</details>

* Fixed a bug where the Proteus last resort prekey could be overwritten.
* Fixed JVM publishing creating broken packages.
* WASM callbacks return false by default if no promise is returned.
* Benchmarks: Remove redundant save when persisting proteus sessions.

## [0.6.0] - 2023-02-13

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0"}}
</details>

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* armv7-linux-androideabi ✅
* aarch64-linux-android ✅
* i686-linux-android ✅
* x86_64-linux-android ✅
* aarch64-apple-ios ✅
* aarch64-apple-ios-sim ✅
* x86_64-apple-ios ✅
* wasm32-unknown-unknown ✅

### 0.6.0 Release changes

* **[BREAKING CHANGE]** E2EI solution API overhauled from pre-release versions
    * This was made to fix some incompatibilities between the DPoP RFC and our code; The API had to be changed as a consequence
    * Please refer to the following point to see the changes
* First stable version of Wire's end-to-end identity client library. It allows a MLS client to generate a x509 certificate proving possession of its userId, clientId and displayName for a given domain/backend. This certificate will later be used as a MLS credential in place of the only currently supported "basic" one which consists of a public key.
    * To generate such a certificate, use the `new_acme_enrollment` method on a partially initialized CoreCrypto instance. This will generate a temporary key material for the enrollment session with the ACME server. Note that only Ed25519 signature scheme is supported at the moment.
    * Only the "enrollment" flow is defined for the moment. Later on, "refresh" and "revocation" flows will be added.
    * This library is heavily opinionated and only suited for **Wire** custom flow, with [our fork of the acme server](https://github.com/wireapp/smallstep-certificates). Any attempt to use it as a generic purpose acme client library will fail terribly.
    * To make sure this works as expected, this library has been tested against the actual [acme-server](https://github.com/wireapp/smallstep-certificates) thanks to [testcontainers](https://www.testcontainers.org/). Only the OIDC provider has been mocked for the moment due to the fact that the target provider [Dex](https://github.com/dexidp/dex) does not yet support Ed25519 signatures.

### 0.6.0 pre-release changes tl;dr, for information

#### Changes

* Added support for externally-generated MLS clients
    * This allows you to generate a standalone Credential/KeyPair, submit it to your MLS Authentication Service, and then update this credential with a newly-attributed Client ID.
* Added APIs to support Proteus Last Resort Prekeys
* Added support for Proteus error codes
    * WASM:
        * all errors are now instances of `CoreCryptoError` which extends the standard JavaScript `Error` but with additional properties:
            * `rustStackTrace` contains the original Rust error string.
            * `proteusErrorCode` contains the error code for Proteus calls. If it's 0, no error, otherwise it contains the code
        * WASM/TS now has access to the `CoreCrypto.proteusLastErrorCode()` method which allows to retrieve the last-occured proteus error and thus brings it to parity with other FFIs
    * On other platforms, the FFI has gained a `proteus_last_error_code` method.
* Fixed a bug where the keystore would not execute its IndexedDB upgrade handler on WASM, leading to older stores and/or new tables not being structurally consistent
* Added missing Proteus APIs to bindings and FFI:
    * `proteus_new_prekey_auto`: generates a new PreKeyBundle with an automatically incremented ID
        * To do this, CoreCrypto finds the first "free" ID within the `0..u16::MAX - 1` range and creates a PreKey using this ID.
* Added Proteus compatibility layer support
* Added API to export secret key derived from the group and client ids from the members
* Change `DecryptedMessage` signature
    * The `decrypt` API now returns if the decrypted message changed the epoch through the `hasEpochChanged` field
* Members can now rejoin group by external commits
    * Validate received external commits
    * Added `clear_pending_group_from_external_commit`
    * External commit returns a bundle containing the PGS


#### Breaking changes


* **[BREAKING CHANGE]** Changed callbacks to be async
    * This allows consumers to perform async I/O within the callbacks
    * **Note** this doesn't affect the Kotlin/Swift bindings as UniFFI does not support async yet.
* **BREAKING** Renamed callback `client_id_belongs_to_one_of` to `client_is_existing_group_user`
* **BREAKING** WASM: Omitted in last build; `CoreCrypto.deferredInit` now takes an object with the parameters much like `init()` for consistency reasons.
* **BREAKING** No one was probably using it, but the C-FFI has been removed


There has been an extensive pre-release period (with many -pre and -rc releases), the original changelog for those has been collapsed below:

<details>
    <summary>0.6.0 pre-releases changelog</summary>

## [0.6.0-rc.8] - 2023-02-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.8"}}
</details>

* Added support for externally-generated MLS clients
    * This allows you to generate a standalone Credential/KeyPair, submit it to your MLS Authentication Service, and then update this credential with a newly-attributed Client ID.
* **[BREAKING CHANGE]** Changed callbacks to be async
    * This allows consumers to perform async I/O within the callbacks
    * **Note** this doesn't affect the Kotlin/Swift bindings as UniFFI does not support async yet.
* Added APIs to support Proteus Last Resort Prekeys

## [0.6.0-rc.7] - 2023-02-06

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.7"}}
</details>

* Fixed WASM build when imported from the outside
    * Made sure we're not leaking internal/private interfaces anymore and causing issues
    * Also added a test to our JS E2E suite to make sure importing the package with TS is successful and we do not encounter regressions like these anymore
* **BREAKING** WASM: Omitted in last build; `CoreCrypto.deferredInit` now takes an object with the parameters much like `init()` for consistency reasons.


## [0.6.0-rc.6] - 2023-02-01

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.6"}}
</details>

**IMPORTANT: The previous release (0.6.0-rc.5) is non-functional in general. The proteus error reporting does NOT work**

There's a post mortem available here: <https://github.com/wireapp/core-crypto/pull/230#issue-1557053094>

* Fixed support for Proteus error codes
    * WASM:
        * all errors are now instances of `CoreCryptoError` which extends the standard JavaScript `Error` but with additional properties:
            * `rustStackTrace` contains the original Rust error string.
            * `proteusErrorCode` contains the error code for Proteus calls. If it's 0, no error, otherwise it contains the code
        * WASM/TS now has access to the `CoreCrypto.proteusLastErrorCode()` method which allows to retrieve the last-occured proteus error and thus brings it to parity with other FFIs
    * On other platforms, the API is unchanged, but now works.


## [0.6.0-rc.5] - 2023-01-25

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.5"}}
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
{{git-cliff tag="v0.6.0-rc.4"}}
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
{{git-cliff tag="v0.6.0-rc.3"}}
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
{{git-cliff tag="v0.6.0-rc.2"}}
</details>

* This release contains nothing. It's only there to fix the faulty Android release CI.

## [0.6.0-rc.1] - 2022-12-14

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.1"}}
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
{{git-cliff tag="v0.6.0-pre.5"}}
</details>

* chore: Get rid of the C-FFI
* feature: Added support for deferred MLS initialization
* Proteus:
    * Expose Proteus session Fingerprints (local & remote)


## [0.6.0-pre.4] - 2022-11-07

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-pre.4"}}
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
{{git-cliff tag="v0.6.0-pre.3"}}
</details>

* Move github action for rust to a maintained one. (More info: https://github.com/actions-rs/toolchain/issues/216)

## [0.6.0-pre.2] - 2022-10.21

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-pre.2"}}
</details>

* Enable proteus support

## [0.6.0-pre.1] - 2022-10.21

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-pre.1"}}
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

</details>

## [0.5.2] - 2022-27-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.5.2"}}
</details>

* Fix: supplied backend's removal key was not TLS serialized but base64 encoded. In this release, it is up to consumer
to base64 decode the key and supply it to core-crypto
* Fix: Typescript enumerations could not be used by value

## [0.5.1] - 2022-21-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.5.1"}}
</details>

* Fix: supplied backend's removal key (used for verifying external remove proposals) was not TLS deserialized
* Fix: incorrect null handing in Typescript wrapper for 'commitPendingProposals' causing an error when there was no proposal to commit
* New test runner for running interoperability tests between various core-crypto clients.
Currently, only native & WASM are supported. Most of all, those tests can be run in our Continuous Integration.

## [0.5.0] - 2022-14-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.5.0"}}
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
{{git-cliff tag="v0.4.2"}}
</details>

* Fixes runtime issues on Android caused by the [sha2](https://github.com/RustCrypto/hashes/tree/master/sha2) crate.

## [0.4.1] - 2022-09-01

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.4.1"}}
</details>

* Fixes build issues for mobile target

## [0.4.0] - 2022-08-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.4.0"}}
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
{{git-cliff tag="v0.3.1"}}
</details>

Maintenance release to prepare for the next release

* Pinned all git dependencies via git tags to avoid breakage in the future


## [0.3.0] - 2022-08-12

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.3.0"}}
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
{{git-cliff tag="v0.2.0"}}
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


