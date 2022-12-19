# Changelog

Platform support legends:

* ✅ = tier 1 support. Things just work.
* ⚠️ = tier 2 support. Things compile but *might* not work as expected. Basically works but with papercuts
    * Note: the papercuts will majorly be with the build process. Things might be very rough to integrate as no polish at all has been given yet.
* ❌ = tier 3 support. It doesn't work just yet, but we plan to make it work.

## [0.6.0-rc.4] - 2022-12-??

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.4" unreleased=true}}
</details>

* Fixed `cargo-make` Makefile.toml to allow building JVM bindings whatever the platform you're running
    * This is done by adding tests to the relevant tasks, allowing to conditionally execute them.
* Added a Makefile task to build the `core_crypto_ffi` Kotlin binding docs (via Dokka) and integrate them into the doc package


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

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.4.0"}}
</details>

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


