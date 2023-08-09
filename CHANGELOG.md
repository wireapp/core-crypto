# Changelog

Platform support legends:

* ✅ = tier 1 support. Things just work.
* ⚠️ = tier 2 support. Things compile but *might* not work as expected. Basically works but with papercuts
    * Note: the papercuts will majorly be with the build process. Things might be very rough to integrate as no polish at all has been given yet.
* ❌ = tier 3 support. It doesn't work just yet, but we plan to make it work.

## [1.0.0-rc.7] - 2023-08-09

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Kotlin tests not compiling after methods became async

### Features

- Correlate RotateBundle with a GroupId

</details>

* **[BREAKING]** `RotateBundle` now returns a `Map<ConversationId, CommitBundle>` instead of a `Vec<CommitBundle>` in order
to correlate the commit with its group id and to merge it afterwards. Note that the `ConversationId` here is hex encoded due to limitations at the FFI boundary.

## [1.0.0-rc.6] - 2023-08-08

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- `e2eiRotateAll` return type was not wrapped
- Signature KeyPair was rotated when credentials were which was zealous. Also fixes an important bug caused by inverted private & public keypair part when rotating credentials

### Features

- [**breaking**] Handle the case when a client tries to decrypt a Welcome referring to a KeyPackage he already has deleted locally
- Add keystore dump exporter CLI tool

### Miscellaneous Tasks

- Release 1.0.0-rc.6

### Testing

- Add a roundtrip test for e2ei credential rotation to tackle a false positive regression

</details>

* Add keystore dump CLI tool to debug internal applications and export the content of the keystore for further analysis
* handle the "orphan welcome" corner case when the client receives a Welcome but already has deleted the associated KeyPackage.
In that case he has to catch & ignore the "OrphanWelcome" error and to rejoin the group with an external commit.
* Fix credential rotation in end-to-end identity was signing the certificate with the wrong keypair part
* Fix `e2eiRotateAll` return type was not correctly wrapped in a object in Typescript

## [1.0.0-rc.5] - 2023-07-31

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- E2ei enum for conversation state was unused and failing the Typescript publication. Now CI will have the same compiler flags when checking bindings in order to prevent this again

### Miscellaneous Tasks

- Release 1.0.0-rc.5

</details>

* Fix WASM publication issues

## [1.0.0-rc.4] - 2023-07-31

<details>
    <summary>git-conventional changelog</summary>

### Miscellaneous Tasks

- Release 1.0.0-rc.4
- Patch visibility issue for enum 'E2eiConversationState' which was failing when building Typescript bindings

</details>

* Fix WASM publication issues

## [1.0.0-rc.3] - 2023-07-31

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Proteus wasm test now uses wasm-browser-run
- Cargo doc fixes for wasm-browser-run
- Interop runner now uses wasm-browser-run to install chromedriver
- Support chromedriver 115 delivery method
- `e2ei_rotate_all` was returning 'undefined' on WASM
- [**breaking**] Entities leaked. Some methods handling the lifecycle of a MLS group were not cleaning created entities correctly. This avoids required storage space to grow linearly.

### Features

- [**breaking**] Rename `e2eiIsDegraded` by `e2eiConversationState` and change return type to an enumeration instead of a boolean to match all the e2ei states a conversation could have.
- Add `e2ei_is_enabled` for clients to spot if their MLS client is enrolled for end-to-end identity

### Miscellaneous Tasks

- Release 1.0.0-rc.3
- Update rstest versions
- Updated xtask deps

</details>


* Ensure that all operations do not leak data (uncleared from the keystore). This was mostly happening with update proposals & credential rotation. Also introduced a separate table for storing epoch keypairs.
* **[BREAKING]** as a consequence (of the new table) all existing conversations are becoming unusable. It is strongly advised to wipe them all.
* Fix method `e2eiRotateAll` was returning undefined on WASM
* Add method `e2eiIsEnabled` to tell if a MLS client has a valid Credential for the given Ciphersuite
* **[BREAKING]** rename ~~`e2eiIsDegraded`~~ into `e2eiConversationState` which returns now an enumeration giving the state of the conversation regarding end-to-end identity.
* Adapt CI to execute WASM tests with chromedriver 115

## [1.0.0-rc.2] - 2023-07-25

<details>
    <summary>git-conventional changelog</summary>

### Features

- [**breaking**] Expose 'ClientId' in e2ei methods for credential rotation since the e2ei client identifier differs from the one used in MLS
- Include certificate roots and certificate policy in GroupContext - WPB-1188

### Miscellaneous Tasks

- Release v1.0.0-rc.2

</details>

* Added support for x509 certificate roots and policies in MLS GroupContext through a TrustAnchor GroupContextExtension #346
* Fixed a CI issue that prevented Swift and JVM package publication

## [1.0.0-rc.1] - 2023-07-20

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- `merge_pending_group_from_external_commit` FFI incorrect return type
- UniFFI bindgen requirements & size tweaks
- Address review comments
- Revert bloating up binaries by emitting crate-type=lib
- Strip mobile libraries
- Handles nicely self-commits

### Documentation

- Add document to detail our crypto primitives

### Features

- Buffer pending messages during join by external commit process to tolerate unordered messages
- Use -dalek fast proteus version
- Use RFC9420 OpenMLS [WPB-579]

### Miscellaneous Tasks

- Release v1.0.0-rc.1
- Build swift bindings with xcode 14.3.1 ([#342](https://github.com/wireapp/core-crypto/issues/342))
- Update HPQ hpke to bump dalek
- Stop shipping kotlin UniFFI bindings [WPB-1180]
- [**breaking**] UniFFI 0.24 upgrade
- Update deps
- Tweak cargo-deny CI
- Whitelist Kyber fork dependency

</details>

* **[BREAKING]** With this release, CoreCrypto is now [RFC9420](https://www.rfc-editor.org/rfc/rfc9420.txt) compliant.
    * This will cause Draft-20 clients to be unable to process keypackages emitted by RFC clients; But the opposite isn't true as RFC clients will ignore the extraneous `Capabilities` Draft-20 clients emit.
* **[BREAKING]** With our update to UniFFI 0.24, the FFI & bindings have significant breaking changes
    * Most if not all APIs are now `async` and will use the platform's executor thanks to UniFFI's integration with them. In terms of platforms, the consequences are the following:
        * Kotlin: Almost all APIs are now `suspend`
        * Swift: Almost all APIs are now `async`
        * TypeScript: A couple more APIs are now `async` compared to before
    * Some other things might have changed - the callbacks ABI has changed but this change should not affect users of our bindings as we try to erase those minute differences by wrapping everything in a stable API
* **[BREAKING]** CoreCrypto now handles self-commits sent by the backend and decrypted by the client.
    * In a particular case, when the backend replays a commit, the client is not to blame.
        * In that case, `decryptMessage` will return a `SelfCommitIgnored` which you should catch and ignore. It means you are likely to already have merged this commit.
* **[BREAKING]** CoreCrypto now handles duplicate application or handshake messages.
    * When such a case happens, `decryptMessage` will return a `DuplicateMessage` error encapsulating a `GenerationOutOfBound` error. The latter variant also has been removed.
* **[BREAKING]** To mitigate unordered messages when joining with an external commit, incoming messages are now buffered until you merge the external commit with `mergePendingGroupFromExternalCommit`.
    * At that point they are replayed and their result return in the method return type ; hence make sure to read and handle it!
    * Note that for messages arriving during the external commit merge window, `decryptMessage` will return a `UnmergedPendingGroup` error which means the edge case has been identified and the message will be reapplied later; so feel free to catch and ignore this error.
* *[SEMI-BREAKING]* CoreCrypto now prevents overwriting an existing conversation when creating a new conversation, joining one with a Welcome or joining with an external commit.
    * This is within an effort to harden our data storage policies and to provide better feedback to API consumers as to what is actually happening.
    * This change also is a breaking behavior change - But you should not be abusing the existing mechanic anyway to replace conversations as this was an unintended bug
* Our CI is now building the Swift bindings with Xcode 14.3.1
* We managed to reduce the size of our libraries by stripping them afterwards
* *[EXPERIMENTAL]* This version of CoreCrypto is the first to ship with a Proteus compatibility layer that uses the same cryptographic primitives as the MLS counterparts
    * This yields in practice performance gains between 20% and 900% depending on the type of operation
    * Again, as this is an experimental change, things *might* break.



## [1.0.0-pre.8] - 2023-07-18

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Use correct env var for maven central credentials ([#355](https://github.com/wireapp/core-crypto/issues/355))

### Miscellaneous Tasks

- Release v1.0.0-pre.8


### Bug Fixes

- Make clippy happy
- Xtask release fix for kotlin sonatype publishing
- Disable stripping to allow FFI to build
- Incorrect error value in tests

### Features

- [**breaking**] Prevent conversation overwrite when joining
- [**breaking**] Detect duplicate messages from previous epoch and fail with a dedicated error
- Publish to Sonatype instead of Github Packages ([#347](https://github.com/wireapp/core-crypto/issues/347))

### Miscellaneous Tasks

- Release v1.0.0-pre.7
- Pin dependencies on wireapp org forks


### Bug Fixes

- Wrong HPQ ciphersuite identifier
- Address review & de-flakify cert expiration test
- Target correct branches
- PQ support for FFI
- Benches modification

### Features

- [**breaking**] Credential rotation
- PostQuantum Ciphersuite
- [**breaking**] Remove `export_group_info()`


### Bug Fixes

- Backend sends raw GroupInfo, we were trying to deserialize it from a MlsMessage


### Bug Fixes

- Pin a version of openmls with a fix in tls_codec related to variable length encoding

### Testing

- Fix external commit test was not merging the external commit


### Bug Fixes

- Typo in build xcframework task


### Features

- CoreCrypto draft-20 upgrade
- Generate XCFramework when releasing for Swift ([#330](https://github.com/wireapp/core-crypto/issues/330))


### Features

- Add `e2ei_is_degraded` to flag a conversation as degraded when at least 1 member is not using a e2ei certificate


### Bug Fixes

- Usize to u64 conversion error on Android in `client_valid_keypackages_count`. Whatever the reason this applies a default meaningful value
- [**breaking**] Creating a MLS group does not consume an existing KeyPackage anymore, instead it always generates a new local one. Also, explicitly ask for the credential type of the creator before creating a new MLS group.
- Mobile FFI was failing when initializing MLS client due to a Arc being incremented one too many times. Also add the E2EI API in the Kotlin wrapper and a test for it

### Features

- [**breaking**] Hide everywhere `Vec<Ciphersuite>` appears in the public API since it seems to fail for obscure reasons on aarch64 Android devices. Undo when we have a better understanding of the root cause of this


### Bug Fixes

- New table was mistakenly in an old migration file

### Miscellaneous Tasks

- Release v0.9.2


### Bug Fixes

- Size regression on FFI

### Miscellaneous Tasks

- Release v0.9.1


### Bug Fixes

- Reload proteus sessions when `restore_from_disk` is called
- Return finalize & certificate url

### Features

- Add persistence options to e2ei enrollment instance
- [**breaking**] Enable multi ciphersuite and multi credential type support
- [**breaking**] Support & expose "target" in ACME challenges

### Miscellaneous Tasks

- Fix clippy lints for wasm target

### Refactor

- Moved Client methods related to keypackage in a dedicated mod
- Moved function `identity_key` into a trait
- Replace `either` by a dedicated enum since after all there could be more than just 2 types of credentials
- Move ClientId to dedicated mod

### Testing

- Have interop runner verify the generic FFI


### Miscellaneous Tasks

- Update bindings ([#312](https://github.com/wireapp/core-crypto/issues/312))


### Bug Fixes

- Native libraries not included in android package ([#308](https://github.com/wireapp/core-crypto/issues/308))
- Typescript path has the wrong file extension ([#309](https://github.com/wireapp/core-crypto/issues/309))


### Bug Fixes

- Fixed iOS keychain handling with proper attributes

### Features

- Verify x509 credential identity and return identity (client_id, handle, display_name, domain) once message is decrypted

### Miscellaneous Tasks

- Release v0.7.0
- Update deps & cargo-deny configuration
- Get rid of internal 'CredentialSupplier' test util


### Bug Fixes

- [**breaking**] Tweak WASM API
- Use schnellru fork for GroupStore faillible inserts
- Fixed GroupStore memory limiter behavior

### Features

- Remove any transitive crate using ring. As a consequence supports EcDSA on WASM
- Copy/modify kotlin wrapper from Kalium ([#284](https://github.com/wireapp/core-crypto/issues/284))
- [**breaking**] Support creating a MLS client from an e2e identity certificate

### Miscellaneous Tasks

- Release v0.7.0-rc.4
- Update interop runner `dirs` dep
- Appease clippy


### Bug Fixes

- Proteus auto prekey ids not incrementing

### Miscellaneous Tasks

- Release v0.7.0-rc.3


### Miscellaneous Tasks

- Release v0.7.0-rc.2


### Bug Fixes

- [**breaking**] Make FFI parameters compliant with rfc8555
- Added missing version() function to Swift bindings
- Enable ios-wal-compat for iOS builds by default
- Exclude self from self-remove-commit delay
- Fix rustsec advisories on xtask deps

### Features

- [**breaking**] Latest e2e identity iteration. ClientId (from MLS) is used instead of requiring just parts of it
- Added API to check the `Arc` strongref counter
- [**breaking**] Add ability to mark subconversations
- [**breaking**] Change proteus auto prekey return type to include prekey id
- [**breaking**] Added LRU cache-based underlying group store to replace the HashMaps

### Miscellaneous Tasks

- Release 0.7.0-rc.1
- Use crates.io sparse protocol on CI via env
- Android upgrade to NDK 25 + openssl android build fix
- Updated serde-wasm-bindgen to 0.5.0
- Updated crypto deps (p256/384 & ecdsa)
- Updated changelog for LRU store changes
- [**breaking**] Drop LRU from keystore
- Bump webdriver version to 110


### Miscellaneous Tasks

- Release 0.6.3 ([#258](https://github.com/wireapp/core-crypto/issues/258))
- Build linux artifacts on Ubuntu LTS for better compatibility ([#257](https://github.com/wireapp/core-crypto/issues/257))


### Bug Fixes

- Fixed commitDelay being undefined when FFI says 0

### Miscellaneous Tasks

- Release v0.6.2
- Fix native libraries not loading by moving them to the package root ([#255](https://github.com/wireapp/core-crypto/issues/255))


### Bug Fixes

- Publishing for JVM generating empty artifacts ([#251](https://github.com/wireapp/core-crypto/issues/251))
- Fall back on false when the callback doesn't retrurn a Promise
- Proteus auto prekey might overwrite Last Resort prekey

### Miscellaneous Tasks

- Release 0.6.1 ([#253](https://github.com/wireapp/core-crypto/issues/253))
- Remove proteus double persistence as it's already automatically eager


### Bug Fixes

- Xtask release outputs dry-run log unconditionally

### Features

- Adapt with acme client library tested on real acme-server forked. Also some nits & dependencies pinned

### Miscellaneous Tasks

- Release v0.6.0


### Features

- Added support for Proteus Last Resort PreKeys (boooo!)
- [**breaking**] Async callbacks
- Externally-generated clients

### Miscellaneous Tasks

- Release v0.6.0-rc.8
- Updated webdriver version to chrome 110


### Bug Fixes

- Fixed E2E interop test for breaking api changes
- New e2eidentityerror enum member wasn't exposed over ffi
- TS/WASM build issues & test

### Miscellaneous Tasks

- Release v0.6.0-rc.7


### Bug Fixes

- Proteus error system not working (at all)
- Force cargo to use git cli to avoid intermittent CI failures

### Miscellaneous Tasks

- Release v0.6.0-rc.6
- Updated rstest_reuse to 0.5
- Updated spinoff to 0.7
- Added codecov settings
- Update node to LTS 18 & enable JS e2e testing
- Make npm build run wasm-opt in Os
- Update JVM publish workflow to build on native platforms ([#229](https://github.com/wireapp/core-crypto/issues/229))


### Bug Fixes

- [**breaking**] Added conversation id to clientIsExistingGroupUser callback
- Increment IndexedDB store version when crate version changes

### Features

- Added support for Proteus error codes

### Miscellaneous Tasks

- Cut release 0.6.0-rc.5
- Moved codecov from tarpaulin to llvm-cov
- Updated RustCrypto primitives & git dep in xtask


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

* This is a release that contains nothing new. This is to fix the previous Kotlin release that was not correctly built & released.

## [1.0.0-pre.7] - 2023-07-17

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Make clippy happy
- Xtask release fix for kotlin sonatype publishing
- Disable stripping to allow FFI to build
- Incorrect error value in tests

### Features

- [**breaking**] Prevent conversation overwrite when joining
- [**breaking**] Detect duplicate messages from previous epoch and fail with a dedicated error
- Publish to Sonatype instead of Github Packages ([#347](https://github.com/wireapp/core-crypto/issues/347))

### Miscellaneous Tasks

- Release v1.0.0-pre.7
- Pin dependencies on wireapp org forks

</details>

* **[BREAKING]** We now detect duplicate messages from previous epochs, as such the `GenerationOutOfBound` error is now named `DuplicateMessage`.
* **[BREAKING]** We now throw errors when consumers try to create or join a group via Welcome message BUT the group already exists within our store. This is to prevent accidental group erasure in case of duplicate notifications from the DS. Note that the API does not change with this but presents a breaking behavior change.
* We pinned some private forks under the @wireapp GitHub org to secure our software supply chain.


## [1.0.0-pre.6] - 2023-07-06

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Wrong HPQ ciphersuite identifier
- Address review & de-flakify cert expiration test
- Target correct branches
- PQ support for FFI
- Benches modification

### Features

- [**breaking**] Credential rotation
- PostQuantum Ciphersuite
- [**breaking**] Remove `export_group_info()`

</details>

* feat!: PostQuantum Ciphersuite support ! Using [Xyber768](https://www.ietf.org/archive/id/draft-westerbaan-cfrg-hpke-xyber768d00-02.html) for Key Exchange.
* feat! Credential rotation support (for E2E Identity). It allows to change the local client Credential in a MLS group, replacing it with a X509 Certificate one.
* feat!: remove `export_group_info()` method that wasn't used

## [1.0.0-pre.5] - 2023-06-12

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Backend sends raw GroupInfo, we were trying to deserialize it from a MlsMessage

</details>

* fix: `joinByExternalCommit` was expecting a `GroupInfo` wrapped in a MlsMessage

## [1.0.0-pre.4] - 2023-06-12

<details>
    <summary>git-conventional changelog</summary>

</details>

* build: fixed different sources of tls_codec

## [1.0.0-pre.3] - 2023-06-11

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Pin a version of openmls with a fix in tls_codec related to variable length encoding

### Testing

- Fix external commit test was not merging the external commit

</details>

* fix: tls_codec had an issue with variable length encoding

## [1.0.0-pre.1] - 2023-06-11

<details>
    <summary>git-conventional changelog</summary>

### Features

- CoreCrypto draft-20 upgrade
- Generate XCFramework when releasing for Swift ([#330](https://github.com/wireapp/core-crypto/issues/330))


### Features

- Add `e2ei_is_degraded` to flag a conversation as degraded when at least 1 member is not using a e2ei certificate


### Bug Fixes

- Usize to u64 conversion error on Android in `client_valid_keypackages_count`. Whatever the reason this applies a default meaningful value
- [**breaking**] Creating a MLS group does not consume an existing KeyPackage anymore, instead it always generates a new local one. Also, explicitly ask for the credential type of the creator before creating a new MLS group.
- Mobile FFI was failing when initializing MLS client due to a Arc being incremented one too many times. Also add the E2EI API in the Kotlin wrapper and a test for it

### Features

- [**breaking**] Hide everywhere `Vec<Ciphersuite>` appears in the public API since it seems to fail for obscure reasons on aarch64 Android devices. Undo when we have a better understanding of the root cause of this

</details>

* **[BREAKING]**: MLS draft-20 !
  * internally use the latest version of openmls compatible with draft-20 (not yet RFC9420)
  * `Public Group State` methods/fields etc.. have been renamed into `Group Info`
  * `CommitBundle` fields (welcome, commit, group_info) are now wrapped in MLS messages
  * `new_external_proposal()` has been removed
  * By default, partial commits (w/o UpdatePath) are created

## [0.11.0] - 2023-05-31

<details>
    <summary>git-conventional changelog</summary>

### Features

- Add `e2ei_is_degraded` to flag a conversation as degraded when at least 1 member is not using a e2ei certificate

</details>

* **[BREAKING]**: fix Ciphersuite lowering for mobile FFI, using either a 16-bit integer (or a List of it) to lower those types across the FFI.
* **[BREAKING]**: removed optional entropy_seed from public API only on mobile since it was not required there and was causing the aforementioned issue with list of ciphersuites.

## [0.10.0] - 2023-05-25

<details>
    <summary>git-conventional changelog</summary>

</details>

* **[BREAKING]**: creating a MLS group was consuming an existing KeyPackage which could lead to inconsistencies if the
former isn't pruned on the backend side. As a consequence, `createConversation()` now expects the CredentialType to pick the right credential the author wants to join the group with.
* **[BREAKING]**: fixed unsound bug happening on aarch64 Android devices because of lowering a List of enumerations across
the FFI. Still uncertain about the root cause but to move on all the parameters like: `ciphersuite: List<Ciphersuite>` in the public API have been replaced with a default value
* Fixed Android FFI bug in `e2eiMlsInit` where a reference counter had one too many reference when trying to destroy it

## [0.9.2] - 2023-05-22

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- New table was mistakenly in an old migration file

### Miscellaneous Tasks

- Release v0.9.2

</details>

* Fixed migrations not running because of a mistakenly added table in an older migration version

## [0.9.1] - 2023-05-17

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Size regression on FFI

### Miscellaneous Tasks

- Release v0.9.1

</details>

* Fixed excessive bloat in the FFI layer due to emitting rlibs

## [0.9.0] - 2023-05-16

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Reload proteus sessions when `restore_from_disk` is called
- Return finalize & certificate url

### Features

- Add persistence options to e2ei enrollment instance
- [**breaking**] Enable multi ciphersuite and multi credential type support
- [**breaking**] Support & expose "target" in ACME challenges

### Miscellaneous Tasks

- Fix clippy lints for wasm target

### Refactor

- Moved Client methods related to keypackage in a dedicated mod
- Moved function `identity_key` into a trait
- Replace `either` by a dedicated enum since after all there could be more than just 2 types of credentials
- Move ClientId to dedicated mod

### Testing

- Have interop runner verify the generic FFI

</details>

* First iteration of multi-ciphersuite support. The API now explicitly requires a Ciphersuite to be supplied anywhere where it's necessary. For now on you should only use the default one. Same thing for `MlsCredentialType`, use `Basic` whenever required
* Allow persisting an e2e identity enrollment for web's needs
* `check_order_response` & `finalize_response` now return the URL for where the next step's payload has to be sent
* ACME challenges now have a "target" field which indicates the URL of the OAuth authorization and the access token endpoint

## [0.8.2] - 2023-04-28

<details>
    <summary>git-conventional changelog</summary>

### Miscellaneous Tasks

- Update bindings ([#312](https://github.com/wireapp/core-crypto/issues/312))

</details>

* build: fix Android packaging (again) by sourcing bindings

## [0.8.1] - 2023-04-27

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Native libraries not included in android package ([#308](https://github.com/wireapp/core-crypto/issues/308))
- Typescript path has the wrong file extension ([#309](https://github.com/wireapp/core-crypto/issues/309))

</details>

* build: fix Android packaging

## [0.8.0] - 2023-04-19

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Fixed iOS keychain handling with proper attributes

### Features

- Verify x509 credential identity and return identity (client_id, handle, display_name, domain) once message is decrypted

### Miscellaneous Tasks

- Release v0.7.0
- Update deps & cargo-deny configuration
- Get rid of internal 'CredentialSupplier' test util

</details>

* **[BREAKING]**(e2e identity): added an expiry in seconds in `create_dpop_token`)

## [0.7.0] - 2023-04-12

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Fixed iOS keychain handling with proper attributes

### Features

- Verify x509 credential identity and return identity (client_id, handle, display_name, domain) once message is decrypted

### Miscellaneous Tasks

- Release v0.7.0
- Update deps & cargo-deny configuration
- Get rid of internal 'CredentialSupplier' test util


### Bug Fixes

- [**breaking**] Tweak WASM API
- Use schnellru fork for GroupStore faillible inserts
- Fixed GroupStore memory limiter behavior

### Features

- Remove any transitive crate using ring. As a consequence supports EcDSA on WASM
- Copy/modify kotlin wrapper from Kalium ([#284](https://github.com/wireapp/core-crypto/issues/284))
- [**breaking**] Support creating a MLS client from an e2e identity certificate

### Miscellaneous Tasks

- Release v0.7.0-rc.4
- Update interop runner `dirs` dep
- Appease clippy


### Bug Fixes

- Proteus auto prekey ids not incrementing

### Miscellaneous Tasks

- Release v0.7.0-rc.3


### Miscellaneous Tasks

- Release v0.7.0-rc.2


### Bug Fixes

- [**breaking**] Make FFI parameters compliant with rfc8555
- Added missing version() function to Swift bindings
- Enable ios-wal-compat for iOS builds by default
- Exclude self from self-remove-commit delay
- Fix rustsec advisories on xtask deps

### Features

- [**breaking**] Latest e2e identity iteration. ClientId (from MLS) is used instead of requiring just parts of it
- Added API to check the `Arc` strongref counter
- [**breaking**] Add ability to mark subconversations
- [**breaking**] Change proteus auto prekey return type to include prekey id
- [**breaking**] Added LRU cache-based underlying group store to replace the HashMaps

### Miscellaneous Tasks

- Release 0.7.0-rc.1
- Use crates.io sparse protocol on CI via env
- Android upgrade to NDK 25 + openssl android build fix
- Updated serde-wasm-bindgen to 0.5.0
- Updated crypto deps (p256/384 & ecdsa)
- Updated changelog for LRU store changes
- [**breaking**] Drop LRU from keystore
- Bump webdriver version to 110

</details>

* Please see the previous RC releases for the full changelog
* Fixed a bug in the iOS WAL compatibility layer that didn't specific correct keychain attributes on the stored SQLCipher salt
* Updated internal dependencies
* Implemented E2EI credential identity verification
    * We are now returning extra data on decrypted messages; you'll be able to get the sender's full identity in them.

## [0.7.0-rc.4] - 2023-03-28

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- [**breaking**] Tweak WASM API
- Use schnellru fork for GroupStore faillible inserts
- Fixed GroupStore memory limiter behavior

### Features

- Remove any transitive crate using ring. As a consequence supports EcDSA on WASM
- Copy/modify kotlin wrapper from Kalium ([#284](https://github.com/wireapp/core-crypto/issues/284))
- [**breaking**] Support creating a MLS client from an e2e identity certificate

### Miscellaneous Tasks

- Release v0.7.0-rc.4
- Update interop runner `dirs` dep
- Appease clippy

</details>

* Updated UniFFI to 0.23
    * Might or might not contain breaking changes depending on your use case, please refer to [UniFFI's documentation](https://github.com/mozilla/uniffi-rs/blob/main/CHANGELOG.md)
* Fixed a small bug in the new GroupStore internals that was a bit too eager in limiting memory usage
* **[BREAKING]**: Renamed the WASM `strongRefCount(): number` API to `isLocked(): boolean`.
    * This essentially hides the implementation details across the FFI and should minimize brittleness
* Removed our dependency on [ring](https://github.com/briansmith/ring), an external crypto library. It was mostly used for validating x509 certificates and crafting Certificate Signing Request
    * By removing `ring`, we now support the following MLS Ciphersuites using NIST elliptic curves / ECDSA on WASM:
        * `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (`0x0002`)
        * `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` (`0x0007`)
* **[BREAKING]**: Overhauled parts of the E2EI implementation
      * Moved from a stateless API to a stateful one. As a consequence, methods have less parameters, less structs need to be exposed. All of this is wrapped under Rust's safe sync primitives in order to be able to perform the ACME enrollment in parallel.
      * The new API allows creating a MLS group from the enrollment process.
        * ~~`certificateResponse()`~~ has been removed
        * `e2eiMlsInit()` has been introduced and permits ending the enrollment flow and use the x509 certificate to initialize a MLS client.
      * `ClientId` is now a string as per [RFC8555](https://www.rfc-editor.org/rfc/rfc8555). It does not anymore require to be prefixed (by `impp:wireapp=`) and is exactly the same as the one used for MLS
      * X509 SAN URIs are now prefixed by `im:wireapp=` instead of `impp:wireapp=`
      * This release has been tested against a real OIDC provider ([Dex](https://dexidp.io/)), federating identity from a LDAP server. The OAuth2 flow used for testing is [Authorization Code with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce)
      * Private key materials are now properly zeroized



## [0.7.0-rc.3] - 2023-03-16

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Proteus auto prekey ids not incrementing

### Miscellaneous Tasks

- Release v0.7.0-rc.3

</details>

* Fixed a bug where `proteus_new_prekey_auto` returning the same prekey ID in particular cases
    * In case of "gaps" in the prekey id sequence, the previous algorithm (using the number of prekeys stored) would return the same ID over and over. As a consequence, the same prekey id would be overwritten over and over.

## [0.7.0-rc.2] - 2023-03-15

<details>
    <summary>git-conventional changelog</summary>

### Miscellaneous Tasks

- Release v0.7.0-rc.2

</details>

* Fix on documentation that prevented release on many platforms

## [0.7.0-rc.1] - 2023-03-15

<details>
    <summary>git-conventional changelog</summary>

</details>

* **[BREAKING]** proteus_new_prekey_auto() now returns a tuple of (prekey_id, CBOR-serialized PreKeyBundle) for backend requirements
    * On bindings, this translates to a new struct ProteusAutoPrekeyBundle which contains two fields:
        * `id`: the proteus prekey id (`u16`)
        * `pkb`: the CBOR-serialized proteus PreKeyBundle
* **[BREAKING]** Added an API to mark subconversations as child of another one (`mark_conversation_as_child_of`)
    * This is breaking because this now allows us to provide the parent conversation's client list in the `client_is_existing_group_user` callback, which adds a new parameter to it
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
* **[BREAKING]** Because of Rust 1.68's release, CoreCrypto is now incompatible with Android NDK versions under 25.2 (the LTS version) and Android API level 24.
* **[BREAKING]** E2EI: The API is now compliant with RFC8555
    * Another change will come soon to be able to initialize a MLS client using the X509 certificate issued by the E2EI process
* Enabled the iOS WAL compatibility layer to prevent spurious background kills
* Added a WASM api to check the Arc strongref counter

## [0.6.3] - 2023-02-17

<details>
    <summary>git-conventional changelog</summary>

### Miscellaneous Tasks

- Release 0.6.3 ([#258](https://github.com/wireapp/core-crypto/issues/258))
- Build linux artifacts on Ubuntu LTS for better compatibility ([#257](https://github.com/wireapp/core-crypto/issues/257))

</details>

* Improve compatbillity with older linux versions when running core-crypto-jvm by building on Ubuntu LTS (22.04).

## [0.6.2] - 2023-02-16

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Fixed commitDelay being undefined when FFI says 0

### Miscellaneous Tasks

- Release v0.6.2
- Fix native libraries not loading by moving them to the package root ([#255](https://github.com/wireapp/core-crypto/issues/255))

</details>

* Fixed a bug in the TypeScript bindings where the `DecryptedMessage` bundle could have `commitDelay` set to `undefined` when it should be 0
    * This could happen in the case of external proposals where the system would determine that the proposals should be immediately committed

## [0.6.1] - 2023-02-16

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Publishing for JVM generating empty artifacts ([#251](https://github.com/wireapp/core-crypto/issues/251))
- Fall back on false when the callback doesn't retrurn a Promise
- Proteus auto prekey might overwrite Last Resort prekey

### Miscellaneous Tasks

- Release 0.6.1 ([#253](https://github.com/wireapp/core-crypto/issues/253))
- Remove proteus double persistence as it's already automatically eager


### Bug Fixes

- Xtask release outputs dry-run log unconditionally

### Features

- Adapt with acme client library tested on real acme-server forked. Also some nits & dependencies pinned

### Miscellaneous Tasks

- Release v0.6.0

</details>

* Fixed a bug where the Proteus last resort prekey could be overwritten.
* Fixed JVM publishing creating broken packages.
* WASM callbacks return false by default if no promise is returned.
* Benchmarks: Remove redundant save when persisting proteus sessions.

## [0.6.0] - 2023-02-13

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Xtask release outputs dry-run log unconditionally

### Features

- Adapt with acme client library tested on real acme-server forked. Also some nits & dependencies pinned

### Miscellaneous Tasks

- Release v0.6.0


### Features

- Added support for Proteus Last Resort PreKeys (boooo!)
- [**breaking**] Async callbacks
- Externally-generated clients

### Miscellaneous Tasks

- Release v0.6.0-rc.8
- Updated webdriver version to chrome 110


### Bug Fixes

- Fixed E2E interop test for breaking api changes
- New e2eidentityerror enum member wasn't exposed over ffi
- TS/WASM build issues & test

### Miscellaneous Tasks

- Release v0.6.0-rc.7


### Bug Fixes

- Proteus error system not working (at all)
- Force cargo to use git cli to avoid intermittent CI failures

### Miscellaneous Tasks

- Release v0.6.0-rc.6
- Updated rstest_reuse to 0.5
- Updated spinoff to 0.7
- Added codecov settings
- Update node to LTS 18 & enable JS e2e testing
- Make npm build run wasm-opt in Os
- Update JVM publish workflow to build on native platforms ([#229](https://github.com/wireapp/core-crypto/issues/229))


### Bug Fixes

- [**breaking**] Added conversation id to clientIsExistingGroupUser callback
- Increment IndexedDB store version when crate version changes

### Features

- Added support for Proteus error codes

### Miscellaneous Tasks

- Cut release 0.6.0-rc.5
- Moved codecov from tarpaulin to llvm-cov
- Updated RustCrypto primitives & git dep in xtask


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

### Features

- Added support for Proteus Last Resort PreKeys (boooo!)
- [**breaking**] Async callbacks
- Externally-generated clients

### Miscellaneous Tasks

- Release v0.6.0-rc.8
- Updated webdriver version to chrome 110

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

### Bug Fixes

- Fixed E2E interop test for breaking api changes
- New e2eidentityerror enum member wasn't exposed over ffi
- TS/WASM build issues & test

### Miscellaneous Tasks

- Release v0.6.0-rc.7

</details>

* Fixed WASM build when imported from the outside
    * Made sure we're not leaking internal/private interfaces anymore and causing issues
    * Also added a test to our JS E2E suite to make sure importing the package with TS is successful and we do not encounter regressions like these anymore
* **BREAKING** WASM: Omitted in last build; `CoreCrypto.deferredInit` now takes an object with the parameters much like `init()` for consistency reasons.


## [0.6.0-rc.6] - 2023-02-01

<details>
    <summary>git-conventional changelog</summary>

### Bug Fixes

- Proteus error system not working (at all)
- Force cargo to use git cli to avoid intermittent CI failures

### Miscellaneous Tasks

- Release v0.6.0-rc.6
- Updated rstest_reuse to 0.5
- Updated spinoff to 0.7
- Added codecov settings
- Update node to LTS 18 & enable JS e2e testing
- Make npm build run wasm-opt in Os
- Update JVM publish workflow to build on native platforms ([#229](https://github.com/wireapp/core-crypto/issues/229))

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

### Bug Fixes

- [**breaking**] Added conversation id to clientIsExistingGroupUser callback
- Increment IndexedDB store version when crate version changes

### Features

- Added support for Proteus error codes

### Miscellaneous Tasks

- Cut release 0.6.0-rc.5
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
