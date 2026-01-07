# Changelog

## Unreleased

### Features

- removed `CoreCrypto.provideTransport()`, added `transport` parameter to `CoreCryptoContext.mlsInit()`

  Instead of providing transport separately from session initialization it is now provided when initializing the MLS
  session.

  Affected platforms: android, ios, web

- renamed `CoreCrypto.reseedRng()` to `CoreCrypto.reseed()`

  Affected platforms: web

- removed `CoreCryptoFfi.reseedRng()` and `CoreCryptoFfi.randomBytes()`

  Affected platforms: android, ios

- removed `.proteusFingerprintPrekeybundle()` and `.proteusLastResortPrekeyId()` from `CoreCryptoContext`.

  Both are available as static methods on `CoreCrypto`.

  Affected platforms: android, ios, web

- We now generate the ts bindings from the same uniffi code that swift and kotlin use.

  - Arrays are now passed as ArrayBuffer between client and the FFI layer, changing parameter and return types.

    Use `.buffer()` to get `ArrayBuffer` from `Uint8Array`.

    Use `new Uint8Array(buffer)` to get a Uint8Array from an `ArrayBuffer`.

  - `CustomConfiguration.keyRotationSpan` now defines milliseconds instead of seconds

  Affected platforms: web

#### New Credential API

- `Credential` is a first-class type representing a cryptographic identity.
  - It can be created at any time and lives in memory.
  - There are two variants of credential: basic and x509. Basic credentials are created with `Credential.basic` static
    method. **TODO DO NOT RELEASE BEFORE REWRITING THIS** X509 credentials are created with `TODO TODO`.
- Initializing a MLS client no longer automatically generates any credentials. Any stored credentials will be
  automatically loaded on MLS init.
- To add a credential to the set MLS knows about, after initializing MLS, call `addCredential` on a transaction context.
  - This adds it to the working set, and stores it to the database.
  - Due to limitations inherent in the current implementation, credentials added to a client must currently be distinct
    on the `(credential type / signature scheme / unix timestamp of creation)` tuple.
    - The time resolution is limited to 1 second
    - If you have need of multiple credentials for a given signature scheme and credential type, just wait 1 full second
      between adding each of them
    - We expect this limitation to be relaxed in the future
  - This also returns a more lightweight `CredentialRef` which can be used elsewhere in the credential API, uniquely
    referring to a single credential which has already been added to that client.
- `CredentialRef` type is a means of uniquely referring to a single credential without transferring the actual
  credential data back and forth across FFI all the time.
  - Each credential ref is aware of basic information about the credential it references:
    - client id
    - public key
    - credential type
    - signature scheme
    - earliest validity
- To remove a credential from the set MLS knows about, call `removeCredential` on a transaction context, handing it the
  appropriate `CredentialRef`.
  - Ensures the credential is not currently in use by any conversation.
  - Removes all key packages generated from this credential.
  - Removes the credential from the current working set and also from the keystore.
- Added a new method to transaction context: `getCredentials` which produces a `CredentialRef` for each credential known
  by this client
- Added a new method to transaction context: `findCredentials` which produces a `CredentialRef` for each credential
  known by this client, efficiently filtering them by the specified criteria.

#### Other

- It is now safer to close a `Database`: instead of depending on a unique reference to the instance, it will just
  invalidate all other references to that instance.

- It is now safer to stash an E2EI enrollment: instead of depending on a unique reference to the instance, it will just
  invalidate all other references to that instance.

- Decode: support displaying the thumbprints of signature keys.

- Decode: support decoding and displaying mls key packages

- Allow in-memory database instantiation and usage with core crypto. Just call `inMemoryDatabase()` (Android, Web) or
  the `Database` constructor without a path (iOS).

- Web: structural errors

  #### Example Usage

  Extract the abort reason given via an `MlsTransportResponse`

  ```typescript
  try {
      // send a commit that is rejected by the DS
  } catch (err) {
    if(isMlsMessageRejectedError(err)) {
      const rejectReason = err.context.context.reason;
      // other things you want to do with this error...
    } else {
        // log error
    }
  }
  ```

  Extract the proteus error code

  ```typescript
  try {
      // look for a proteus session that doesn't exist
  } catch (err) {
    if(isProteusSessionNotFoundError(err)) {
      const errorCode = err.context.context.errorCode;
      // other things you want to do with this error...
    } else {
        // log error
    }
  }
  ```

### Bug Fixes

- Web: fixed the abort reason of an `MlsTransportResponse` not being forwarded to rust.

### Breaking Changes

- Deferred init is now the only way to instantiate core crypto.

  Affected platforms: all

  Migration: instead of calling `deferredInit()`, call `init()` (TypeScript), or the regular `CoreCrypto` constructor
  (Swift, Kotlin). As before with `deferredInit()`, call `mlsInit()` in a transaction to initialize MLS.

- The core crypto constructor now takes a `Database` instance instead of a `DatabaseKey` and a path. To instantiate,
  call `openDatabase()` (Android, Web) or the `Database` constructor (iOS).

  Affected platforms: all

- `mlsInit()` was decoupled from key package creation.

  Affected platforms: all

  Migration: to create key packages after initializing MLS, call `clientKeypackages()` in a transaction.

- `proteusErrorCode` field was removed from the root error type, you can get it from the nested context now (see above).
  Affected platforms: web

- Renamed `CoreCryptoClient` to `CoreCrypto` and moved `historyClient(historySecret: HistorySecret)` into `CoreCrypto`
  Companion functions Affected platforms: jvm, android

- Removed static methods from `CoreCrypto` that are globally available:

  - removed `version()`
  - removed `buildMetadata()`

  Affected platforms: ios

- Removed static methods from `CoreCrypto` that are globally available:

  - removed `setMaxLogLevel(level: CoreCryptoLogLevel)` on ios, web
  - removed `setLogger(logger: CoreCryptoLogger)` on ios, web

  Affected platforms: ios, web

- Removed `setLogger(logger: CoreCryptoLogger, level: CoreCryptoLogLevel)` and renamed
  `setLoggerOnly(logger: CoreCryptoLogger)` to `setLogger(logger: CoreCryptoLogger)`. To set the loglevel use
  `setMaxLogLevel(level: CoreCryptoLogLevel)`

  Affected platforms: all

## v9.1.2 - 2025-11-05

This release fixes a bug in the TypeScript bindings where the commit delay could in some situations be undefined when
receiving a proposal.

### Bug Fixes

- in js 0 is falsy, which messes with ternary logic
  ([e7b73c0](https://github.com/wireapp/core-crypto/commit/e7b73c034d7492bc728c50d3c287a2a5272d3b71))

## v9.1.1 - 2025-10-24

This release fixes the issue where `libcore_crypto_ffi.so` had segments aligned on 4k instead of 16k on Android
platforms.

### Bug Fixes

- ci: use the correct NDK when building and packaging for Android [WPB-21347]
  ([ce433fe](https://github.com/wireapp/core-crypto/commit/ce433fec36d1382c364a729cd523f18e444cf6c2))

### Documentation

- README: add a note about ANDROID_NDK_HOME
  ([5c98d7f](https://github.com/wireapp/core-crypto/commit/5c98d7fc2a9dada5a53da1126a10fcb7a7d536b5))

## v9.1.0 - 2025-09-29

Note: even though this is a minor version bump, it contains a breaking change. See below for more information.

### Highlights

- added typescript structured errors
- fix the message rejected reason not being propagated on web
- improvements to logs when epochs advance

### Features

- Web: structural errors

  #### Example Usage

  Extract the abort reason given via an `MlsTransportResponse`

  ```typescript
  try {
      // send a commit that is rejected by the DS
  } catch (err) {
    if(isMlsMessageRejectedError(err)) {
      const rejectReason = err.context.context.reason;
      // other things you want to do with this error...
    } else {
        // log error
    }
  }
  ```

  Extract the proteus error code

  ```typescript
  try {
      // look for a proteus session that doesn't exist
  } catch (err) {
    if(isProteusSessionNotFoundError(err)) {
      const errorCode = err.context.context.errorCode;
      // other things you want to do with this error...
    } else {
        // log error
    }
  }
  ```

### Bug Fixes

- Web: fixed the abort reason of an `MlsTransportResponse` not being forwarded to rust.

### Breaking Changes

- `proteusErrorCode` field was removed from the root error type, you can get it from the nested context now (see above).
  Affected platforms: web

______________________________________________________________________

### Features

- \[**breaking**\] expose error structure in ts wrapper
  ([ff9dc8d](https://github.com/wireapp/core-crypto/commit/ff9dc8d636994b89923c3b49400e5a260b007d02))
- \[**breaking**\] structural wasm errors
  ([eb2760b](https://github.com/wireapp/core-crypto/commit/eb2760b425e84752568ac0ef57b8d31b98aea635))
- extend the epoch advanced log with context on which members were added/removed
  ([d039879](https://github.com/wireapp/core-crypto/commit/d0398794218a0935d6a23bf7153b8d634f5b9f8a))
- add new `Database` type [WPB-19568]
  ([431dc15](https://github.com/wireapp/core-crypto/commit/431dc15bed76878bba4b3bbebcd35ed495899f50))

### Bug Fixes

- `MlsTransportResponse` abort reason wasn't propagated
  ([90ab72f](https://github.com/wireapp/core-crypto/commit/90ab72f3b3d959bf8006bae9bf81c1789409e140))

### Documentation

- update changelog for structured ts errors
  ([8b58236](https://github.com/wireapp/core-crypto/commit/8b58236d6c2ee1e292f4323e6e7a3d0d23e9069c))
- README: fix instructions for local Maven publishing
  ([a045972](https://github.com/wireapp/core-crypto/commit/a045972857f268cbc648af19c11ab74dc34bd4ae))

### Testing

- test structured errors
  ([65aeeb4](https://github.com/wireapp/core-crypto/commit/65aeeb432825577393c02d5c432863e9feca50c4))
- add a typescript test verifying the added/removed context when logging epoch advances
  ([b4177db](https://github.com/wireapp/core-crypto/commit/b4177db719d145811f74def1a9923caacbe5d523))
- add additional utility functions to the js test suite
  ([35f51d7](https://github.com/wireapp/core-crypto/commit/35f51d7c680d073098bb3a1f62c787e3a0f8d465))
- test initialization of `Database`
  ([9fb6c9a](https://github.com/wireapp/core-crypto/commit/9fb6c9a0d056adced9bc52f6295142d94e1d7927))

## v9.0.1 - 2025-09-18

### Breaking Changes

- v9.0.0 had erroneously renamed `migrateDatabaseKeyTypeToBytes` to `migrateDbKeyTypeToBytes`. This has been fixed, and
  `migrateDatabaseKeyTypeToBytes` is usable again on all platforms.

  Affected platforms: Android

### Bug Fixes

- Kotlin documentation is now correctly generated and deployed.

______________________________________________________________________

### Bug Fixes

- crypto-ffi: use the old parameter name
  ([8d18b71](https://github.com/wireapp/core-crypto/commit/8d18b718ae61e8801b9c1facf8937d8302304ffd))
- crypto-ffi: use the correct name, migrateDatabaseKeyTypeToBytes, for uniffi
  ([870aaae](https://github.com/wireapp/core-crypto/commit/870aaaece3684502f783f631a19bb1f1586f91c5))

### Documentation

- eliminate `:nodoc:` by writing proper docs
  ([f85d9fb](https://github.com/wireapp/core-crypto/commit/f85d9fb5840e0de3e66922dd6b5a249e977686ac))

### Testing

- crypto-ffi: fix Kotlin test to use the correct API
  ([b1d5509](https://github.com/wireapp/core-crypto/commit/b1d550937581e917169885ebb2d0d912f7c4efbd))

## v9.0.0 - 2025-09-16

### Highlights

- we're now tying the Kotlin wrapper more closely to the generated bindings which allows for greater velocity when
  making changes in code that affects our API - this causes most of the breaking changes in this release
- removed cryptobox migration API
- in Swift, added protection against concurrent access from multiple core crypto instances
- added implicit obfuscation of sensitive data in logs
- reworked the entire build system and CI

### Note

In this release we include a fix for missing artifacts in our Web release. The faulty release process affects all `8.x`
versions. Therefore, instead of migrating from any version < `8.x` to `8.x`, directly migrate to this version.

### Breaking Changes

- Removed support for migrating CoreCrypto database to version 1.

  Affected platforms: Web

  Databases saved by CoreCrypto versions older than 2.0 cannot be migrated anymore.

- Removed `proteusCryptoboxMigrate`.

  Affected platforms: all

  Support for Cryptobox migration has been removed.

  Migration: remove all calls to `proteusCryptoboxMigrate`.

- Renamed `CoreCryptoContext.proteusDecrypt` to `CoreCryptoContext.proteusDecryptSafe(...)`.

  Affected platforms: Android

  It used to be the case that the Kotlin bindings hid the actual behavior of `proteusDecrypt` by adding a higher-level
  behavior, trading away some efficiency for ease-of-use. With this change, we have exposed the low-level behavior of
  `proteusDecrypt`, enabling for more efficient uses when decrypting many proteus messages at once. The old higher-level
  behavior of `proteusDecrypt` is now exposed as `proteusDecryptSafe`.

  Migration: replace all calls to `proteusDecrypt` with calls to `proteusDecryptSafe`.

- Eliminated wrapper `class E2EIEnrollment` in favor of generated `class E2eiEnrollment`.

  Affected platforms: Android

  We've brought the uniffi-generated code to very near parity with the older high-level bindings. The following breaking
  changes were necessary to eliminate the old binding class:

  **Name changes:**

  These methods have had their names changed. To migrate, simply rename all calls to these functions.

  - `accountResponse` -> `newAccountResponse`
  - `authzResponse` -> `newAuthzResponse`
  - `dpopChallengeResponse` -> `newDpopChallengeResponse`
  - `contextOidcChallengeResponse` -> `newOidcChallengeResponse`

- Eliminated (hand-written) wrapper `class CoreCryptoContext` in favor of (uniffi-generated) `class CoreCryptoContext`.

  Affected platforms: Android

  We've brought the uniffi-generated code to very near parity with the older high-level bindings. The following breaking
  changes were necessar to eliminate the old binding class:

  **Name changes:**

  These methods have had their names changed. To migrate, simply rename all calls to these functions.

  - `getPublicKey` -> `clientPublicKey`
  - `generateKeyPackages` -> `clientKeypackages`
  - `validKeyPackageCount` -> `clientValidKeypackagesCount`
  - `addMember` -> `addClientsToConversation`
  - `removeMember` -> `removeClientsFromConversation`
  - `members` -> `getClientIds`
  - `deriveAvsSecret` -> `exportSecretKey`
  - `proteusGetLocalFingerprint` -> `proteusFingerprint`
  - `proteusGetRemoteFingerprint` -> `proteusFingerprintRemote`
  - `proteusGetPrekeyFingerprint` -> `proteusFingerprintPrekeyBundle`
  - `proteusDoesSessionExist` -> `proteusSessionExists`
  - `proteusCreateSession` -> `proteusSessionFromPrekey`
  - `proteusDeleteSession` -> `proteusSessionDelete`

  **Parameter order changes:**

  These methods have had the order of their parameters changed. To migrate, either name the arguments in the caller or
  reorder the parameters appropriately.

  - `generateKeyPackages` / `clientKeypackages`: `amount` is now the final parameter, not the first
  - `joinByExternalCommit`: `credentialType` and `configuration` have swapped positions
  - `e2eiNewEnrollment`: `team` now appears after `handle` and before `expirySec`
  - `e2eiNewActivationEnrollment`: `team` now appears after `handle` and before `expirySec`
  - `e2eiNewRotateEnrollment`: new param order: `(displayName, handle, team, expirySec, ciphersuite)`
  - `proteusCreateSession` / `proteusSessionFromPrekey`: params swapped
  - `proteusDecrypt`: params swapped
  - `proteusEncrypt`: params swapped

  **Other Parameter changes:**

  These methods have had the set of their parameters changed. To migrate, see instructions for each changed method.

  - `createConversation`: accepts `(ConversationId, CredentialType, ConversationConfiguration)`. Conversation
    configuration must be constructed externally.

  **Removed Methods:**

  These methods no longer exist.

  - `proteusNewPrekeys`: similar to `from.until(from + count).map { cc.proteusNewPrekey(it.toUShort()) }`
  - `proteusNewLastPrekey`: similar to `cc.proteusLastResortPrekey()`
  - `proteusEncryptWithPreKey`: similar to:
    ```kotlin
    cc.proteusSessionFromPrekey(sessionId, preKey)
    val encryptedMessage = cc.proteusEncrypt(sessionId, message)
    cc.proteusSessionSave(sessionId)
    return encryptedMessage
    ```

- Stopped duplicating generated code in kotlin bindings.

  Affected platforms: Android

  Hand-written wrappers have largely been removed. The following items have been renamed:

  - `Ciphersuites.DEFAULT` -> `CIPHERSUITES_DEFAULT`
  - `Ciphersuite.DEFAULT` -> `CIPHERSUITE_DEFAULT`
  - `CredentialType.Basic` -> `CredentialType.BASIC`
  - `MLSGroupId` -> `ConversationId`
  - `MLSKeyPackage` -> `KeyPackage`
  - `DeviceStatus.Valid` -> `DeviceStatus.VALID`
  - `DeviceStatus.Expired` -> `DeviceStatus.EXPIRED`
  - `DeviceStatus.Revoked` -> `DeviceStatus.REVOKED`
  - `E2eiConversationState.Verified` -> `E2eiConversationState.VERIFIED`
  - `E2eiConversationState.NotVerified` -> `E2eiConversationState.NOT_VERIFIED`
  - `E2eiConversationState.NotEnabled` -> `E2eiConversationState.NOT_ENABLED`

- Changed exposed error type structures

  Affected platforms: iOS

  Migration

  - When pattern-matching the affected error types, add argument labels
  - When accessing inner error values, add field names

### Features

- In our Swift bindings we are now protecting against concurrent access from multiple core crypto instances.
- In the decode tool we add support for listing members or identities present in a group info.

______________________________________________________________________

### Features

- crypto: mark sensitive fields to add obfuscation
  ([7a3f557](https://github.com/wireapp/core-crypto/commit/7a3f557246d9b4e696268696d7796295d1f9ba8c))
- keystore: mark sensitive fields to add obfuscation
  ([03aa8af](https://github.com/wireapp/core-crypto/commit/03aa8af98e17ce7d635b617ab4e136ad4119fb91))
- add #[sensitive] attribute to debug macro
  ([2aefaf8](https://github.com/wireapp/core-crypto/commit/2aefaf8deb6c69faf98e34eb97d156d6b39fd81c))
- define obfuscate trait and Obfuscated type
  ([2d25985](https://github.com/wireapp/core-crypto/commit/2d2598548f36f5a0c550d91432f3d632d12b446c))
- salt obfuscated values
  ([217bd6d](https://github.com/wireapp/core-crypto/commit/217bd6de2fccfc242ca009e8627bb655e8526ce4))
- add DebugBytes derive macro
  ([1e63c68](https://github.com/wireapp/core-crypto/commit/1e63c68cc22d1f2f17dd9ec55be478fb0fde630f))
- add options for listing members or identities
  ([491221e](https://github.com/wireapp/core-crypto/commit/491221e545cd2ba41480f5aa9484ff28af52439e))
- take input from stdin or a file
  ([a1489f7](https://github.com/wireapp/core-crypto/commit/a1489f74a48a091ba075d686806caff311a96218))
- \[**breaking**\] remove the cryptobox-migrate feature
  ([bacf33b](https://github.com/wireapp/core-crypto/commit/bacf33b76c1572a6e07b3aabccda97ec08212105))
- hold a file lock on they keystore while executing a transaction
  ([1abf479](https://github.com/wireapp/core-crypto/commit/1abf4794532b07c7ea04a77354fdbce010bb4a3a))

### Bug Fixes

- include previously (v8.x) missing artifacts in released web package
  ([d576172](https://github.com/wireapp/core-crypto/commit/d576172514b1c7d5b53cbb70667ef842e45fe81c))
- warning about DYLIB_CURRENT_VERSION getting truncated
  ([04c623c](https://github.com/wireapp/core-crypto/commit/04c623c3882bf2cdcff6b59471c699d03e906f38))
- fix android build ([fdf2451](https://github.com/wireapp/core-crypto/commit/fdf245164c466db577d40e7f8be2d7bec52aad17))
- don't throw an error when calling proteus_reload_sessions without having called proteus_init
  ([2ca0907](https://github.com/wireapp/core-crypto/commit/2ca0907334a063853be9e91998c249f2ac1b1476))
- use `HashMap` for in-memory cache [WPB-18762]
  ([4bc12dc](https://github.com/wireapp/core-crypto/commit/4bc12dc382328cc937854d7b95eabb5f2461bf8a))
- use consistent ids for `ProteusIdentity`
  ([6b9f1e2](https://github.com/wireapp/core-crypto/commit/6b9f1e20f632802aafc5bec086d3ed93d5c734fe))

### Documentation

- update changelog ([1c28a61](https://github.com/wireapp/core-crypto/commit/1c28a616a69c62f0ff43b4749c8ef3176c44d37a))
- add js README for npm
  ([4783f66](https://github.com/wireapp/core-crypto/commit/4783f666f2358273cb40676130f4455077e0adb7))
- fix swift and ts docs target directory
  ([7d2de8c](https://github.com/wireapp/core-crypto/commit/7d2de8c5bc5ef8c9c748e44471cf756a25099700))
- link to `CHANGELOG.md` from docs landing page [WPB-19490]
  ([812865c](https://github.com/wireapp/core-crypto/commit/812865c4c16d3bb1fa79c60e7cf2e7afa8ed865a))
- ensure that all public items in `core-crypto-ffi` have docs
  ([b02c1dd](https://github.com/wireapp/core-crypto/commit/b02c1ddea9f4995c249c3072ae31c10676226a61))
- add make help output for relevant targets
  ([48f9db9](https://github.com/wireapp/core-crypto/commit/48f9db94a9569a2d6db32ad33b4fcaa0c2c51b88))
- update `README.md` ([eec14b0](https://github.com/wireapp/core-crypto/commit/eec14b0095589c61eef7d92873f07039dfd85ce1))
- add android ndk installation to readme
  ([335576e](https://github.com/wireapp/core-crypto/commit/335576e675c1818861765b36ff307871fdf25321))
- update CHANGELOG ([e716bac](https://github.com/wireapp/core-crypto/commit/e716bac6474f6e0b50190f7b0088da451727e77c))
- update keystore docs
  ([60ecf12](https://github.com/wireapp/core-crypto/commit/60ecf1260aa5e7e675ce1f7cae64075fe95f1f70))
- update CHANGELOG ([83c143f](https://github.com/wireapp/core-crypto/commit/83c143f17487f55a76f1e57a5d91c5f773690dc0))
- bindings/swift: add missing doc strings
  ([31530e9](https://github.com/wireapp/core-crypto/commit/31530e90ea4c345a9af61e7c432dde6b174d74d1))
- remove `7.x` series from `index.md`
  ([6102d9f](https://github.com/wireapp/core-crypto/commit/6102d9fa5c364c18d2a8439cb60d381e11f4b298))
- add docs for `ByteArray.toGroupInfo()`
  ([748082b](https://github.com/wireapp/core-crypto/commit/748082b8d127f4571982d64cb48ebdf7bd4f6364))
- remove unintended code comment showing up in `index.md`
  ([7dd028b](https://github.com/wireapp/core-crypto/commit/7dd028b55c575c63c8d917073842c7f5c31dba17))
- update links in `index.md`
  ([a085ae6](https://github.com/wireapp/core-crypto/commit/a085ae67d1af84c3d00be1e6478c6e5b496f67d3))

### Testing

- add scheduled test of all features to run nightly on main
  ([4f4b5c3](https://github.com/wireapp/core-crypto/commit/4f4b5c32ce05b7f02d0a4dcda2812c21a19f7e1f))
- fix previously-invisible test failures
  ([e7686c7](https://github.com/wireapp/core-crypto/commit/e7686c79d687f3004aa10bf300580f9faa7ab628))
- keystore: use the correct minimum supported db version
  ([826bc0f](https://github.com/wireapp/core-crypto/commit/826bc0fde57cc88707625fa23fe914aefc02dba4))
- add test asserting that transactions are performally serially also across multiple CoreCrypto instances
  ([d4c6667](https://github.com/wireapp/core-crypto/commit/d4c6667d06d4be7971ab0d0af144587456d7023e))
- update tests according to refactorings for new in-memory cache
  ([5b15f83](https://github.com/wireapp/core-crypto/commit/5b15f8337f41eaacecf9880d019669f99cb8fb99))
- crypto-ffi: remove now-unused global const IDs
  ([c0029c7](https://github.com/wireapp/core-crypto/commit/c0029c78777e6178d59d61a3fbeddef186a62366))
- crypto-ffi: do not use same IDs across different tests
  ([cdf3aa3](https://github.com/wireapp/core-crypto/commit/cdf3aa3c9f98e0a794f63b4e301486f8528dc6e3))

### Other Breaking Changes

- \[**breaking**\] keystore: remove migration to DB_VERSION_1
  ([11eb669](https://github.com/wireapp/core-crypto/commit/11eb6698fc8fec3854ff4e49847ff95de0045058))
- \[**breaking**\] keystore: remove keystore_v_1_0_0
  ([72b9e7b](https://github.com/wireapp/core-crypto/commit/72b9e7bc38986d367d584e6004e630ec27f53878))
- \[**breaking**\] eliminate log level setter wrapping
  ([8efc319](https://github.com/wireapp/core-crypto/commit/8efc319b766335b173b20e1746329b6eb8f61cf2))
- \[**breaking**\] Revert "refactor!(kotlin): `CoreCryptoContext.exportSecretKey` now returns a newtype"
  ([2e61956](https://github.com/wireapp/core-crypto/commit/2e6195669a9840c7c4448d61acd6be4906d5dfcb))

## v8.0.3 - 2025-08-12

This is only relevant for Kotlin.

Fixes page size alignment for all supported linkers.

Adds `ClientId.copyBytes()`.

Adds `ClientId.toString()`.

Changes `ClientId.value` from `ByteArray` to the generated FFI type `com.wire.crypto.uniffi.ClientId`

## v8.0.2 - 2025-07-23

This is only relevant for Kotlin.

Adds `MLSKeyPackage.copyBytes()`.

## v8.0.1 - 2025-07-23

This release is relevant only for Kotlin. It adds several pseudo-constructors and accessors for newtypes around byte
vectors.

For other platforms, no relevant changes are included.

### Documentation

- add docs for `ByteArray.toGroupInfo()`
  ([ac7723f](https://github.com/wireapp/core-crypto/commit/ac7723f3e0fa48e3123a0928c22e3009f473a96d))
- remove `7.x` series from `index.md`
  ([7ae7133](https://github.com/wireapp/core-crypto/commit/7ae7133ca51d44b7c3d455825e4b1eb61a9a04c2))
- remove unintended code comment showing up in `index.md`
  ([b635818](https://github.com/wireapp/core-crypto/commit/b63581895dce87cb7cfb71764019e92c7ddb8a8c))
- update links in `index.md`
  ([020aba4](https://github.com/wireapp/core-crypto/commit/020aba4c0e89a23ef62b91a7522404931e6ada34))

### Other Breaking Changes

- \[**breaking**\] Revert "refactor!(kotlin): `CoreCryptoContext.exportSecretKey` now returns a newtype"
  ([5c5427c](https://github.com/wireapp/core-crypto/commit/5c5427c21e600f9d58a45959687bf2f6ee404d54))

## v8.0.0 - 2025-07-17

### Highlights

This release contains the complete API necessary for history sharing in conversations. We've improved the generated
types in bindings to be more typesafe, and we've added the feature to rotate the key used for the core crypto database.

### Breaking changes

- Removed `canClose()`, and `isLocked()`.

  Affected platforms: Web

  Migration: Only needed if you were relying on the output of `canClose()` before calling `close()`:

  Call `close()` directly. Instead of handling the `false` case of `canClose()`, catch the error that `close()` may
  throw: `Cannot close as multiple strong refs exist`, then try again.

  The behavior of `close()` was adjusted, so that it waits for any running transaction to finish, instead of throwing an
  error.

- Removed `mlsInitWithClientId`, `mlsGenerateKeypairs`, `e2eiDumpPKIEnv`, `deleteKeypackages`, `getCredentialInUse`

  Affected platforms: Web, Android, iOS

  Migration: not needed, no client is using these functions.

- Changed the location of the Wasm bytecode file

  Affected platforms: Web

  The Wasm bytecode file, `core-crypto-ffi_bg.wasm`, has been moved to a subdirectory named `autogenerated`. While this
  is an internal change and should normally not be breaking, in reality it may break the Web client, which assumes the
  location of that internal file.

  Migration: update relevant paths in the Web client to point to the new location, under `autogenerated`, including in
  any calls to `initWasmModule`.

- Added a parameter `refreshToken` to `newOidcChallengeRequest`

  Affected platforms: Web

  This fixes an inconsistency between Web and other platforms.

  Migration: pass the refresh token received from the identity provider when calling `newOidcChallengeRequest`.

- Added a parameter `context` to `newOidcChallengeResponse`

  Affected platforms: Web

  Migration: pass the transaction context when calling `newOidcChallengeResponse`.

- Added `encryptedMessage` field to `CommitBundle`

  Affected platforms: Web, Android, iOS

  This field is used to bundle encrypted history secrets with a commit that adds a new history client.

  Migration: update any pattern-matching or other code that depends on the structure of `MlsCommitBundle` to include the
  new field. Also, make sure to update your implementation of the `MlsTransport` protocol/interface to include this
  field in the payload sent to the Delivery Service.

- `ClientId` is a newtype, not a bare byte array.

  Affected platforms: Web, Swift

  Migration: call `new ClientId(id)` to construct a `ClientId`, and `id.copyBytes()` to get a byte array out.

- `ClientId` wrapper accepts a byte array, not a string.

  Affected platforms: Android

  Migration: call `.toByteArray()` on the input.

- `Ciphersuite` is an exported public enum, not an integer

  Affected platforms: all

  Migration: use the relevant enum variant instead of an integer.

- `SecretKey`, `ExternalSenderKey`, `GroupInfo`, `ConversationId`, `KeyPackage`, `Welcome` are now newtypes

  Affected items:

  - `CoreCryptoContext.exportSecretKey` (aka `CoreCryptoContext.deriveAvsSecret`) now returns a `SecretKey`
  - (kotlin) `AvsSecret` newtype removed in favor of `SecretKey`
  - `CoreCryptoContext.getExternalSender` now returns an `ExternalSenderKey`
  - `ConversationConfiguration::external_senders` now accepts `ExternalSenderKey`s
  - `CoreCryptoContext.joinByExternalCommit` now accepts a `GroupInfo`
  - `GroupInfoBundle` now contains a `GroupInfo`
  - Many `CoreCryptoContext` methods now accept a `ConversationId` newtype instead of a byte array
  - `HistoryObserver` and `EpochObserver` now produce `ConversationId` instances instead of byte arrays
  - `CoreCryptoContext.clientKeypackages` now produces `KeyPackage`s
  - `CoreCryptoContext.addClientsToConversation` now accepts `KeyPackage`s
  - `CommitBundle` now might contain a `Welcome`
  - `CoreCryptoContext.processWelcomeMessage` now accepts a `Welcome`

  Affected platforms: all

  Migration: call `.copyBytes()` on the newtype to get access to the raw byte vector. To construct the newtype from a
  byte array, just use the appropriate constructor.

  In the past, Android (but only Android) had newtypes in these instances; other clients needed to work with a raw byte
  vector. We've decided to expand the use of newtypes around byte vectors in the FFI interface. This has several
  benefits:

  - Increased consistency between client FFI libraries
  - Reduced thickness of the high-level FFI wrappers
  - In some cases, we can avoid bidirectional data transfers across the FFI boundary, and just move pointers around
    instead.

- Removed `PlaintextMessage`, `MlsMessage` and `SignaturePublicKey` newtypes in favor of `ByteArray`

  Affected platforms: Android

  The Message newtypes were only used in `CoreCryptoContext.encryptMessage` and `CoreCryptoContext.decryptMessage`.
  `SignaturePublicKey` was used only for the return value of `fun getPublicKey`. The only usage we found was an
  immediate access of the byte vector.

  These types appear to provide no type safety benefits, instead only adding a bit of friction.

### Features

- Support Android environments with 16k page size
- Added a module-level function `updateDatabaseKey`, to update the key of an existing CoreCrypto database
- Support for history sharing which can be enabled by calling `enableHistorySharing()` and disabled again by calling
  `disableHistorySharing()`.

______________________________________________________________________

### Features

- crypto-ffi: add updateDatabaseKey to JS bindings [WPB-18538]
  ([e35f1a5](https://github.com/wireapp/core-crypto/commit/e35f1a5ec5d3de80bd1523b694ec28f8b3365d20))
- crypto-ffi: add updateDatabaseKey to Kotlin bindings [WPB-18538]
  ([373fc4e](https://github.com/wireapp/core-crypto/commit/373fc4e82df85542df5625f1944dc0eb4f899b8a))
- crypto-ffi: add updateDatabaseKey to bindings [WPB-18538]
  ([f682a15](https://github.com/wireapp/core-crypto/commit/f682a15ff79380b38dc71757c83cf3959548eef0))
- keystore: add a way to rekey the db on Wasm [WPB-18538]
  ([a62cfb5](https://github.com/wireapp/core-crypto/commit/a62cfb549dc6fdfe1242cf478b7c290c6b40a4c5))
- keystore: add a way to rekey the db on non-Wasm platforms [WPB-18538]
  ([54d5fd1](https://github.com/wireapp/core-crypto/commit/54d5fd19951eb4cb4e41b2d7ac445d643cf8eb58))
- \[**breaking**\] remove `can_close()` and `isLocked()` [WPB-17633]
  ([58b4aa2](https://github.com/wireapp/core-crypto/commit/58b4aa2ff94cc2c3e9289121100df476ad733314))
- update history client on member remove [WPB-17096]
  ([714ff73](https://github.com/wireapp/core-crypto/commit/714ff739ebe8ae3acbb643fd6a0ddde1be58d3e1))
- update Android NDK to 28.1 [WPB-18293]
  ([6101eb8](https://github.com/wireapp/core-crypto/commit/6101eb80187a5384eb48e9e94342fc8607abeebf))
- implement enabling and disabling history sharing [WPB-17106]
  ([b036967](https://github.com/wireapp/core-crypto/commit/b036967208be65444c5dfd6ba93017d63106912f))
- add `is_history_sharing_enabled()` [WPB-17106]
  ([0b9eedf](https://github.com/wireapp/core-crypto/commit/0b9eedff3228fb2bbc703f3db025a94df6535742))
- \[**breaking**\] add field to `MlsCommitBundle` [WPB-17106]
  ([eb30ab6](https://github.com/wireapp/core-crypto/commit/eb30ab651b63b606b1fdb9b962c9180b42703f48))
- \[**breaking**\] crypto-ffi: remove deleteKeypackages
  ([4c5def3](https://github.com/wireapp/core-crypto/commit/4c5def3f23f3c2e8d9961108ab0827aa7634e2f2))
- introduce HistoryObserver
  ([43ceb73](https://github.com/wireapp/core-crypto/commit/43ceb7371dfc5f2d46f48c9413dd9f00d2d78e60))
- \[**breaking**\] crypto: remove e2ei_dump_pki_env and related code
  ([7927ebb](https://github.com/wireapp/core-crypto/commit/7927ebbed5670be4db316d641bf79a1cfc0611b1))
- \[**breaking**\] crypto-ffi: remove e2eiDumpPKIEnv and related functions
  ([b444f13](https://github.com/wireapp/core-crypto/commit/b444f1301982c9dd0aaa44c36c8c3008dd2e7c8b))
- introduce `Metabuilder`
  ([f556fc7](https://github.com/wireapp/core-crypto/commit/f556fc7001b141323a54203e0695d9e3db2f2fd1))
- support instantiating sessions with mixed credential types
  ([c8471b2](https://github.com/wireapp/core-crypto/commit/c8471b221eb2c4d6b402bd91569be8ec91ef4290))
- allow session instantiation with test chain and basic credentials
  ([c700f04](https://github.com/wireapp/core-crypto/commit/c700f042c406d1cdffbbfb1f7824d0c464436468))
- add all required abstactions
  ([a59c587](https://github.com/wireapp/core-crypto/commit/a59c5876c2d5038151cebbe7212e949a19aa076a))
- \[**breaking**\] crypto-ffi: remove wasmFilePath
  ([92e6dad](https://github.com/wireapp/core-crypto/commit/92e6dada9357494b1786e79667e1ab84715bdadc))
- \[**breaking**\] crypto-ffi: bindings: remove getCredentialInUse
  ([81a75a8](https://github.com/wireapp/core-crypto/commit/81a75a8b9d270aafaea3441d9c965d2c1f265430))
- crypto: remove generate_raw_keypairs
  ([1ea2b76](https://github.com/wireapp/core-crypto/commit/1ea2b76825b9799c17a4670d57067e3ef8744552))
- \[**breaking**\] crypto-ffi: remove mls_generate_keypairs
  ([5d5cdc1](https://github.com/wireapp/core-crypto/commit/5d5cdc1b3272706ee4ca6556fe1c338ab8ecd142))
- \[**breaking**\] crypto-ffi: bindings: remove mlsGenerateKeypairs
  ([ad9a6b8](https://github.com/wireapp/core-crypto/commit/ad9a6b861723f9fe534bcb622013f27df3d53cbd))
- \[**breaking**\] crypto: remove init_with_external_client_id
  ([625cbec](https://github.com/wireapp/core-crypto/commit/625cbec18002fc85e72ddbd29848c49a5ca6aabd))
- \[**breaking**\] crypto-ffi: remove mls_init_with_client_id
  ([40bbbeb](https://github.com/wireapp/core-crypto/commit/40bbbeb480d68cc154870e6869eb92e52e3911a1))
- \[**breaking**\] crypto-ffi: bindings: remove mlsInitWithClientId
  ([10a80ca](https://github.com/wireapp/core-crypto/commit/10a80ca58e2149d60d648ddaeb1db3e8c96009fe))
- add `remove_guarded()`
  ([6733dad](https://github.com/wireapp/core-crypto/commit/6733dad03219a0b4635db7ec918ef760167317d6))
- add `update_guarded_with()`
  ([8d98ef2](https://github.com/wireapp/core-crypto/commit/8d98ef20fa89c4b7400f99ac1a20e9a7ac59eaf1))
- add `advance_epoch()` API
  ([f2c2592](https://github.com/wireapp/core-crypto/commit/f2c2592c5779aa9fbf3bea0b72f8e3f02cc3ffb7))

### Bug Fixes

- no emitted warning on `wasm_bindgen` errors [WPB-15468]
  ([124356d](https://github.com/wireapp/core-crypto/commit/124356df18dd1153be1c30c40ad2d6943fef2660))
- proteus error type mapping
  ([2ec2fa9](https://github.com/wireapp/core-crypto/commit/2ec2fa9fe2051801660a10332a8a8c5d60aab383))
- add missing API to `CoreCryptoProtocol` [WPB-18634]
  ([a816979](https://github.com/wireapp/core-crypto/commit/a81697941e29b79e60f721511a23957de64fc1c4))
- `Error::ConversationAlreadyExists` has a byte vector not handle
  ([1660757](https://github.com/wireapp/core-crypto/commit/1660757ea2fc66945b6e0d776bbc2b9f15c0537f))
- use new types where appropriate
  ([19b1ffa](https://github.com/wireapp/core-crypto/commit/19b1ffa4b6b509a59f20ee07ae845f94b2a5b3ec))
- use appropriate types in observer indirectors
  ([a04259f](https://github.com/wireapp/core-crypto/commit/a04259fd03865856ad96d2771f4ec44562eafc88))
- document `SecretKey`
  ([366a1e9](https://github.com/wireapp/core-crypto/commit/366a1e93d875101db6e034cbde0d0ab7056c04f3))
- `ciphersuite` not `cipherSuite`
  ([6594972](https://github.com/wireapp/core-crypto/commit/6594972b0ecb3133e5155b3bd50ade2c53292387))
- epoch observer observes a proper `ConversationId` type
  ([77036e1](https://github.com/wireapp/core-crypto/commit/77036e1906d133318d1ad8b67c6d0e2702e3ed06))
- use proper `ClientId` in bun test utils
  ([59db6f8](https://github.com/wireapp/core-crypto/commit/59db6f8a8913c95a1ce9668aacced2a17566e88e))
- use proper `ConversationId` type in web bench
  ([ba264f5](https://github.com/wireapp/core-crypto/commit/ba264f5c8e06db1ba9d7f68443105e90055ad32e))
- history observers observe `ConversationId`
  ([102359e](https://github.com/wireapp/core-crypto/commit/102359e9268eefd7664dd43f33cc59741d770b47))
- do not store the signature key when instantiating a history client
  ([b3f7720](https://github.com/wireapp/core-crypto/commit/b3f772049a7e902291f529d4a8bdc2815e999b55))
- invalid API Docs link in README.md
  ([500c36f](https://github.com/wireapp/core-crypto/commit/500c36f11d20d673802a8f32556653209fab9a91))
- building android bindings on a mac
  ([67125cd](https://github.com/wireapp/core-crypto/commit/67125cd257e5f4ca960f8be81e3e15f467011a9a))
- unreleased changes generation had an extra token
  ([bc56760](https://github.com/wireapp/core-crypto/commit/bc567602ae772302562073e2fb93969ba29ab433))
- crypto-ffi: fix field names in X509Identity on wasm
  ([6481d8c](https://github.com/wireapp/core-crypto/commit/6481d8c9e4b32611096cbed4f3281b0127ca3070))
- initWasm was being called with the wrong property field.
  ([ca52dbf](https://github.com/wireapp/core-crypto/commit/ca52dbf659c88ec02c078fdf3e36420bff5d5c3d))
- allow registering epoch observer before calling mls_init
  ([0cad9a3](https://github.com/wireapp/core-crypto/commit/0cad9a35c5e27dffbaeced066b1e61105400a09e))

### Documentation

- upload swift docs into the right folder
  ([902d8f2](https://github.com/wireapp/core-crypto/commit/902d8f2ac08dcaa4dccfb2e5fd00a42faa383fd8))
- build swift documentation in CI
  ([a2f910f](https://github.com/wireapp/core-crypto/commit/a2f910fe413ec76873622498f37d8745b3c15069))
- update changelog: info about new field in `MLsCommitBundle`
  ([d1431a3](https://github.com/wireapp/core-crypto/commit/d1431a3262e6d56a2f336b23f12acc6a38142065))
- include hyperlink to commit in git cliff output
  ([6e209f5](https://github.com/wireapp/core-crypto/commit/6e209f512679acb68fad8f3b932b02b5b93ee7e7))
- publish unreleased changes to github pages
  ([6c33a70](https://github.com/wireapp/core-crypto/commit/6c33a709b2ed5f1b45c7291f5bbb6cc13ed9abf2))
- add internal links to high-level documents
  ([0ca52eb](https://github.com/wireapp/core-crypto/commit/0ca52ebe5f2fb0c459bb7594cc6c7b8eb741f6df))
- simplify docs directory structure
  ([e9a7c2f](https://github.com/wireapp/core-crypto/commit/e9a7c2f5faa848d07392d29b1538aaa27ea76104))
- eliminate fake docs module / submodules
  ([a459167](https://github.com/wireapp/core-crypto/commit/a459167bd52a4b19cbe982a7bb78a1a0704e65f4))

### Testing

- crypto-ffi: add a test for updateDatabaseKey in Swift bindings [WPB-18538]
  ([a2160d8](https://github.com/wireapp/core-crypto/commit/a2160d8ab029f370e0adaca1e4667e530065d049))
- crypto-ffi: add a test for updateDatabaseKey in JS bindings [WPB-18538]
  ([7528b2a](https://github.com/wireapp/core-crypto/commit/7528b2a46de04d0f9a80c2a4650ff2fc27d2eaaf))
- crypto-ffi: add a test for updateDatabaseKey in Kotlin bindings [WPB-18538]
  ([9111a32](https://github.com/wireapp/core-crypto/commit/9111a32bd470590d177c1c770cc5e1537400768f))
- error builds correctly when coming from cc or `wasm_bindgen`
  ([aab8d60](https://github.com/wireapp/core-crypto/commit/aab8d6005f98d2684203423bd5a9034590dcb7e8))
- proteus session not found maps to correct error type
  ([0a481ef](https://github.com/wireapp/core-crypto/commit/0a481ef33b9f5606f31ae7b776118dacbcbe4798))
- re-add database tests which were accidentally omitted
  ([185e90f](https://github.com/wireapp/core-crypto/commit/185e90f0bf749266478854c85ac620e432569fb8))
- test history client update on remove
  ([f2aa941](https://github.com/wireapp/core-crypto/commit/f2aa94193171a3638b764b22642ee02bc5c4459e))
- test history sharing [WPB-17106]
  ([79025cd](https://github.com/wireapp/core-crypto/commit/79025cd56c9fdde0950db742cdbb14db3eaa69ed))
- remove leaf node validation tests [WPB-18083]
  ([c2ae76d](https://github.com/wireapp/core-crypto/commit/c2ae76d67ef4878d099fb11b27a4987bf3ace687))
- fix: `TestContext::sessions_x509()` should always create x509 sessions
  ([49ee4e6](https://github.com/wireapp/core-crypto/commit/49ee4e64210ede5054e5cd9ebd86d6ca6c6ac406))
- add test handling self-commit after failed transaction [WPB-17464]
  ([01a6d46](https://github.com/wireapp/core-crypto/commit/01a6d4638c2b88d5b09e80171075cc37688437b4))

### Other Breaking Changes

- \[**breaking**\] crypto-ffi: tell wasm-bindgen to output files into a separate dir
  ([e34b944](https://github.com/wireapp/core-crypto/commit/e34b944694813234dd72cd4a6ed5bcbfa2bf4a70))
- \[**breaking**\] eliminate certain wasm-specific discrepancies from core-crypto-ffi
  ([1143d11](https://github.com/wireapp/core-crypto/commit/1143d1105e93fb440c7d89f90598cabd3ee3f4be))

## v7.0.2 - 2025-07-07

### Highlights

Upgrade OpenMLS to fix a bug where the ratchet tree would sometimes become corrupt leading to broken MLS groups.

### Bug Fixes

- update openmls [WPB-18569] (7ca7ba7)

## v7.0.1 - 2025-06-02

### Bug Fixes

- initWasm was being called with the wrong property field. (ca1706d)
- allow registering epoch observer before calling mls_init (3f0605a)

## v7.0.0 - 2025-05-21

### Breaking changes

The typescript bindings no longer implicitly load the wasm module when importing the core crypto module. To replace this
behaviour the `async initWasmModule()` function has been added, which must be called before any other core crypto
function.

### Features

- remove top level await and expose async init method instead (ce6e566)
- expose `historyClient` constructor to swift (22d98de)
- expose `historyClient` constructor to kotlin (b16839d)
- expose `historyClient` constructor to wasm (3c2531a)
- expose `history_client` constructor publicly (c24fcc3)
- restore history secrets (5643e87)
- add `fn history_client(HistorySecret) -> CoreCrypto` (8b7b7d4)
- add `fn generate_history_secret` (a998dec)

### Bug Fixes

- crypto-ffi: fix naming and attributes of WelcomeBundle fields on Wasm (1b2e88b)
- prevent cancellations during transactions (Kotlin) (75217d5)
- prevent cancellations during transactions (Kotlin) (ae621b7)

### Testing

- add `TestConversation::remove` (70c2c26)
- add `TestConversation::transport` (67a76fd)
- add `TestConversation::external_join` (b332e79)
- add `TestConversation` struct (d3401b8)
- support x509 scenarios in test case sessions (7e2eef9)
- add case for communication x509 -> history client (b1f9216)
- add a test that ephemeral clients can be created and used (48b8915)

## v6.0.1 - 2025-05-07

### Bug Fixes

- swift publishing CI action (d1030e1)

## v6.0.0 - 2025-05-07

### Highlights

- Changed the core crypto database key format, to enable validation of the same and ensure consistency between platforms
- Added a function for each platform to migrate from the old to the new key type
- Several more bug fixes, including prevention of the _pending commit_ error

### Breaking changes

- Changed the core crypto database key format

  Affected platforms: Web, Android, iOS

  Migration: before instantiating this version of core crypto for the first time, call `migrateDatabaseKeyTypeToBytes()`
  with the appropiate arguments (old key and your new key) _exactly once_. Then, instantiate core crypto with the new
  key.

  Note: Make sure the new key is not based on a string, and provide full 256 bits of entropy.

  Note: Instantiating this version of core crypto will fail before you call the migration function.

### Bug Fixes

- clear pending commit before creating a new one [WPB-17356] (a937c9d)
- re-throw inner error which cancelled the transaction (840bc10)
- add registerEpochObserver to CoreCryptoProtocol (6e4ffc7)
- create an interface for `ConversationConfiguration` (f18d3e8)
- handle pending conversation when getting conversation (931b4d4)
- fix ffi incompatibilities in high-level swift wrapper (1576bd8)
- fix ffi incompatibilities in high-level kotlin wrapper (09bf52f)
- ensure that we don't change the interface of WireIdentity (35d348d)
- duck types are not trait objects (4d91669)
- fix ffi incompatibilities in high-level ts wrapper (f892f42)
- broken swift bindings by publishing uniffi framework separately (bed051d)
- don't refer to the internal uniffi EpochObserver type in the public API (b959576)
- re-expose proteus_reload_session which removed by mistake (08f3e34)
- \[**breaking**\] add a swift function to migrate the database key (390e5c8)
- crypto-ffi: add a Kotlin migration function for database key type change (842aeb4)
- keystore: add a key type migration function for non-Wasm platforms (0442812)
- crypto-ffi: add a JS migration function for database key type change (ff1c7b9)
- keystore: add a key type migration function for Wasm (2b323b3)
- \[**breaking**\] crypto-ffi: update Kotlin wrapper to use the DatabaseKey type (4192311)
- \[**breaking**\] crypto-ffi: update JS wrapper to use the DatabaseKey type (a655618)
- \[**breaking**\] crypto-ffi: use DatabaseKey instead of string for the database key (2dff46a)
- \[**breaking**\] mls-provider: use DatabaseKey instead of string for the database key (7538805)
- \[**breaking**\] crypto: use DatabaseKey instead of string for the database key (05782fa)
- \[**breaking**\] keystore: introduce a DatabaseKey newtype and move away from strings (6307183)
- swift publishing failing due to not running on latest macos runner (385f031)

### Documentation

- update `Readme.md` (562d59f)
- update CHANGELOG with v3.1.1 info (415c290)
- fix doc warnings in js bindings (5c0ef34)

### Testing

- add test reproducing pending commit bug [WPB-17356] (9b84901)
- Kotlin: extend epoch observer test (0039d6f)
- port tests of static functions to bun (5519022)
- port web test utils to bun test utils (dbdc6f2)
- add bun test infrastructure (59d9f69)
- crypto-ffi: add a Swift test for migrating the db key type (c507512)
- crypto-ffi: add a Kotlin test for migrating the db key type (821f016)
- crypto-ffi: add a JS test for migrating the db key type (9fcd942)
- fix constant interop http server test port (f7bbf6f)

## v5.4.0 - 2025-05-14

### Highlights

Kotlin bindings only: transactions are now
[`NonCancellable`](https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines/-non-cancellable/),
as [required by Uniffi](https://mozilla.github.io/uniffi-rs/latest/futures.html#cancelling-async-code). This prevents a
category of bug where Kotlin thinks a transaction has been cancelled, while Rust thinks it is still running.

### Bug Fixes

- prevent cancellations during transactions (a28338fe)
- prevent cancellations during transactions (2fb8d979)

## v5.3.0- 2025-04-29

### Bug Fixes

- re-throw inner error which cancelled the transaction (Swift) (0c282b2)

## v5.2.0 - 2025-04-15

### Bug Fixes

- add registerEpochObserver to CoreCryptoProtocol (eadf388)
- create an interface for `ConversationConfiguration` (b1e82bf)
- swift publishing failing due to not running on latest macos runner (dcc1890)

## v5.1.0 - 2025-04-03

### Bug Fixes

- broken swift bindings by publishing uniffi framework separately (2b950cc)
- don't refer to the internal uniffi EpochObserver type in the public API (7833300)
- re-expose proteus_reload_session which removed by mistake (36f2b87)

## v5.0.0 - 2025-03-21

### Highlights

New Swift bindings which are more ergonomic and allows for better testing by exposing the transaction context as a
protocol.

New API for observing epoch changes through a callback API: `registerEpochObserver`. After adopting this API clients can
remove their own epoch observers.

### Breaking changes

- New Swift bindings are replacing the old Swift bindings.

### Features

- add API for observing epochs to the swift bindings (47f9a6e)
- \[**breaking**\] add Swift wrapper on top of uniffi (ce862d4)
- add `registerEpochObserver` helper in TS (1e25f4a)
- add `registerEpochObserver` helper in Kotlin (bc05e13)
- enable epoch observer registration in wasm (6a5f395)
- enable epoch observer registration in uniffi (e04b83e)
- relax `Debug` restriction on `EpochObserver` (ff22e35)
- add an `EpochObserver` trait and instance to the client (e83f9f5)

### Bug Fixes

- android-uniffi library namespace was conflicting the main android library (a7ec292)
- kotlin documentation links on the main page (8045031)
- release swift framework with correct version (f1c6029)
- the android artefact was still trying to publish to nexus (0b1dfeb)
- make `EpochObserver` and registration fn visible from the outside (b4a16f8)
- ensure that local epoch changes are also observed (bc43dc3)

### Documentation

- add note about logs in browser tests (bf6b594)

### Testing

- add test demonstrating epoch observer (a65ab45)
- add test for epoch observer behavior (c302cb3)
- add tests of basic behavior (a810259)
- don't assert a non-epoch-change when the epoch must change (d939255)
- rm `has_epoch_changed` usage in favor of `EpochObserver` (88cbff2)

## v4.2.3 - 2025-03-14

### Bug Fixes

- fix android publishing to maven central

## v4.2.2 - 2025-03-14

### Bug Fixes

- fix publishing to maven central

## v4.2.1 - 2025-03-14

### Bug Fixes

- expose `proteusCryptoboxMigrate()` [WPB-16549] (682b9fe)

### Documentation

- fix comments in index.md (b35b021)
- update README.md with instructions to update docs table (0ce3d49)
- update documentation table with links to docs for `v3.1.0` and `v4.2.0` (93bcba9)
- add docs landing page [WPB-11382] (5361146)

## v4.2.0 - 2025-02-28

### Highlights

- The Android release once again bundles API docs.
- The Kotlin bindings have received several API fixes in particular:
  - AcmeChallenge was missing the target property.
  - proteusGetPrekeyFingerprint was missing.
- The Typescript bindings now correctly expose WireIdentity and X509Identity.
- The code base has migrated to Rust 2024 edition.

### Bug Fixes

- expose target on AcmeChallenge (c509a3f)
- add missing proteus function (a956924)
- don't expose uniffi types in the kotlin bindings (988b7d0)
- publishing android docs (7b91f08)
- publicly expose WireIdentity and X509Identity in the typescript bindings (6592d4a)
- return the wasm bindgen generated JS type instead of converting the value to JSON. (3446920)

### Testing

- add test case for querying identities (3c36cb5)

## v4.1.0 - 2025-02-07

### Highlights

- Add the capability to handle the case where a proposal-referencing commit arrives before the proposals it references.

### (Semi-) Breaking changes

- For the case mentioned above, the corresponding error type `BufferedCommit` has been added.
  - Depending on the error model, this can be a breaking change.

### Features

- implement commit buffering (3737e97)

### Testing

- add test case for the first part of 15810 (258aa23)

## v4.0.1 - 2025-02-05

### Features

- support entity derive for tables with hex ids (0bd3676)

## v4.0.0 - 2025-01-28

### Highlights

- All errors crossing the FFI boundary are now logged.
- An iOS client has been added to internal interop tests, which means we now test the entire FFI stack on iOS.
- A new interface for MLS transport has been added, allowing for a much simpler and more robust CoreCrypto API.
- Removal of a number of deprecated and unnecessary functions and types.
- Completely reworked internal error handling, to allow for more precise errors.
- A number of improvements to Kotlin and Javascript bindings, making the bindings more consistent.
- The `decode` tool gained support for decoding MLS messages.

### Breaking changes

- Deprecated functions on the `CoreCrypto` type that were automatically creating transactions have been removed.

  Affected platforms: Web, Android, iOS

  Migration: replace calls to functions on `CoreCrypto` with calls to corresponding functions on `CoreCryptoContext`,
  which is created when you explicitly create a transaction. Transactions have to be explicitly created now.

- The low-level uniffi-generated Kotlin bindings code is no longer publicly available. It should never have been used in
  application code directly.

  Affected platforms: Android

  Migration: make sure to use the Kotlin high-level API only.

- The Wasm bytecode generated by `wasm-bindgen` is now imported directly when importing the `corecrypto` module. This
  makes sure that the Wasm module is immediately initialised, without any additional steps. There is no need for the
  client app to know or handle the path to Wasm bytecode file.

  Additionally, it is now possible to use the same CoreCrypto module in both browser and non-browser contexts.

  Affected platforms: Web

  Migration: drop any references to `core-crypto-ffi_bg.wasm` and do not set the `wasmFilePath` argument to the
  `CoreCrypto.init` function -- it is no longer used. Additionally, make sure there is no special handling or separate
  hosting of the Wasm bytecode file. CoreCrypto release artifacts should be used without any changes.

- Validation callbacks, as well as related error variants, have been removed.

  Affected platforms: Web, Android, iOS

  Migration: remove all implementations of `authorize`, `userAuthorize` and `clientIsExistingGroupUser`, as well as
  calls to `CoreCrypto.setCallbacks`.

- The `MlsTransport` interface has been added. This is another milestone in the effort to simplify the public API and
  make it more robust.

  All client applications have to provide an implementation of the new interface, which comprises only two functions,
  `sendMessage` and `sendCommitBundle`.

  Affected platforms: Web, Android, iOS

  Migration: implement the `MlsTransport` interface and call `CoreCrypto.provideTransport` to make CoreCrypto use your
  implementation.

- Functions `CoreCrypto.wipe` and `CoreCrypto.unload` have been removed. They were not providing any value.

  Affected platforms: Web, Android, iOS

  Migration: drop calls to `wipe` and `unload`. Client applications wishing to make their keys and conversations
  inaccessible should remove the CoreCrypto database explicitly.

- The function `CoreCrypto.proteusLastErrorCode` has been removed. We now have Proteus error codes attached to errors
  that are emitted by CoreCrypto.

  Affected platforms: Web, Android, iOS

  Migration: drop calls to `proteusLastErrorCode` and instead check the returned error object.

- The functions `CoreCrypto.buildMetadata` and `CoreCrypto.version` have been moved to the module level. It is no longer
  required to create a `CoreCrypto` instance to call them.

  Affected platforms: Web

  Migration: use module-level `buildMetadata` and `version` functions.

- Several changes have been made to the E2EI API.

  The function `CoreCrypto.e2eiRotateAll` has been removed. Client applications should instead go over each conversation
  individually and call `CoreCrypto.e2eiRotate`.

  Two new functions have been added, `CoreCrypto.saveX509Credential` and `CoreCrypto.deleteStaleKeyPackages`. The former
  should be used after getting a new X509 credential, while the latter should be called after generating keypackages for
  the new credential and replacing the stale ones in the backend.

  Affected platforms: Web, Android, iOS

  Migration: replace calls to `e2eiRotateAll` with iterations over conversations, calling `e2eiRotate` on every
  conversation and checking for errors. Use `saveX509Credential` and `deleteStaleKeyPackages` as appropriate (more
  details in API documentation).

- The proposal API has been removed, simplifying the public API a great deal. This includes functions like
  `newProposal`, `newExternalProposal`, `clearPendingProposal`, `joinConversation` etc.

  Affected platforms: Web, Android, iOS

  Migration: drop all calls to removed functions as they are no longer necessary with the new MLS transport interface.

### Features

- add support for decoding MLS messages (c921210)
- integrate iOS interop client into interop tests (3b19886)
- iOS interop client (e2568dd)
- log all errors returned across ffi boundary [WPB-14355] (6f1d1c3)
- implement basic derive macro for entity trait [WPB-14952] (797ff75)
- \[**breaking**\] APIs that produce commits send them over MLS transport [WPB-12121] (daa3a6e)
- \[**breaking**\] crypto-ffi: move buildMetadata to the module level [WPB-14827] (0cfbe4f)
- run instrumented android test on CI (44f74a6)
- \[**breaking**\] add mls transport api in wrappers (a80c042)
- \[**breaking**\] add transport api [WPB-12119], remove validation callbacks [WPB-14463] (dea76f9)

### Bug Fixes

- publishing android artifact by disabling javadoc generation (68af2b3)
- emit output when bailing out (821de8e)
- chrome webdriver crashing when running on macos-latest runner (54f9a86)
- broken error type mapping in try/catch patterns. (9d0dc59)
- fix TS wrapper according to mls transport API changes [WPB-15407] (286f114)
- mls transport retry implementation as designed (7c9f2b0)
- crypto-ffi: fix Typescript documentation generation (4b8498e)
- fix decryption of pending messages when receiving own commit (705dfd7)
- error mapping for `LeafError` type (e03e030)
- manually implement std::error::Error for RecursiveError (6886fe0)
- keystore: remove debug_assert! calls in the memory keystore impl [WPB-14558] (6fb5a56)
- `innermost_source_matches` can handle dereferencing boxed errors (045b3cc)
- cause kotlin to build again (7ba1bbc)
- ensure everything still builds in arbitray feature combinations (0365192)
- cause doctests to build/pass (3d56953)
- make leaf node validation tests pass (d65a69e)
- fix `check` ci action (a8aa178)
- fix remaining failing test cases (2f8aec4)
- make core-crypto compile again for `wasm32-unknown-unknown` (3120040)
- expose `OrphanWelcome` to clients [WPB-14954] (14742ad)
- silence verbose logs when performing a transaction [WPB-14953] (b248ff0)
- don't swallow transaction errors if they don't originate from the closure [WPB-14895] (082b8bc)
- wait for current transaction to finish when creating a new one [WPB-14895] (991d5fd)
- instrumented android tests not compiling (309d374)
- start deleting/wiping the clients in the interop tests (d9e39d0)
- \[**breaking**\] stop exposing wipe() and unload() since they are broken in Kotlin [WPB-14514] (f0bec13)

### Documentation

- add a _correct_ safety comment for `CoreCryptoWasmLogger` (67e9f27)
- update CHANGELOG for 4.0.0 (a961df7)
- some minor docs cleanup (1fd0f46)
- add MLS decoding example (910ae58)
- fix github pages deployment (0aac074)
- refine kotlin wrapper docs (923496d)
- crypto-ffi: fix some of the warnings [WPB-15318] (4f1a82c)
- README: fix Wasm instructions and a couple of typos [WPB-14827] (ed5bd09)

### Testing

- add test for retrieving the CC version (9fd4c5a)
- ensure that errors raised in core-crypto produce logs [WPB-14355] (d5b496e)
- update error type mapping test (7bfa905)
- remove proposal API tests in Kotlin/TS wrappers (ef2844b)
- retry with or without intermediate commits should work (2ba486c)
- support intermediate commits on retry (f5ca4f3)
- remove duplicate test (0488a1c)
- remove tests about "leaking entities" (8b36320)
- add tests for error type mappings (9bd3515)
- crypto-ffi: remove tsc-import-test.ts (1b41df4)
- crypto-ffi: change wdio log level to warn [WPB-14558] (39b830f)
- crypto-ffi: use the module level function buildMetadata [WPB-14827] (2a35392)
- parallel transactions are performed serially (20d47c1)

## v3.1.1 - 2025-04-15

- This release bumps the version of rusty-jwt-tools to 0.13.0, which includes additional end-to-end identity tests and
  test markers relevant to Bund.

## v3.1.0 - 2025-02-12

### Highlights

- Add a test case mimicking a real life bug ([WPB-15810]), demonstrating that in some cases it was possible to generate
  errors by swapping the ordering of two messages.

- Add a new layer of buffering to handle that situation.

  > [!NOTE]
  > Decrypting a message can now potentially return a `MlsError::Other` variant with the message
  >
  > > Incoming message is a commit for which we have not yet received all the proposals. Buffering until all proposals
  > > have arrived.
  >
  > Clients do not need to take any action in response to this message. This error simply indicates that the commit has
  > been buffered, and will be automatically unbuffered when possible.

  If the required proposal is never delivered, however, the client will eventually desync as the commit will never be
  processed. Clients should be on the lookout for this case and trigger their rejoin protocol in that event.

### Features

- implement commit buffering (e98f0a6)
- support entity derive for tables with hex ids (235730c)
- implement basic derive macro for entity trait [WPB-14952] (7add536)

### Testing

- add test case for the first part of 15810 (3b41175)

## v3.0.2 - 2025-01-31

### Highlights

- Fix a bug which could cause certain errors to generate spurious log lines of the form

  > Cannot build CoreCryptoError, falling back to standard Error! ctx: Incoming message is from an epoch too far in the
  > future to buffer.

## v3.0.1 - 2025-01-27

### Highlights

- Emit info log with context when buffering, restoring, or clearing buffered messages

## v3.0.0 - 2024-12-11

### Highlights

- Fix the 'transaction in progress' error when there was an attempt to perform multiple transactions in parallel. This
  will no longer throw an error, instead the transactions will be queued and performed serially one after another.

### Breaking changes

- Added the missing MLS error case OrphanWelcome.

### Bug Fixes

- expose `OrphanWelcome` to clients [WPB-14954] (530b2e4)
- silence verbose logs when performing a transaction [WPB-14953] (b13553d)
- don't swallow transaction errors if they don't originate from the closure [WPB-14895] (124b8a7)
- wait for current transaction to finish when creating a new one [WPB-14895] (73b9d52)

### Testing

- parallel transactions are performed serially (ccc0b32)

## v2.0.0 - 2024-12-02

### Highlights

- The number of public errors has been reduced and simplified. It's no longer necessary to use the
  `proteus_last_error_code` function, since thrown error should contain all the information.
- The logger callback now includes an additional context parameter which contains additional context for a log event in
  the form of a JSON Object string.
- It's now possible to change the logger and log level at runtime (see `setLogLevel` and `setLogger`).

### Breaking changes

- Dropped support for `i686-linux-android` target.
- `CoreCryptoLogger` takes an additional `context` parameter.
- `CoreCryptoError` and its child errors have been refactored to reduce the amount of error we expose and provide
  explicit errors for Proteus errors. The errors we have removed will appear under the `Other` case.
  ```
  enum ProteusError {
      SessionNotFound,
      DuplicateMessage,
      RemoteIdentityChanged,
      Other(Int),
  }

  pub enum MlsError {
      ConversationAlreadyExists,
      DuplicateMessage,
      BufferedFutureMessage,
      WrongEpoch,
      MessageEpochTooOld,
      SelfCommitIgnored,
      UnmergedPendingGroup,
      StaleProposal,
      StaleCommit,
      Other(String)
  }
  ```

### Features

- include the message of the source error when bundling errors together [WPB-14614] (16bc6e6)
- refactor non-WASM error types (9d41c11)
- proteus error codes are `Option<u16>` not `u32` outside wasm also (52547a0)
- refactor WASM error types (31c860a)
- proteus error codes are `Option<u16>` not `u32` (838c1ce)
- add logging for following the changes in mls groups WPB-11544 (8cc0e7f)
- support logs with a context of key/value pairs (b6ef534)
- disambiguate `WrongEpoch` [WPB-14351] (e6a5e01)
- support changing the logger and log level at runtime WPB-11541 (cd071f0)
- add helper to extract data from within a transaction (c852363)
- relax `Debug` trait bound on `CoreCryptoCommand` and add Rust helper [WPB-12132] (e952a0f)

### Bug Fixes

- bump ios deployment target to 15.0 to fix linker issue (1327b1b)
- improve errors when hitting an idb error during IndexedDB migration (0c0c954)
- don't obfuscate rexie error in keystore v1.0.0 (6ed43e6)
- improve errors when hitting a indexdb error during cryptobox migration (682bd9a)
- build without error without default features (97e2d24)

### Documentation

- improve platform-specific test instructions (a08a3b2)
- improve naming and documentation for `TransactionHelper` (e8b4756)

### Testing

- cause jvm kotlin tests to pass (3b8d930)
- fixup tests broken by recent changes (59db9ed)
- change test for build metadata to achieve closer parity with the kotlin test (ffd4e02)
- use wdio where `bun test` was used previously (9c67569)
- use util functions, migrate tests from puppeteer to wdio [WPB-12176] (fbff47a)
- add test util functions [WPB-12176] (196c877)
- crypto: use world.com instead of wire.com [WPB-14356] (6edcef7)
- crypto: use explicit functions to create certificate bundles [WPB-14356] (c52b9b6)
- crypto: remove From impls for CertificateBundle [WPB-14356] (2f59009)
- add js test for for logs with context data (600ba7c)
- add test that build metadata is available in kotlin via uniffi (87c3ab9)
- add test that build metadata is available in ts (4aa18e6)
- add js binding test verifying that we can replace a logger (30d9db7)
- update js tests after renaming initLogger to setLogger (1c1c949)

## v1.1.2 - 2024-11-27

### Bug Fixes

- improve errors when hitting an idb error during IndexedDB migration (8512391)
- don't obfuscate rexie error in keystore v1.0.0 (3896bab)

## v1.1.1 - 2024-11-26

### Bug Fixes

- Improve errors when hitting an indexdb error during cryptobox migration (3266550)

## v1.1.0 - 2024-11-12

### Highlights

- Transactions are now exposed on `CoreCrypto`, opening the door to substantially improve performance by batching
  operations.

### Features

- implement set_data() and get_data() on context [WPB-10919] (7e88695)
- implement in-memory cache on transaction (427e0e0)
- create a keystore transaction struct to be used in the context (4c3f487)
- add decode cli tool (6f83796)
- decouple idb version from crate version (06312fe)
- implement idb migration for all remaining entities [WPB-10144] (545b376)
- implement idb migration for one entity [WPB-10144] (32fd279)
- change aad format [WPB-10108] (8e0b7e5)

### Bug Fixes

- avoid spaces in kotlin test names (1e53e64)
- EntityFindParams SQL clause ordering (a768db4)

### Documentation

- README.md: add a note regarding sed on macOS (b8f2f55)
- README.md: replace xtask usage with the update-versions.sh script (59f2530)
- README.md: update release instructions (b63f17d)
- regenerate CHANGELOG.md with plain git-cliff (e02621f)
- remove CHANGELOG.tpl (8a47ba5)
- update README.md (3eba7b3)

### Testing

- add js binding test verifying that we log errors thrown by the logger (1b959e2)
- add js bindning wrapper test for logger (0005d1d)
- fix jvm tests [WPB-11668] (98ce97e)
- add test for upgrading from basic to x509 credentials (9da3b88)
- test migrations for all entities (48ea746)
- factor out random method into its own trait (8fd49b0)
- interop: make sure that there exists platforms/web/index.html (d9fe1c9)
- crypto-ffi: move index.html contents into a separate file (2dab8bf)
- include E2eiEnrollment and MlsEpochEncryptionKeyPair in tests (0e5a466)

## v1.0.2 - 2024-08-16

### Bug Fixes

- run ci to generate junit report on tags [WPB-10608] (5f93f21)
- grouping were randomly failing because it expected query to be ordered (23f5ff8)

### Testing

- add cross signing tests [WPB-7264] (04f6203)
- add utilities to cross sign certificate chains (3aa7ca2)

## v1.0.1 - 2024-08-05

### Bug Fixes

- get_or_create_key_packages() must respect credential type [WPB-10294] (23081e6)
- handle own commit after mls error [WPB-10105] (aadd06c)

### Testing

- test handling invalid own commit (801f3b8)

## v1.0.0 - 2024-07-18

### Features

- add log level to the callback [WPB-7260] (#600) (c9f44fd)
- Expose logging to public API [WPB-7260] (#560) (180de78)
- crypto-ffi: add bindings for conversation_ciphersuite (4d4dd86)
- crypto: mls: add a way to get the conversation ciphersuite (2e887f1)
- Add logging capabilities to CoreCrypto [WPB-7260] (db53683)

### Bug Fixes

- change the log output to json (956a22d)

### Documentation

- add info about bench execution to README.md, add some benchmark descriptions (ca4dde4)
- FFI.md: add instructions on how to add new API to bindings [WPB-9175] (cd2a288)
- README.md: add more documentation on how we work and release [WPB-9172] (db5d94f)
- README.md: update bindings instructions (0a9d2ac)
- document crates (52646f5)

### Testing

- crypto: box the future so we don't blow up the stack (833d7e6)
- crypto: bring back external remove proposal tests (WPB-9184) (9ede2e7)
- pin future to heap in test with overflowing stack [WPB-9543] (24efdbf)
- crypto-ffi: add a test for conversation ciphersuite getter (5e9ecf7)

## v1.0.0-rc.60 - 2024-05-06

### Bug Fixes

- Ciphersuite being ignored on WASM createConversation (581954b)

## v1.0.0-rc.59 - 2024-05-02

### Bug Fixes

- Support legacy external senders with ECDSA (62f9e17)

## v1.0.0-rc.58 - 2024-04-30

### Bug Fixes

- Avoid lock reentrancy on Generic FFI's conversation_create causing deadlocks (71165f2)
- Use Mozilla's hack to fix Android on x86_64 (2064b1e)

## v1.0.0-rc.57 - 2024-04-25

### Bug Fixes

- Convert TS enums to their discriminant repr (8a480ce)

## v1.0.0-rc.56 - 2024-04-22

### Features

- support JWK external sender and fallback to the previous format (8a1981c)
- Support for P521 (2be007f)

### Bug Fixes

- e2ei signature key translation was not working for P384 & P521. Also cleaned the conversion methods (563f0f3)

## v1.0.0-rc.55 - 2024-03-28

### Features

- \[**breaking**\] borrow enrollment instead of requiring ownership (e700ac5)
- MLS thumbprint has hash algorithm agility (8d5d282)
- \[**breaking**\] WireIdentity now also wraps Basic credentials (55b75fe)
- \[**breaking**\] introduce `e2ei_verify_group_state` to preemptively check a group state through its GroupInfo before
  joining it (09f8bbd)

## v1.0.0-rc.54 - 2024-03-20

### Bug Fixes

- Correctly handle new CRL DPs in add_members (e573f5e)

## v1.0.0-rc.53 - 2024-03-15

### Bug Fixes

- MLS credential verification should ignore expired certificates (d53edef)

## v1.0.0-rc.52 - 2024-03-14

### Bug Fixes

- Correctly handle new CRL DPs (d3e0b84)

## v1.0.0-rc.51 - 2024-03-13

### Bug Fixes

- Various tweaks and fixes for revocation [WPB-6904] (e55c37d)
- refresh time of interest in the PKI env before querying device/user identities (c4a3140)

## v1.0.0-rc.49 - 2024-03-11

### Bug Fixes

- Misc improvements (7d8ea56)
- Remove unique index on SignatureKeypair.pk (4301ac4)
- catch the "NoMatchingEncryptionKey" error from openmls and also return a "OrphanWelcome" one (4990be7)

## v1.0.0-rc.48 - 2024-03-07

### Bug Fixes

- deduplicate CRL DPs (5b8815b)

### Testing

- Add test to assert that a basic client can join a verified conversation (cec3281)
- Add test to assert that revocation works properly (a28c8f6)

## v1.0.0-rc.47 - 2024-03-04

### Features

- Upload unit test results in junit format (WPB-6928) (11e2839)

### Bug Fixes

- check revocation in status (b3857a4)
- Don't create an empty PKI env on restore (4a50632)

### Testing

- remove ignore (and not relevant anymore) test (40fb405)

## v1.0.0-rc.46 - 2024-02-28

### Bug Fixes

- rollback handling of e2ei deactivation since it creates issues in the regular case (6821328)

## v1.0.0-rc.44 - 2024-02-27

### Bug Fixes

- only restore PKI env if client is e2ei capable. This helps client developers when e2ei is turned off (a37b387)

## v1.0.0-rc.43 - 2024-02-22

### Bug Fixes

- Update deps for wasm-browser-run (0b9aae6)

### Testing

- fix joining by external commit test (918c6dc)

## v1.0.0-rc.41 - 2024-02-21

### Bug Fixes

- Remove cached is_e2ei_capable flag (02fde65)
- KeyPackage lifetime validation when receiving messages (b998d03)
- Integrate -pre version to iDB store version (5992227)

## v1.0.0-rc.40 - 2024-02-20

### Bug Fixes

- TS mapping of identities was using experimental methods (487de51)

## v1.0.0-rc.39 - 2024-02-20

### Features

- add serialNumber, notBefore & notAfter in `WireIdentity` object (1a8e092)
- add display name in dpop token (d9891ac)

### Bug Fixes

- Harden x509 validation & revocation checks (8984fc5)

### Documentation

- update all doc warnings including a lot of broken links (e79f99d)

### Testing

- verify that registering a TA twice fails (115e87a)

## v1.0.0-rc.38 - 2024-02-16

### Features

- add getter for external sender to seed subconversations (2b423b1)

### Bug Fixes

- intermediates were not registered during enrollment (da231e5)

## v1.0.0-rc.37 - 2024-02-15

### Features

- \[**breaking**\] `clientPublicKey` now also works for x509 credentials (60a6889)
- Validate x509 credentials when introduced (b2dbb43)

### Bug Fixes

- \[**breaking**\] Add dedicated error for stale commits and proposals (bede132)
- verify GroupInfo (52e0fb0)
- Allow revoked Credentials in MLS operations (b5fe5c3)
- Reenable E2EI tests (d71155a)
- Update tests (d898ad8)
- post-rebase fixes (b872550)
- Consider x509 credentials as always valid if no PKI environment is available (df72c15)
- Adapt calls to OpenMLS new async methods (d2f1f3f)
- Disable non working (MissingSki) E2EI tests (ea0f70a)
- Undo WASM binding API mistake (aa3edbc)

### Testing

- Get rid of rcgen-based x509 cert generation (01621a3)

## v1.0.0-rc.35 - 2024-01-29

### Features

- \[**breaking**\] return CRL Distribution Points when registering intermediate certificates (30dced5)

### Bug Fixes

- register intermediate certificates at issuance since they're not fetchable afterwards (b2b3399)

## v1.0.0-rc.34 - 2024-01-25

### Features

- \[**breaking**\] change certificate expiry from days to seconds in the public API (fe1ad71)

## v1.0.0-rc.33 - 2024-01-24

### Features

- filter out root CA when registering intermediates in case the provider repeats it (db0d451)
- \[**breaking**\] remove refreshToken handling from WASM altogether as it is not used (1d84dbb)

### Bug Fixes

- restore pki_env from disk whenever necessary (0af2919)
- relax uniqueness constraint on intermediate certificates and CRLs on sqlite (1c333e9)

## v1.0.0-rc.32 - 2024-01-23

### Features

- Add full PKI test harness (8090577)

### Bug Fixes

- Remove unused test (9e06774)
- Use forked x509-cert to fix WASM compilation (71cbe16)
- Fix tests (4ba3b37)
- Duration overflow in x509 expiration setting (f13bcb8)
- Typo in E2eiAcmeCA registration SQL query (613f8f8)
- Add missing CRLDP field to FFI + fill it up (6c61edf)

## v1.0.0-rc.31 - 2024-01-22

### Bug Fixes

- use 2 acme authorizations instead of 1 (8313977)

## v1.0.0-rc.30 - 2024-01-17

### Features

- \[**breaking**\] expose keyauth in ACME authz (67f5bb4)

### Bug Fixes

- wrong rusty-jwt-tools pinned in rc30 (a6326b7)

## v1.0.0-rc.29 - 2024-01-16

### Bug Fixes

- pin rusty-jwt-tools v0.8.4 fixing an issue with the wrong signature key being used for the client DPoP token (24fabf9)

## v1.0.0-rc.28 - 2024-01-15

### Bug Fixes

- actually fix keyauth issue (cefed75)

## v1.0.0-rc.27 - 2024-01-15

### Bug Fixes

- use rusty-jwt-tools v0.8.1 which fixes the keyauth issue (d57ff1c)

## v1.0.0-rc.26 - 2024-01-15

### Bug Fixes

- previous fix was not compiling (46f5a01)

## v1.0.0-rc.25 - 2024-01-15

### Bug Fixes

- e2ei keystore method 'find_all' was unimplemented on WASM for intermediate CAs & CRLs (4164adb)

## v1.0.0-rc.24 - 2024-01-15

### Features

- Added support for PKI environment (9478ff5)
- change ClientId & Handle format to URIs (ab62648)

### Bug Fixes

- Pin e2ei package tag (28fc908)
- Add PKI API to bindings (6e88c3e)

## v1.0.0-rc.23 - 2024-01-08

### Features

- \[**breaking**\] remove PerDomainTrustAnchor extension altogether. Backward incompatible changes ! (be4edd4)

### Bug Fixes

- null pointer in Javascript when calling 'new_oidc_challenge_response' (806ce08)
- Swift wrapper for E2eiEnrollment was not used in other methods (a7ff1d1)
- use 'implementation' Gradle configuration not to enforce dependencies version into consumers. Fixes #451 (48b3fc2)

## v1.0.0-rc.22 - 2023-12-13

### Features

- \[**breaking**\] remove 'clientId' from activation & rotate enrollment now that we expect a specific ClientId format
  (9f1a6dc)
- \[**breaking**\] add `get_credential_in_use()` to check the e2ei state from a GroupInfo (5508dc5)
- \[**breaking**\] rename `E2eiConversationState::Degraded` in to `E2eiConversationState::NotVerified` (151c5c4)
- \[**breaking**\] managed OIDC refreshToken (wpb-5012) (62ed3a3)

### Bug Fixes

- README mentions a task which doesn't exist (#445) (68c7a63)
- remove unnecessary boxing of values before persisting them in IndexedDb (82eac29)

### Testing

- verify that clients can create conversation with x509 credentials (f089a03)

## v1.0.0-rc.21 - 2023-12-05

### Features

- \[**breaking**\] canonicalize ClientId keeping only the regular version where the UserId portion is the hyphenated
  string representation of the UUID. Also apply this to 'getUserIdentities()' (4ea3a1c)

## v1.0.0-rc.20 - 2023-12-04

### Features

- better errors: 'ImplementationError' was way too often used as a fallback when the developer was too lazy to create a
  new error. This tries to cure that, especially with e2ei errors. It also tries to distinguish client errors from
  internal errors (e16624f)
- \[**breaking**\] simplify API of 'add_clients_to_conversation' by not requiring to repeat the ClientId of the new
  members alongside their KeyPackage when the former can now be extracted from the latter (3c85678)
- \[**breaking**\] introduce handle & team in the client dpop token (ac6b87e)

### Testing

- test DB migration from 0.9.2 (9c1e201)

## v1.0.0-rc.19 - 2023-11-20

### Testing

- Add new keystore regression test to CI (2714259)
- Test keystore migration regressions (b040f01)

## v1.0.0-rc.18 - 2023-11-14

### Bug Fixes

- Preserve schema upgrade path between schemafix'd versions and upcoming (1308cfe)

## v1.0.0-rc.17 - 2023-10-30

### Bug Fixes

- Don't depend on OpenSSL on WASM (cda1209)
- dynamic linking issue on Android with the atomic lib (19808e2)

## v1.0.0-rc.16 - 2023-10-12

### Features

- Switch from node to bun (3c6caf9)

### Bug Fixes

- Prevent CI from overriding RUSTFLAGS (c2aa638)
- Added missing d.ts declarations (4a77bad)
- KP test was taking too much time (5e7bae5)

### Documentation

- Updated README.md noting Bun usage (aedbac2)

## v1.0.0-rc.15 - 2023-10-11

### Features

- re-export e2ei types (f765df8)

### Bug Fixes

- add '-latomic' flag when building for Android to dynamically link atomic lib which is supposedly causing issues with
  openssl (4a100ab)

## v1.0.0-rc.14 - 2023-10-09

### Bug Fixes

- backward incompatible database schemas. It only preserves Proteus compatibility when migrating from CC 0.11.0 ->
  1.0.0. For anything MLS-related it is recommended to wipe all the groups (4c95713)

## v1.0.0-rc.13 - 2023-09-27

### Features

- \[**breaking**\] make initial number of generated KeyPackage configurable (dcd3dc3)
- add e2ei ffi in Swift wrapper (fbd38a9)
- \[**breaking**\] add LeafNode validation (49caeb8)

### Bug Fixes

- do not reapply buffered messages when rejoining with external commit (2df2d04)
- coarsetime issue causing compilation error on WASM (9585594)

### Testing

- try fixing flaky time-based LeafNode validation tests (5b9f014)

## v1.0.0-rc.12 - 2023-08-31

### Bug Fixes

- use sed in a cross-platform way for kt edits (698fda9)

## v1.0.0-rc.11 - 2023-08-31

### Bug Fixes

- \[**breaking**\] UniFFI Errors (568bdf3)

## v1.0.0-rc.10 - 2023-08-31

### Bug Fixes

- UniFFI symbol matching (205b8b0)

## v1.0.0-rc.9 - 2023-08-30

### Features

- \[**breaking**\] return raw PEM certificate in `getUserIdentities` for display purpose (cd6e768)
- \[**breaking**\] bump rusty-jwt-tools to v0.5.0. Add 'revokeCert' to AcmeDirectory (a8316b3)

### Bug Fixes

- Make UniFFI produce the correct symbol in bindings (9b5ec44)
- change e2ei enrollment identifier causing collision now that keypairs are reused (3e2639c)

### Documentation

- regenerate changelog (a1525e2)

## v1.0.0-rc.8 - 2023-08-25

### Features

- expose `getUserIdentities` through the FFI (6eeb571)
- \[**breaking**\] also restore buffered messages on the receiver side (a552197)
- increase max past epoch to 3 since backend inordering of messages requires client's config to backend's one + 1
  (1d35364)

### Bug Fixes

- TLS serialization of x509 credential (124d7b3)
- \[**breaking**\] UniFFI Async cancellable routines + bytes (05d660a)
- Make interop runner pick up CHROME_PATH from env (3c4ed23)

### Testing

- fix wasm test hitting a limit. Just split them for now, waiting for a proper solution (1b68f7e)
- fix spinoff 0.8 compilation (4b9987e)

## v1.0.0-rc.7 - 2023-08-09

### Features

- correlate RotateBundle with a GroupId (0077dbe)

### Bug Fixes

- kotlin tests not compiling after methods became async (7f7e015)

## v1.0.0-rc.6 - 2023-08-08

### Features

- \[**breaking**\] handle the case when a client tries to decrypt a Welcome referring to a KeyPackage he already has
  deleted locally (ce6e71e)
- Add keystore dump exporter CLI tool (fb0f65d)

### Bug Fixes

- `e2eiRotateAll` return type was not wrapped (7d77b7e)
- Signature KeyPair was rotated when credentials were which was zealous. Also fixes an important bug caused by inverted
  private & public keypair part when rotating credentials (f607138)

### Testing

- add a roundtrip test for e2ei credential rotation to tackle a false positive regression (52bfa04)

## v1.0.0-rc.5 - 2023-07-31

### Bug Fixes

- e2ei enum for conversation state was unused and failing the Typescript publication. Now CI will have the same compiler
  flags when checking bindings in order to prevent this again (3744e93)

## v1.0.0-rc.3 - 2023-07-31

### Features

- \[**breaking**\] rename `e2eiIsDegraded` by `e2eiConversationState` and change return type to an enumeration instead
  of a boolean to match all the e2ei states a conversation could have. (e7404d8)
- add `e2ei_is_enabled` for clients to spot if their MLS client is enrolled for end-to-end identity (1521ad7)

### Bug Fixes

- Proteus wasm test now uses wasm-browser-run (712e959)
- cargo doc fixes for wasm-browser-run (1455b0e)
- Interop runner now uses wasm-browser-run to install chromedriver (07e6bcc)
- Support chromedriver 115 delivery method (1e2939f)
- `e2ei_rotate_all` was returning 'undefined' on WASM (fdee4c0)
- \[**breaking**\] entities leaked. Some methods handling the lifecycle of a MLS group were not cleaning created
  entities correctly. This avoids required storage space to grow linearly. (51a7e13)

## v1.0.0-rc.2 - 2023-07-25

### Features

- \[**breaking**\] expose 'ClientId' in e2ei methods for credential rotation since the e2ei client identifier differs
  from the one used in MLS (d687ae3)
- Include certificate roots and certificate policy in GroupContext - WPB-1188 (2ef9892)

## v1.0.0-rc.1 - 2023-07-21

### Features

- buffer pending messages during join by external commit process to tolerate unordered messages (3f20913)
- Use -dalek fast proteus version (2196b23)
- Use RFC9420 OpenMLS [WPB-579] (b7c18cd)

### Bug Fixes

- `merge_pending_group_from_external_commit` FFI incorrect return type (bfd5eed)
- UniFFI bindgen requirements & size tweaks (a9983ff)
- Address review comments (d878bcb)
- Revert bloating up binaries by emitting crate-type=lib (80ae18b)
- Strip mobile libraries (694eebf)
- handles nicely self-commits (4bcb77c)

### Documentation

- Add document to detail our crypto primitives (a149986)

## v1.0.0-pre.8 - 2023-07-18

### Bug Fixes

- use correct env var for maven central credentials (#355) (38207e2)

## v1.0.0-pre.7 - 2023-07-17

### Features

- \[**breaking**\] prevent conversation overwrite when joining (3149f97)
- \[**breaking**\] detect duplicate messages from previous epoch and fail with a dedicated error (e8c2588)
- publish to Sonatype instead of Github Packages (#347) (7167bf5)

### Bug Fixes

- make clippy happy (c4fac26)
- xtask release fix for kotlin sonatype publishing (f3649ba)
- Disable stripping to allow FFI to build (1d173ce)
- Incorrect error value in tests (6c9888c)

## v1.0.0-pre.6 - 2023-07-06

### Features

- \[**breaking**\] credential rotation (fa32918)
- PostQuantum Ciphersuite (ea7a8c6)
- \[**breaking**\] remove `export_group_info()` (4525084)

### Bug Fixes

- Wrong HPQ ciphersuite identifier (7c2d982)
- Address review & de-flakify cert expiration test (3083771)
- Target correct branches (b2b65a6)
- PQ support for FFI (653f8bc)
- Benches modification (c724f3b)

## v1.0.0-pre.5 - 2023-06-12

### Bug Fixes

- backend sends raw GroupInfo, we were trying to deserialize it from a MlsMessage (5944f84)

## v1.0.0-pre.3 - 2023-06-09

### Bug Fixes

- pin a version of openmls with a fix in tls_codec related to variable length encoding (2a50f8e)

### Testing

- fix external commit test was not merging the external commit (457e796)

## v1.0.0-pre.2 - 2023-06-09

### Bug Fixes

- typo in build xcframework task (bca3660)

## v1.0.0-pre.1 - 2023-06-09

### Features

- CoreCrypto draft-20 upgrade (4e7d907)
- generate XCFramework when releasing for Swift (#330) (19fd4c0)

## v0.11.0 - 2023-06-01

### Features

- add `e2ei_is_degraded` to flag a conversation as degraded when at least 1 member is not using a e2ei certificate
  (f39a868)

## v0.10.0 - 2023-05-25

### Features

- \[**breaking**\] hide everywhere `Vec<Ciphersuite>` appears in the public API since it seems to fail for obscure
  reasons on aarch64 Android devices. Undo when we have a better understanding of the root cause of this (08584e8)

### Bug Fixes

- usize to u64 conversion error on Android in `client_valid_keypackages_count`. Whatever the reason this applies a
  default meaningful value (2d90576)
- \[**breaking**\] creating a MLS group does not consume an existing KeyPackage anymore, instead it always generates a
  new local one. Also, explicitly ask for the credential type of the creator before creating a new MLS group. (254e336)
- mobile FFI was failing when initializing MLS client due to a Arc being incremented one too many times. Also add the
  E2EI API in the Kotlin wrapper and a test for it (e0a5dcb)

## v0.9.2 - 2023-05-22

### Bug Fixes

- new table was mistakenly in an old migration file (e65d91c)

## v0.9.1 - 2023-05-17

### Bug Fixes

- Size regression on FFI (5cb463b)

## v0.9.0 - 2023-05-16

### Features

- add persistence options to e2ei enrollment instance (e3ace8d)
- \[**breaking**\] enable multi ciphersuite and multi credential type support (f5e5714)
- \[**breaking**\] support & expose "target" in ACME challenges (1a77795)

### Bug Fixes

- Reload proteus sessions when `restore_from_disk` is called (c0828b0)
- return finalize & certificate url (448bff0)

### Testing

- have interop runner verify the generic FFI (a00f73c)

## v0.8.1 - 2023-04-27

### Bug Fixes

- native libraries not included in android package (#308) (73d9a3e)
- typescript path has the wrong file extension (#309) (af1ee13)

## v0.7.0 - 2023-04-12

### Features

- verify x509 credential identity and return identity (client_id, handle, display_name, domain) once message is
  decrypted (45787f4)

### Bug Fixes

- Fixed iOS keychain handling with proper attributes (1f2af04)

## v0.7.0-rc.4 - 2023-03-28

### Features

- remove any transitive crate using ring. As a consequence supports EcDSA on WASM (1588676)
- copy/modify kotlin wrapper from Kalium (#284) (b96507e)
- \[**breaking**\] support creating a MLS client from an e2e identity certificate (f12dcf9)

### Bug Fixes

- \[**breaking**\] Tweak WASM API (a3ebfcb)
- use schnellru fork for GroupStore faillible inserts (cdf337c)
- Fixed GroupStore memory limiter behavior (97c9fc5)

## v0.7.0-rc.3 - 2023-03-16

### Bug Fixes

- Proteus auto prekey ids not incrementing (50603e7)

## v0.7.0-rc.1 - 2023-03-15

### Features

- \[**breaking**\] latest e2e identity iteration. ClientId (from MLS) is used instead of requiring just parts of it
  (fba4323)
- Added API to check the `Arc` strongref counter (d25a569)
- \[**breaking**\] Add ability to mark subconversations (e7ed3e0)
- \[**breaking**\] Change proteus auto prekey return type to include prekey id (f99c458)
- \[**breaking**\] Added LRU cache-based underlying group store to replace the HashMaps (3d4dd38)

### Bug Fixes

- \[**breaking**\] Make FFI parameters compliant with rfc8555 (df2e4f1)
- Added missing version() function to Swift bindings (2366539)
- enable ios-wal-compat for iOS builds by default (f8003c1)
- Exclude self from self-remove-commit delay (8378510)
- Fix rustsec advisories on xtask deps (2cf29e6)

## v0.6.2 - 2023-02-16

### Bug Fixes

- Fixed commitDelay being undefined when FFI says 0 (9a81d54)

## v0.6.1 - 2023-02-16

### Bug Fixes

- publishing for JVM generating empty artifacts (#251) (70b9d90)
- Fall back on false when the callback doesn't retrurn a Promise (6db3147)
- Proteus auto prekey might overwrite Last Resort prekey (2e4c5b5)

## v0.6.0 - 2023-02-13

### Features

- adapt with acme client library tested on real acme-server forked. Also some nits & dependencies pinned (efac714)

### Bug Fixes

- xtask release outputs dry-run log unconditionally (9f5d35b)

## v0.6.0-rc.8 - 2023-02-09

### Features

- Added support for Proteus Last Resort PreKeys (boooo!) (8bac78f)
- \[**breaking**\] Async callbacks (96ad897)
- Externally-generated clients (457ee28)

## v0.6.0-rc.7 - 2023-02-06

### Bug Fixes

- Fixed E2E interop test for breaking api changes (6b3030c)
- New e2eidentityerror enum member wasn't exposed over ffi (35ea9e5)
- TS/WASM build issues & test (9d2bef8)

## v0.6.0-rc.6 - 2023-02-02

### Bug Fixes

- Proteus error system not working (at all) (814590c)
- Force cargo to use git cli to avoid intermittent CI failures (3f9a60c)

## v0.6.0-rc.5 - 2023-01-25

### Features

- Added support for Proteus error codes (20c75df)

### Bug Fixes

- \[**breaking**\] Added conversation id to clientIsExistingGroupUser callback (b380d3f)
- Increment IndexedDB store version when crate version changes (d3f960c)

## v0.6.0-rc.4 - 2023-01-20

### Features

- expose end to end identity web API (dad51e9)
- add end to end identity bindings (a96a8b6)

### Bug Fixes

- aarch64-apple-ios-sim target not compiling (#213) (93f47c2)
- Cryptobox import now throws errors on missing/incorrect store (e897a60)

## v0.6.0-rc.3 - 2022-12-15

### Bug Fixes

- Added missing Proteus APIs and docs (8ee833e)

## v0.6.0-rc.2 - 2022-12-15

### Bug Fixes

- Functional Android NDK 21 CI (0d70f29)
- Publish android CI (470ec4f)
- unreachable pub makes docs build fail (4a29191)

## v0.6.0-rc.1 - 2022-12-15

### Features

- expose a 'WrongEpoch' error whenever one attempts to decrypt a message in the wrong epoch (fc87a6f)
- add 'restore_from_disk' to enable using multiple MlsCentral instances in iOS extensions (541674a)
- add specialized error when trying to break forward secrecy (b638a0e)
- add 'out_of_order_tolerance' & 'maximum_forward_distance' to configuration without exposing them and verify they are
  actually applied (838fb62)
- \[**breaking**\] change 'client_id' in CoreCrypto constructor from a String to a byte array to remain consistent
  across the API (e89cbf9)
- Expose proteus prekey fingerprint - CL-107 (09e685d)

### Bug Fixes

- Broken Proteus implementation (f0dc510)
- prevent application messages signed by expired KeyPackages (cfe1837)
- Fix cryptobox import on WASM [CL-119] (c55ec39)
- Incorrect TS return types [CL-118] (89d1e14)

### Testing

- ensure we are immune to duplicate commits and out of order commit/proposal (96a6af8)

## v0.6.0-pre.5 - 2022-11-10

### Features

- Expose proteus session fingerprints (local and remote) - CL-108 (6821800)
- support deferred MLS initialization for proteus purposes [CL-106] (5f20e89)

## v0.6.0-pre.4 - 2022-11-07

### Features

- Expose session exists through the ffi - CL-101 (40f8b5b)

### Bug Fixes

- \[**breaking**\] Incorrect handling of enums across WASM FFI (dae9a0a)
- commits could lead to inconsistent state in keystore in case PGS serialization fails (95d3d6a)
- Make tags have semantic versioning names and downgrading to swift 5.5 - CL-49 (81c32b8)
- Publication of swift packages (cd80cac)

### Testing

- ensure everything keeps working when pure ciphertext format policy is selected (579c752)

## v0.6.0-pre.3 - 2022-11-01

### Bug Fixes

- Change the internal type of the public group info to Vec<u8> so we don't have extra bytes in the serialized message -
  FS-1127 (2ee4e18)

## v0.6.0-pre.1 - 2022-10-21

### Features

- \[**breaking**\] expose a 'PublicGroupStateBundle' struct used in 'CommitBundle' variants (a9bfe56)
- \[**breaking**\] remove all the final\_\* methods returning a TLS encoded CommitBundle (62212ad)
- Returning if decrypted message changed the epoch - CL-92 (#152) (a4d4661)
- Exporting secret key derived from the group and client ids from the members - CL-97 - CL-98 (#142) (b8bfa8a)
- Added API to generate Proteus prekeys (cee049a)
- Fixed Cryptobox import for WASM (30d5140)
- Added support for migrating Cryptobox data (f6a3da8)
- Added FFI for CoreCrypto-Proteus (01b0ee5)
- Added support for Proteus (9743949)
- validate received external commits making sure the sender's user already belongs to the MLS group and has the right
  role (f70ff30)
- \[**breaking**\] rename callback\~~`client_id_belongs_to_one_of`\~~ into `client_is_existing_group_user` (36e34ca)
- \[**breaking**\] external commit returns a bundle containing the PGS (54ba6f5)
- \[**breaking**\] add `clear_pending_group_from_external_commit` to cleanly abort an external commit. Also renamed
  `group_state` argument into `public_group_state` wherever found which can be considered a breaking change in some
  languages (b5db441)
- \[**breaking**\] rename `MlsConversationInitMessage#group` into `MlsConversationInitMessage#conversation_id` because
  it was misleading about the actual returned value (9ed7025)

### Bug Fixes

- 'join_by_external_commit' returns a non TLS serialized conversation id (eaa22e4)

### Testing

- fix external commit tests allowing member to rejoin a group by external commit (30641a7)
- add a default impl for 'TestCase', very useful when one has to debug on IntelliJ (d228e39)
- parameterize ciphers (b196450)
- ensure external senders can be inferred when joining by external commit or welcome (46287fa)
- fix rcgen failing on WASM due to some unsupported elliptic curve methods invoked at compile time (eea14db)
- ensure external commit are retriable (7fee252)

## v0.5.2 - 2022-09-27

### Bug Fixes

- wire-server sends a base64 encoded ed25519 key afterall. Consumers are in charge of base64 decoding it and pass it to
  core-crypto (5d8c480)
- TS Ciphersuite enum not correctly exported (dcbbea6)

### Documentation

- add installation instructions for e2e runner on macos (3271adf)

## v0.5.1 - 2022-09-21

### Bug Fixes

- incorrect null handing in Typescript wrapper for 'commitPendingProposals' (5623214)
- external_senders public key was not TLS deserialized causing rejection of external remove proposals (a8b6124)

### Documentation

- better explanation of what DecryptedMessage#proposals contains (0e2ebfa)

## v0.5.0 - 2022-09-14

### Features

- \[**breaking**\] 'commit_pending_proposals' now returns an optional CommitBundle when there is no pending proposals to
  commit (9a7fd84)

### Bug Fixes

- NPM publish workflow missing npm ci + wrong method names in TS bindings (c215d61)
- NPM publish workflow missing npm i (ffb1480)
- rollback openmls & chrono in order to release 0.5.0 (d242532)
- pin openmls without vulnerable chrono (0af35df)
- wee_alloc memory leak + NPM publish issue (f937b18)
- Unreachable pub struct breaks docgen (02d7c16)
- Fixed iOS SQLCipher salt handling within keychain (5e32ad9)
- \[**breaking**\] Changed misleading callback API and docs (bd25518)
- \[**breaking**\] Added missing TS API to set CoreCrypto callbacks (74c429d)
- force software implementation for sha2 on target architectures not supporting hardware implementation (i686 & armv7 in
  our case) (baca163)

### Documentation

- add forgotten 0.4.0 changelog (699e071)

## v0.4.1 - 2022-09-01

### Bug Fixes

- uniffi breaking changes in patch release and ffi error due to unused `TlsMemberAddedMessages` (953ebb5)

## v0.4.0 - 2022-08-31

### Features

- commits and group creation return a TLS serialized CommitBundle. The latter also contains a PublicGroupStateBundle to
  prepare future evolutions (9215f3d)
- \[**breaking**\] 'decrypt_message' returns the sender client id (7665f9d)
- use 128 bytes of padding when encrypting messages instead of 16 previously (4a1f3d5)
- Add function to return current epoch of a group [CL-80] (#96) (fde8804)
- Adding a wrapper for the swift API and initial docs [CL-62] (#89) (59e07cf)
- add '#[durable]' macro to verify the method is tolerant to crashes and persists the MLS group in keystore (08e174b)
- expose 'clear_pending_commit' method (7aa5ada)
- allow rollbacking a proposal (67e45e7)
- \[**breaking**\] expose 'clear_pending_commit' method (72ff109)
- \[**breaking**\] allow rollbacking a proposal (641bcb4)

### Bug Fixes

- ensure durable methods are well tested and actually durable (912bdf9)

### Testing

- add reminder for x509 certificate tests (55578de)

## v0.3.0 - 2022-08-12

### Features

- review external add proposal validation and remove 'InvalidProposalType' error (f27c882)
- remove required KeyPackage when creating an external add proposal (93af490)
- remove commits auto-merge behaviour (e85f3c0)
- expose GroupInfo after commit operation (d822315)
- use draft-16 implementation of external sender. Expose a correct type through ffi for remove key (12fd96c)
- Add API to wipe specific group from core crypto [CL-55] (#81) (45d9757)
- Adding validation to external proposal [CL-51] (#71) (4fc74d0)
- decrypting a commit now also return a delay when there are pending proposals (983dce8)
- decrypting a commit now also return a delay when there are pending proposals (ae129ee)
- 'commit_delay' now uses openmls provided leaf index instead of computing it ourselves. It is also now infallible.
  (81913a0)
- ensure consistent state (a657d38)
- \[**breaking**\] add commit delay when a message with prending proposals is processed [CL-52] (#67) (2ee2827)
- Added KeyPackage Pruning (8ae3ab0)
- Added support for external entropy seed (16c913d)
- join by external commit support - CL-47 (#57) (4828cb6)
- Added Entity testing to keystore (9561c61)
- external remove proposal support (8b8df2e)
- supports and validates x509 certificates as credential (dfcb29d)
- expose function to self update the key package to FFI and Wasm #CL-17 (#48) (d9fdc8e)
- Added support for wasm32-unknown-unknown target (75a91f2)
- support external add proposal (c90aa0b)
- Added method to leave a conversation (bd72c3b)
- enforce (simple) invariants on MlsCentralConfiguration (9801387)
- expose add/update/remove proposal (34001c1)

### Bug Fixes

- Clippy fix impl eq (42ef44d)
- libgcc swizzling for android was removed (d198ca9)
- Cleaned up FFI names for clearer intent (de67752)
- Caught up WASM api with the internal API changes (76eeaac)
- doctests were failing because included markdown snippets were parsed and compiled (808446c)
- defer validation that a callback has to be set for validating external add proposal after incoming proposal identified
  as such (57edb3f)
- Updated RustCrypto dependencies to match hpke-rs requirements (5f7c08f)
- group was not persisted after decrypting an application message (d46d95d)
- UniFFI wrong type defs (1c033db)
- aes_gcm compilation issue (e6a69cc)
- WASM persistence & CoreCrypto Async edition (5044b7d)
- 'client_keypackages' does not require mutable access on 'mls_client' (4df44a4)
- add_member/remove_member IoError (7ac5422)
- Incorrect number of keypackages returned (7c456fa)
- Added support for MLS Group persistence [CL-5] (0c6f36a)

### Documentation

- Added bindings docs where appropriate + generated gh-pages (c966a42)
- fix Client struct documentation (30acb9a)
- Improving docs of Core-Crypto - [CL-50] (#60) (a9e772b)

### Performance

- avoid cloning conversation extra members when creating the former (0bf20d3)

### Testing

- add tests for 'commit_pending_proposals' (8198d66)
- verify that commit operation are returning a valid welcome if any (9458abf)
- use Index trait to access conversation from Central instead of duplicate accessor (7fc82b8)
- use central instead of conversation (321a60e)
- fix minor clippy lints in tests (dce4c2d)
- apply clippy suggestions on test sources (152d76b)
- reorganize tests in conversation.rs (0b8892f)
- nest conversation tests in dedicated modules (e94830f)
- verify adding a keypackage to a ConversationMember (05a5469)

## v0.2.0 - 2022-03-22

### Features

- add android project (614de7a)
- add tasks for building and copying jvm resources (719772b)
- add jvm project (29f82af)
- WIP hand-written ts bindings (ffcfe76)
- Generate Swift & Kotlin bindings 🎉 (72b8c5e)
- Updated deps (a99976b)
- Added salt in keychain management instead of flat AES-encrypted file (8a9ba96)
- Added WIP DS mockup based on QUIC (28f094f)
- Added ability to create conversations (!!!) (4469b3c)
- Added api support for in-memory keystore (19bb84a)
- Added in-memory faculties for keystore (5e41221)
- Added benches for the MLS key management (5207685)
- Added benches & fixed performance issues (d5ade0d)
- Added integration tests + fixes (df24f90)
- Implemented LRU cache for keystore (c10c080)
- Added support for Proteus PreKeys (88a19d0)
- Progress + fix store compilation to WASM (528d2ca)

### Bug Fixes

- set correct path to toolchain depending on platform & copy bindings (cab317d)
- Fix broken tests (d4bae6c)
- Tests fix (b2b15c5)
- Fixed iOS WAL behavior for SQLite-backed stores (f644e42)
- Fix Keystore trait having update method removed (5eeef67)
- clippy + fmt pass on core-crypto (a230b95)
- fmt + clippy pass (e979a2f)
- Migrations were incorrectly defined (d9a43a6)
