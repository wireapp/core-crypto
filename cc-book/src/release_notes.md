# Changelog

## Unreleased

### Changes

- `GroupInfo` and `Welcome` constructors are now fallible.

  Both `GroupInfo::new` and `Welcome::new` previously accepted any byte sequence unconditionally. They now validate the
  bytes as a TLS-encoded MLS structure at construction time and return an error if the bytes are not well-formed.

  Affected platforms: android, ios, web

- `GroupInfo::copy_bytes()` and `Welcome::copy_bytes()` have been removed.

  These methods returned raw byte copies of the wrapped data. They are not available on the new types because the
  underlying types do not have a TLS serialization implementation.

  Affected platforms: android, ios, web

- `GroupInfoBundle.payload` now contains a byte array instead of a class instance.

- Added `Welcome::serialize()`

  We had test functions which required the serialized bytes given a `Welcome` instance. So we added the ability to
  recreate those bytes.

  Affected platforms: android, ios, web

- `GroupInfo` and `Welcome` no longer support equality, hashing, or hex display.

  These capabilities were previously exposed in the generated bindings. Client code relying on comparing or hashing
  these values will need to be updated.

  Affected platforms: android, ios, web

- `CoreCryptoContext::export_secret_key()` and `CoreCryptoFfi::export_secret_key()` now return `SecretKey` instead of
  `Vec<u8>`.

  Use `SecretKey::copy_bytes()` to extract the raw bytes when needed.

  Affected platforms: android, ios, web

- `CoreCryptoContext::get_external_sender()` now returns `ExternalSenderKey` instead of `Vec<u8>`.

  Use `ExternalSenderKey::copy_bytes()` to extract the raw bytes when needed.

  Affected platforms: android, ios

- `CoreCryptoContext::create_conversation()` now accepts `Option<ExternalSender>` instead of
  `Option<ExternalSenderKey>`.

  Previously the raw external-sender bytes were parsed inside `create_conversation`. Callers must now parse external
  senders ahead of time using one of the new free functions: `ExternalSender::parse_jwk` for the JWK form,
  `ExternalSender::parse_public_key()` for the legacy raw public-key form, or `ExternalSender::parse()` which tries both
  in turn. Parse errors surface at parse time rather than during conversation creation. Call
  `ExternalSender::serialize()` to recover the raw bytes when needed.

  Affected platforms: android, ios, web

- `DatabaseKey` constructor parameter is now named `bytes` not `key`

  We've changed the internal macro which generates this type and consequently the parameter name changed.

  Affected platforms: ios

- The `decode` tool has been extracted into its own repository at <https://github.com/wireapp/decode>.

### Features

- expose enitre read-only API in Kotlin on the `CoreCrypto` type. This allows reading data without opening a
  transaction.

- replaced `CoreCrypto.init(database: Database)` with class constructor `new CoreCrypto(database: Database)`

  Affected platforms: web

- added PKI Environment API

  - added `PkiEnvironment` struct/class with language-specific constructor
  - added `PkiEnvironmentHooks` interface which has to be implemented by a client and will be used by CoreCrypto during
    e2ei flow
  - added `CoreCrypto.setPkiEnvironment()` to set a PkiEnvironment on a `CoreCrypto` instance
  - added `CoreCrypto.getPkiEnvironment()` to get the PkiEnvironment of a `CoreCrypto` instance

  Affected platforms: android, ios, web

- added `Database.open(location: String, key: DatabaseKey)` as a static method to construct a persistent database
  instance, and `Database.open(key: DatabaseKey)` / `Database.inMemory(key: DatabaseKey)` to construct an in-memory
  database instance.

  Removed default Constructor from swift to align with other language bindings.

  Affected platforms: android, ios, web

- `CoreCrypto.e2ei_is_env_setup()` can't throw anymore and will always return a boolean.

- added `Database.getLocation()` to allow getting the location of a persistent database instance. Returns null if the
  database is in-memory.

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

  - `CustomConfiguration.keyRotationSpan` now defines milliseconds instead of seconds

  Affected platforms: web

- The `update_database_key` function has been moved; it is now a static function `Database::update_key`.

  Affected platforms: all

- removed `CoreCryptoContext.markConversationAsChildOf()`

  No client should actually be using this function and all existing references to it should be removed.

  Affected platforms: all

- removed `CoreCryptoContext.proteusReloadSessions()`

  Proteus sessions are now loaded from the keystore on demand by the new per-session cache, so there is no longer a need
  to explicitly reload them. Any call sites should simply be deleted.

  Affected platforms: android, ios, web

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

- Allow in-memory database instantiation and usage with core crypto. Just call `Database.inMemory()` (Web),
  `Database.open` without a path (Android, iOS)

- The duplicate signature error when adding members to a conversation now contain debug information about which members
  had duplicate signatures.

### Breaking Changes

- During decryption, core-crypto would automatically replay previously executed but unmerged (i.e., not yet acceped by
  the delivery service) operations. This behavior has changed: the responsibility of replaying any unmerged operations
  is delegated to the consumer.

  Affected platforms: all

- Changed the `MlsTransport` interface. Instead of returning an `MlsTransportResponse` to communicate the reason why a
  message was rejected by the DS, now throw an `MlsTransportError` instead. `MlsTransportResponse` was removed.

  Affected platforms: all

- We aligned key package spelling to KeyPackage

  - renamed `Keypackage` -> `KeyPackage`
  - renamed `KeypackageRef` -> `KeyPackageRef`
  - renamed `generateKeypackage` -> `generateKeyPackage`
  - renamed `getKeypackages` -> `getKeyPackages`
  - renamed `removeKeypackage` -> `removeKeyPackage`
  - renamed `removeKeypackagesFor` -> `removeKeyPackagesFor`

  Affected platforms: all

- We aligned cipher suite spelling to CipherSuite

  - renamed `Ciphersuite` -> `CipherSuite`

  Affected platforms: all

- Removed `WelcomeBundle` type that was returned from `processWelcomeMessage()` and `joinByExternalCommit()`. They
  return a `ConversationId` now only.

  Affected platforms: all

- Typescript: to set the ground for a native module, the browser module is now exported as
  `@wireapp/core-crypto/browser`. Update your imports from `@wireapp/core-crypto` to `@wireapp/core-crypto/browser`.

  Affected platforms: web

- TypeScript: To construct `CoreCrypto`, call the static function `CoreCrypto.new()`.

  Affected platforms: web

- TypeScript: The free functions `openDatabase()` and `inMemoryDatabase()` are no longer exported. Use the static
  methods `Database.open()` and `Database.inMemory()` instead.

  Affected platforms: web

- added `.close()` to `Database` and removed `.close()` from `CoreCrypto`.

  A database should be closed if it is not used anymore. Closing a database makes any `PkiEnvironment` or `CoreCrypto`
  instance unusable and return a `CoreCryptoError.Other`. `CoreCrypto` instances do not need to be closed anymore.

  Affected platforms: web

- Removed previously deprecated field `has_epoch_changed` from `DecryptedMessage`.

  Migration: use the `EpochObserver` interface.

  Affected platforms: all

- Removed `send_message` method from `MlsTransport` interface

  This wasn't well-documented and wasn't being used in any case. We remove it for the purpose of making life easier for
  everyone.

  Affected platforms: all

- Adjusted TypeScript error structure

  Affected platform: web

  Migration: whenever matching on errors using version `>= 9.1.0` type guards, update their usage as shown in the
  examples below.

  For more info, see
  [the corresponding section of ubrn docs](https://jhugman.github.io/uniffi-bindgen-react-native/idioms/errors.html#enums-as-errors).

  ##### Example Usage

  Extract the abort reason given via throwing an `MlsTransportError`

  ```typescript
  import { CoreCryptoError, MlsError } from "core-crypto";

  try {
      // send a commit that is rejected by the DS
  } catch (err) {
    if (CoreCryptoError.Mls.instanceOf(err) &&
        MlsError.MessageRejected.instanceOf(err.inner.mlsError)) {
      const rejectReason = err.inner.mlsError.inner.reason;
      // other things you want to do with this error...
    } else {
        // log error
    }
  }
  ```

  Optional: use `switch` to handle multiple errors in one go.

  ```typescript
  import { CoreCryptoError, MlsError, MlsError_Tags } from "core-crypto";

  try {
      // send a commit that is rejected by the DS
    } catch (err) {
        if (CoreCryptoError.Mls.instanceOf(err)) {
            switch (err.inner.mlsError.tag) {
                case MlsError_Tags.MessageRejected: {
                    const rejectedReason = err.inner.mlsError.inner.reason;
                    // other things you want to do with this error...
                    break;
                }

                // handle other mls errors
            }
        }
    }
  ```

  Catch a proteus error

  ```typescript
  import { CoreCryptoError, ProteusError } from "core-crypto";

  try {
      // look for a proteus session that doesn't exist
  } catch (err) {
    if (CoreCryptoError.Proteus.instanceOf(err)
       && ProteusError.SessionNotFound.instanceOf(err.inner.exception)) {
       let message = err.inner.exception.message;
       // other things you want to do with this error...
    } else {
        // log error
    }
  }
  ```

- `CoreCryptoContext.generateKeyPackage()` now returns a `Keypackage` instance instead of an `Uint8Array`.

  Affected platforms: web

  Migration: if you need the underlying `Uint8Array`, call the `serialize` property on the `KeyPackage`.

- Deferred init is now the only way to instantiate core crypto.

  Affected platforms: all

  Migration: instead of calling `deferredInit()`, call `init()` (TypeScript), or the regular `CoreCrypto` constructor
  (Swift, Kotlin). As before with `deferredInit()`, call `mlsInit()` in a transaction to initialize MLS.

- The core crypto constructor now takes a `Database` instance instead of a `DatabaseKey` and a path. To instantiate,
  call `openDatabase()` (Android, Web) or the `Database` constructor (iOS).

  Affected platforms: all

- `mlsInit()` was decoupled from key package creation.

  Affected platforms: all

  Migration: to create key packages after initializing MLS, call `generateKeypackage()` in a transaction.

- `proteusErrorCode` field was removed from the root error type. Affected platforms: web

  Migration: There is deterministic mapping from error code to error type. If you were using the error code, use the
  error type now instead (see above). Check
  [here](https://github.com/wireapp/proteus/blob/develop/crates/proteus-traits/src/lib.rs) for the mapping.

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

## v9.3.4 - 2026-04-30

### Highlights

Fixes an issue that could cause _epoch observer_ events to be emitted for epoch changes that would not (yet) actually be
persisted to the CoreCrypto database. This is relevant if the CoreCrypto instance is used inside the event handler of
the _epoch observer_ (e.g., to update the exported secret). If you created a CoreCrypto transaction inside the handler
and didn't use the CoreCrypto instance directly, this fix is irrelevant.

## v9.3.3 - 2026-03-31

- no more errors when deleting a non-existent credential

## v9.3.2 - 2026-03-18

- serialize structs into camelCase

## v9.3.1 - 2026-03-18

### Highlights

Fixes an enum representation bug on web.

## v9.3.0 - 2026-02-20

### Highlights

Lidl compat: Ios and Android can now export a compacted version of the CC database, retaining its encryption. This is
only relevant for Lidl builds and should be ignored by everyone else.

## v9.2.1 - 2026-02-17

Upgrades openssl to version 3.5.5 (used on Android and iOS for encryption at rest).

## v9.2.0 - 2026-02-05

### Highlights

- Kotlin: expose the enitre read-only API on the `CoreCrypto` type. This allows performing arbitrary read-only
  operations on data while a transaction is running (e.g., in an `EpochObserver` event).
- Kotlin: Introduce `KotlinInstant` type

## v9.1.3 - 2025-12-18

Upgrades the binding generator (uniffi 0.29.5) to include a crash fix for Android

## v9.1.2 - 2025-11-05

This release fixes a bug in the TypeScript bindings where the commit delay could in some situations be undefined when
receiving a proposal.

## v9.1.1 - 2025-10-24

This release fixes the issue where `libcore_crypto_ffi.so` had segments aligned on 4k instead of 16k on Android
platforms.

## v9.1.0 - 2025-09-29

> [!NOTE]
> Even though this is a minor version bump, it contains a breaking change. See below for more information.

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

## v9.0.1 - 2025-09-18

### Breaking Changes

- v9.0.0 had erroneously renamed `migrateDatabaseKeyTypeToBytes` to `migrateDbKeyTypeToBytes`. This has been fixed, and
  `migrateDatabaseKeyTypeToBytes` is usable again on all platforms.

  Affected platforms: Android

### Bug Fixes

- Kotlin documentation is now correctly generated and deployed.

## v9.0.0 - 2025-09-16

### Highlights

- we're now tying the Kotlin wrapper more closely to the generated bindings which allows for greater velocity when
  making changes in code that affects our API - this causes most of the breaking changes in this release
- removed cryptobox migration API
- in Swift, added protection against concurrent access from multiple core crypto instances
- added implicit obfuscation of sensitive data in logs
- reworked the entire build system and CI

> [!NOTE]
> In this release we include a fix for missing artifacts in our Web release. The faulty release process affects all
> `8.x` versions. Therefore, instead of migrating from any version < `8.x` to `8.x`, directly migrate to this version.

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

## v5.4.0 - 2025-05-14

### Highlights

Kotlin bindings only: transactions are now
[`NonCancellable`](https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines/-non-cancellable/),
as [required by Uniffi](https://mozilla.github.io/uniffi-rs/latest/futures.html#cancelling-async-code). This prevents a
category of bug where Kotlin thinks a transaction has been cancelled, while Rust thinks it is still running.

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

## v4.2.3 - 2025-03-14

- fix android publishing to maven central

## v4.2.2 - 2025-03-14

- fix publishing to maven central

## v4.2.1 - 2025-03-14

- expose `proteusCryptoboxMigrate()` [WPB-16549] (682b9fe)

## v4.2.0 - 2025-02-28

### Highlights

- The Android release once again bundles API docs.
- The Kotlin bindings have received several API fixes in particular:
  - AcmeChallenge was missing the target property.
  - proteusGetPrekeyFingerprint was missing.
- The Typescript bindings now correctly expose WireIdentity and X509Identity.
- The code base has migrated to Rust 2024 edition.

## v4.1.0 - 2025-02-07

### Highlights

- Add the capability to handle the case where a proposal-referencing commit arrives before the proposals it references.

### (Semi-) Breaking changes

- For the case mentioned above, the corresponding error type `BufferedCommit` has been added.
  - Depending on the error model, this can be a breaking change.

## v4.0.1 - 2025-02-05

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
