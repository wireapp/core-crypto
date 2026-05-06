# Migrating from v9.x to v10.0

This page covers breaking changes that are identical across all platforms. For platform-specific migration steps, see
the sub-pages:

- [TypeScript](migration/typescript.md)
- [Swift](migration/swift.md)
- [Kotlin](migration/kotlin.md)

## MLS Initialization

1. `mlsInit()` was decoupled from key package creation. To create key packages after initializing MLS, call
   `CoreCryptoContext.generateKeyPackage()` in a transaction.

1. Removed `CoreCrypto.provideTransport()`, added `transport` parameter to `CoreCryptoContext.mlsInit()`. Instead of
   providing transport separately from MLS initialization, provide it when calling `mlsInit()`.

## Key Packages

1. We **removed** `CoreCryptoContext.clientKeypackages()`. To generate a desired amount of key packages, make repeated
   calls to `CoreCryptoContext.generateKeyPackage()`.

1. We **removed** `CoreCryptoContext.clientValidKeypackagesCount()`. To count remaining key packages, call
   `CoreCryptoContext.getKeyPackages()`, filter the results as desired, and count the remaining items.

1. We aligned key package spelling to `KeyPackage`:

   - renamed `Keypackage` → `KeyPackage`
   - renamed `KeypackageRef` → `KeyPackageRef`
   - renamed `generateKeypackage` → `generateKeyPackage`
   - renamed `getKeypackages` → `getKeyPackages`
   - renamed `removeKeypackage` → `removeKeyPackage`
   - renamed `removeKeypackagesFor` → `removeKeyPackagesFor`

1. We aligned cipher suite spelling to `CipherSuite`:

   - renamed `Ciphersuite` -> `CipherSuite`

## Higher-Level Newtypes

1. `GroupInfo.new()` and `Welcome.new()` are now **fallible** constructors. Previously, both accepted any byte sequence
   unconditionally. They now validate the input as a TLS-encoded MLS structure at construction time and throw if the
   bytes are malformed.

1. We **removed** `GroupInfo.copyBytes()` and `Welcome.copyBytes()`. The underlying types no longer store raw bytes and
   cannot be round-tripped back to a byte array.

1. Added `Welcome::serialize()`. We had test functions which required the serialized bytes given a `Welcome` instance,
   so we added the ability to recreate those bytes.

1. `GroupInfo` and `Welcome` no longer support equality comparisons, hashing, or hex string display in generated
   bindings.

1. `exportSecretKey()` now returns a `SecretKey` object instead of a byte array. To access the raw bytes, call
   `secretKey.copyBytes()`.

## MlsTransport Interface

Instead of returning an `MlsTransportResponse` to communicate the reason why a message was rejected by the DS, throw an
`MlsTransportError` instead. `MlsTransportResponse` was removed.

## No More Buffering of Unmerged Changes While Decrypting

During decryption, CoreCrypto would previously automatically replay previously executed but unmerged (i.e., not yet
accepted by the delivery service) operations. This behavior has changed: the responsibility of replaying any unmerged
operations is delegated to the consumer.

## Other Changes

1. `CoreCrypto.e2eiIsEnvSetup()` can't throw anymore and will always return a boolean.

1. removed `.proteusFingerprintPrekeybundle()` and `.proteusLastResortPrekeyId()` from `CoreCryptoContext`. Both are
   available as static methods on `CoreCrypto`.
