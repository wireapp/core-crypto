# Migrating to CC 10: Swift

See the [common migration guide](../migration-guide.md) for changes that apply to all platforms.

## CoreCrypto Instantiation

1. The `CoreCrypto` constructor now takes a `Database` instance instead of a `DatabaseKey` and a path. To instantiate a database, call the `Database.new()` static method.

2. Deferred init is now the only way to instantiate `CoreCrypto`. Instead of calling `deferredInit()`, call the `CoreCrypto` constructor. As before, call `mlsInit()` in a transaction to initialize MLS.

## Higher-Level Newtypes

`CoreCryptoContext.getExternalSender()` now returns an `ExternalSenderKey` object instead of a byte array. To access the raw bytes, call `externalSenderKey.copyBytes()`.

## Logging

1. We **removed** `CoreCrypto.setLogger(logger: CoreCryptoLogger, level: CoreCryptoLogLevel)` and `CoreCrypto.setMaxLogLevel(level: CoreCryptoLogLevel)`, as logging is configured globally and not tied to a `CoreCrypto` instance. To set the log level, use the free function `setMaxLogLevel(level: CoreCryptoLogLevel)`.

2. We **renamed** `setLoggerOnly(logger: CoreCryptoLogger)` to `setLogger(logger: CoreCryptoLogger)`.

## Other

1. Removed `CoreCryptoFfi.reseedRng()` and `CoreCryptoFfi.randomBytes()`.

2. Removed the following static methods from `CoreCrypto` that were globally available:
   - `version()`
   - `buildMetadata()`
