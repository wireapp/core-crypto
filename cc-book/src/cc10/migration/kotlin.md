# Migrating to CC 10: Kotlin

See the [common migration guide](../migration-guide.md) for changes that apply to all platforms.

## Renames and Moves

1. `CoreCryptoClient` has been renamed to `CoreCrypto`.

1. `historyClient(historySecret: HistorySecret)` has been moved into `CoreCrypto` Companion functions.

## CoreCrypto Instantiation

1. The `CoreCrypto` constructor now takes a `Database` instance instead of a `DatabaseKey` and a path. To instantiate a
   database, call the `Database.open()` static method.

1. Deferred init is now the only way to instantiate `CoreCrypto`. Instead of calling `deferredInit()`, call the
   `CoreCrypto` constructor. As before, call `mlsInit()` in a transaction to initialize MLS.

## Higher-Level Newtypes

`CoreCryptoContext.getExternalSender()` now returns an `ExternalSenderKey` object instead of a byte array. To access the
raw bytes, call `externalSenderKey.copyBytes()`.

## Logging

1. We **removed** `level` parameter from `setLogger(logger: CoreCryptoLogger, level: CoreCryptoLogLevel)`. To set the
   log level, use the free function `setMaxLogLevel(level: CoreCryptoLogLevel)`.
1. We **removed** `setLoggerOnly`.

## Other

1. Removed `CoreCryptoFfi.reseedRng()` and `CoreCryptoFfi.randomBytes()`.
