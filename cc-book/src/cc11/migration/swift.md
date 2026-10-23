# Migrating to CC 11: Swift

See the [common migration guide](../migration-guide.md) for changes that apply to all platforms.

## Database Path and Salt

The database path is no longer required to stay the same across CoreCrypto instances. In previous versions of
CoreCrypto, the database path was used to look up salt values for the database encryption. This is no longer the case,
and the salt values are now stored in a file in the same directory as the CoreCrypto database. For existing clients the
database must be opened once with the old path in order for a migration to be performed.

The salt file is named after the database, with a `.salt` suffix: `<database path>.salt`. The database can't be
decrypted without it, so whenever you move, back up or delete the database, do the same with the salt file.

## Other

1. `CoreCryptoContext.setData` is now a synchronous function, not async.
