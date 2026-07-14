# Migrating from v10.0 to Unreleased

> [!NOTE]
> These changes will be relevant with the next release of CoreCrypto.

## Database

1. Deprecated the `key` parameter from in-memory Database constructor. In-memory databases are never encrypted.

1. `Database.getLocation` now returns the absolute path to the database file for non-web platforms.
