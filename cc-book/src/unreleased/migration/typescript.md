# Migrating to Unreleased: TypeScript

See the [common migration guide](../migration-guide.md) for changes that apply to all platforms.

## Database

Deprecated `Database.close()`. Database references are now automatically destroyed when the garbage collector cleans up
the object. If you need to explicitly close the database, you can call `uniffiDestroy()` on the `Database` instance.
