# Migrating to CC 11: TypeScript

See the [common migration guide](../migration-guide.md) for changes that apply to all platforms.

## Browser and Native Packages

Browser bindings are published as `@wireapp/core-crypto`. The `@wireapp/core-crypto/browser` import remains available as
an alias. Native bindings are published separately as `@wireapp/core-crypto-native`, which automatically installs its
`@ubjs/core` and `@ubjs/node` runtime dependencies.

If you previously used the native subpath, install `@wireapp/core-crypto-native` and update your imports:

```typescript
// before
import { ... } from "@wireapp/core-crypto/native";

// after
import { ... } from "@wireapp/core-crypto-native";
```

## Database

Deprecated `Database.close()`. Database references are now automatically destroyed when the garbage collector cleans up
the object. If you need to explicitly close the database, you can call `uniffiDestroy()` on the `Database` instance and
any object holding a reference to that database, notably `CoreCrypto` and `PkiEnvironment` instances.

The database is stored in OPFS. Its `location` parameter is a relative path within the `core-crypto` directory in the
OPFS filesystem. If the `location` has more components than the filename, then deleting the parent directory within OPFS
will clean up the database and all ancillary files. Note: this operation is only legal once the database has been
destroyed.

`Database.inMemory()` is now a synchronous function, not async.

## Reseed (Browser)

`CoreCrypto.reseed` now requires exactly 32 bytes. Callers that pass a longer seed will now get an error.
