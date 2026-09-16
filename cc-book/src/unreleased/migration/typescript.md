# Migrating to Unreleased: TypeScript

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
the object. If you need to explicitly close the database, you can call `uniffiDestroy()` on the `Database` instance.
