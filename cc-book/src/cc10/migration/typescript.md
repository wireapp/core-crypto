# Migrating to CC 10: TypeScript

See the [common migration guide](../migration-guide.md) for changes that apply to all platforms.

## Browser Module Location

We want to prepare the ground for a native module, which runs on node or bun.
Therefore, the browser module is now exported as `@wireapp/core-crypto/browser`.
Update your imports:

```typescript
// before
import { ... } from "@wireapp/core-crypto";

// after
import { ... } from "@wireapp/core-crypto/browser";
```

## CoreCrypto Instantiation

1. The `CoreCrypto` constructor now takes a `Database` instance instead of a `DatabaseKey` and a path. To instantiate a database, call `openDatabase()`.

2. Deferred init is now the only way to instantiate `CoreCrypto`. We **replaced** `CoreCrypto.init(database: Database)` with the static function `CoreCrypto.new(database: Database)`. Instead of calling `CoreCrypto.deferredInit()`, call `CoreCrypto.new()`. As before, call `mlsInit()` in a transaction to initialize MLS.

## Logging

1. We **removed** `CoreCrypto.setLogger(logger: CoreCryptoLogger, level: CoreCryptoLogLevel)` and `CoreCrypto.setMaxLogLevel(level: CoreCryptoLogLevel)`, as logging is configured globally and not tied to a `CoreCrypto` instance. To set the log level, use the free function `setMaxLogLevel(level: CoreCryptoLogLevel)`.

2. We **renamed** `setLoggerOnly(logger: CoreCryptoLogger)` to `setLogger(logger: CoreCryptoLogger)`.

## Passing ByteArray Arguments

We now generate the TypeScript bindings from the same uniffi code that Swift and Kotlin use. Arrays are now passed as `ArrayBuffer` between client and the FFI layer, changing parameter and return types.

- Use `.buffer()` to get an `ArrayBuffer` from a `Uint8Array`.
- Use `new Uint8Array(buffer)` to get a `Uint8Array` from an `ArrayBuffer`.

## Errors

### Error Structure

We adjusted the TypeScript error structure. Whenever matching on errors using version `>= 9.1.0` type guards, update their usage as shown in the examples below.

> **Note**
>
> For more info, see [the corresponding section of the ubrn docs](https://jhugman.github.io/uniffi-bindgen-react-native/idioms/errors.html#enums-as-errors)

**Extracting the abort reason given via throwing an `MlsTransportError`:**

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

**Optional: use `switch` to handle multiple errors in one go:**

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

**Catch a proteus error:**

```typescript
import { CoreCryptoError, ProteusError } from "core-crypto";

try {
    // look for a proteus session that doesn't exist
} catch (err) {
  if (CoreCryptoError.Proteus.instanceOf(err) &&
      ProteusError.SessionNotFound.instanceOf(err.inner.exception)) {
     let message = err.inner.exception.message;
     // other things you want to do with this error...
  } else {
      // log error
  }
}
```

### Proteus Error Codes

The `proteusErrorCode` field was removed from the root error type. There is a deterministic mapping from error code to error type. If you were using the error code, use the error type instead (see above). See [the proteus-traits error table](https://github.com/wireapp/proteus/blob/develop/crates/proteus-traits/src/lib.rs) for the mapping.

## Other

1. `CoreCryptoContext.generateKeyPackage()` now returns a `KeyPackage` instance instead of an `ArrayBuffer`. If you need the underlying `ArrayBuffer`, call the `serialize` property on the `KeyPackage`.

1. `CustomConfiguration.keyRotationSpan` now defines milliseconds instead of seconds.
