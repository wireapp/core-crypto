# Migrating to CC 12: TypeScript

See the [common migration guide](../migration-guide.md) for changes that apply to all platforms.

## CoreCrypto Runs in a Worker (Browser)

The native package, `@wireapp/core-crypto-native`, is not affected by anything in this section.

### Serving the worker

`initWasmModule()` compiles the wasm module and starts the worker from `worker.js`, which ships next to `corecrypto.js`
in the package. If your bundler understands `new URL("./worker.js", import.meta.url)`, it picks the file up on its own.
Otherwise, make sure `worker.js` is served from the same directory as `corecrypto.js`.

### Every call is async

Each call into CoreCrypto is now a message to the worker, so every call returns a promise. This includes calls that used
to be synchronous, such as constructors, methods on FFI objects and module-level functions:

```typescript
// before
const clientId = new ClientId(new Uuid(userId), DeviceId.fromHexString(deviceId), "wire.com");
const cc = CoreCrypto.new(database);
const bytes = keyPackage.serialize();

// after
const clientId = await ClientId.create(await Uuid.create(userId), await DeviceId.fromHexString(deviceId), "wire.com");
const cc = await CoreCrypto.new(database);
const bytes = await keyPackage.serialize();
```

Constructors became static `create` methods, because a JavaScript constructor can't return a promise. For the same
reason, types that implement `toString` now provide `asyncToString` instead. `toString` itself falls back to
JavaScript's default, so string interpolation of these types no longer gives a useful result.

If you share code between the browser and the native package, it's fine to `await` everywhere. Awaiting a value that
isn't a promise just returns the value.

### Logging

`CoreCryptoLogger.log` is still a synchronous function, but each log message is now sent from the worker to the page,
and CoreCrypto doesn't wait for your logger to handle it. Two things follow from that:

- If your logger throws, CoreCrypto can't report the error back to you. It only shows up in the console.
- A log message can arrive after the call that produced it has returned. Code that inspects logs straight after awaiting
  a call, for example in tests, may need to wait for them.
