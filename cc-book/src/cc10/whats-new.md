# What's New in CC 10

## New APIs

With CC10 we introduce multiple new types that provide their own new API.

### Database API

- `Database.getLocation()` allows getting the location of a persistent database instance. It returns `null` if the
  database is in-memory.

- added `Database.open(location: String, key: DatabaseKey)` as a static method to construct a persistent database
  instance, and `Database.open(key: DatabaseKey)` / `Database.inMemory(key: DatabaseKey)` to construct an in-memory
  database instance.

- **Typescript Only**: Added `Database.close()` and **removed** `CoreCrypto.close()`. A `Database` should be closed if
  it is not used anymore. Closing a database makes any `PkiEnvironment` or `CoreCrypto` instance unusable. Calls to
  these instances will return a `CoreCryptoError.Other`. `CoreCrypto` instances do not need to be closed anymore.

- It is now safer to close a `Database`: instead of depending on a unique reference to the instance, it will just
  invalidate all other references to that instance.

### PKI Environment API

- Added `PkiEnvironment` constructed via
  - `PkiEnvironment(database: Database, hooks: PkiEnvironmentHooks)` (swift)
  - `PkiEnvironment.new(database: Database, hooks: PkiEnvironmentHooks)` (kotlin)
  - `PkiEnvironment.create(database: Database, hooks: PkiEnvironmentHooks)` (ts)
- Added `PkiEnvironmentHooks` interface which has to be implemented by a client and will be used by CoreCrypto during
  e2ei flow
- Added `CoreCrypto.setPkiEnvironment()` to set a PkiEnvironment on a `CoreCrypto` instance
- Added `CoreCrypto.getPkiEnvironment()` to get the PkiEnvironment of a `CoreCrypto` instance

### Credential API

`Credential` is now a first-class type representing a cryptographic identity. A credential can be created at any time,
lives in memory, and is independent of any client instance or storage. There are two variants: basic credentials,
created with the `Credential.basic` static method, and X509 credentials, obtained through the acquisition flow described
in the [X509 Credential Acquisition](migration-guide.md#x509-credential-acquisition) section of the migration guide.

Initializing an MLS client no longer automatically generates any credentials; instead, any previously stored credentials
are loaded automatically on MLS init. To put a freshly created credential to use, register it with `addCredential` on a
transaction context, which stores it and adds it to the working set. This explicit model is considerably more flexible
than before: rather than CoreCrypto implicitly selecting the most recent credential of a given type and cipher suite,
clients now choose exactly which credential each operation should use.

Registering a credential returns a `CredentialRef`: a compact, stable handle that uniquely identifies a single stored
credential without shuttling the full credential data back and forth across the FFI boundary. A `CredentialRef` carries
basic metadata about the credential it points to — client id, credential type, signature scheme, cipher suite, earliest
validity, and the hash of its public key — and is the value you pass throughout the rest of the credential API.

Two transaction-context methods recover these references for credentials already known to a client: `getCredentials`
returns a `CredentialRef` for every credential, and `findCredentials` does the same while efficiently filtering by
criteria you specify. To delete a credential, pass its `CredentialRef` to `removeCredential`; this verifies the
credential is not in use by any conversation, removes every key package derived from it, and deletes it from both the
working set and the keystore.

> [!NOTE]
> CC v10.0 introduces lots of changes. We provide a [migration guide](migration-guide.md).

## New Platform: TS Native

With CC 10 we are expanding the set of supported bindings. In addition to the existing browser bindings--now published
as `@wireapp/core-crypto/browser`--we are also publishing bindings for Node and other native platforms, as
`@wireapp/core-crypto/native`.

These new bindings are conceptually more similar to [KMP](https://kotlinlang.org/multiplatform/) than to the browser
bindings: under the hood, they are not compiled to WASM at all. Instead, they call directly into a `.so` or `.dylib`
library according to the relevant system.

> [!NOTE]
> We do not currently provide a `.dll` with which it would be possible to run the TS Native bindings on Windows.

While the mechanics of the library's implementation are different, the actual API will be very familiar; we've
intentionally minimized the differences between the native and browser implementations.

### Removing non-browser WASM support

In 9.x it was possible to instantiate WASM clients in a node-like runtime, though without persistence. With the addition
of the TS Native bindings, this is no longer supported. The TS Native bindings enable fully-persistent usage patterns
outside the browser and should replace all usage of the WASM bindings outside the browser.
