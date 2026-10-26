# The Database

The `Database` is CoreCrypto's keystore: the persistent store for all key material and cryptographic state, as well as
some non-cryptographic internal data. It is opened before constructing a `CoreCrypto` instance and passed in as an
argument, making the storage layer an explicit dependency rather than something CoreCrypto manages internally.

## What the Database Stores

The database holds all state that must survive process restarts:

- **MLS group state** — the serialized ratchet tree and secrets for every conversation the device participates in
- **Credentials and key packages** — the device's identity material and the key packages it has published to the
  delivery service
- **Pending messages** — application messages and commits that arrived during an epoch transition and are waiting to be
  merged
- **Proteus identity and sessions** — the device's long-lived Proteus identity keypair and the state of every active
  Proteus session
- **Proteus prekeys** — including the last-resort prekey
- **Data needed for X509 credentials** — X509 trust anchors, intermediate and leaf certificates, CRLs and the like

All entries are encrypted at rest using the `DatabaseKey` provided at open time.

## Backing Storage

The database is backed by [SQLCipher](https://www.zetetic.net/sqlcipher/), an encrypted SQLite variant. In the browser,
the database file is stored in OPFS. Data is encrypted at rest.

## The Database Key

The `DatabaseKey` is a 32-byte symmetric key used to encrypt all data at rest. Construct it from a byte array:

<!-- langtabs-start -->

```typescript
const key = DatabaseKey.new(bytes)  // bytes must be exactly 32 bytes
```

```swift
let key = DatabaseKey(bytes: bytes)  // bytes must be exactly 32 bytes
```

```kotlin
val key = DatabaseKey(bytes)  // bytes must be exactly 32 bytes
```

<!-- langtabs-end -->

CoreCrypto does not generate or store the key — that is entirely the client's responsibility. The key should be kept in
the platform's secure credential storage.

> [!NOTE]
> The database key is never written to disk by CoreCrypto. If the key is lost, the database contents are unrecoverable.

## Opening the Database

All platforms define an async `Database.open` static method accepting a location and key. On platforms with an OS, the
location is a filesystem path. On WASM, the location is the name of the database file in OPFS.

All platforms can also open a transient database in memory. In-memory databases are never encrypted, so they take no
key. In TypeScript, this is `Database.inMemory()`. For Kotlin and Swift, this is an overload of `Database.open` without
arguments.

## Key Rotation

The database can be re-encrypted with a new key without closing and reopening it:

<!-- langtabs-start -->

```typescript
await db.updateKey(newKey)
```

```swift
try await db.updateKey(key: newKey)
```

```kotlin
db.updateKey(newKey)
```

<!-- langtabs-end -->

This re-encrypts all stored data in place.

## Single-Transaction Constraint

Only one transaction may write to the database at a time. If a transaction is requested while another transaction is in
flight, the call will block until the first transaction concludes.

For more detail, see [Transactions → Concurrency](transactions.md#concurrency).

## Exporting a Copy

On native platforms, a fully vacuumed copy of the database can be written to a new file:

<!-- langtabs-start -->

```swift
try await exportDatabaseCopy(database: db, destinationPath: destinationPath)
```

```kotlin
exportDatabaseCopy(db, destinationPath)
```

<!-- langtabs-end -->

The copy is encrypted with the same key as the source. This is useful for backup or for migrating the database to a new
location. This function is not available on browser platforms.
