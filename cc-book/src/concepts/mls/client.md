# The Client

In MLS terminology a _client_ is a single device acting on behalf of a user — each phone, desktop, or web session that participates in MLS groups is a distinct client with its own identity and key material.
CoreCrypto maps this concept to the `CoreCrypto` object itself.
One `CoreCrypto` instance, backed by one `Database`, represents one MLS client.

> **Note**
>
> The Rust library internally calls this type `Session` to avoid ambiguity — "client" means something different at the Wire application layer (where it refers to a registered device in the Wire backend sense) and at the MLS protocol layer.
> The name `Session` does not appear in platform bindings; from Swift, Kotlin, and TypeScript, the type is always `CoreCrypto`.

## Sharing a CoreCrypto Instance

`CoreCrypto` is cheap to clone.
All internal state — the database connection, the MLS session, the Proteus state — is reference-counted, so cloning the object creates a new handle to the same shared state rather than copying anything.
This means `CoreCrypto` can be freely passed to background tasks or across threads without wrapping it in an additional mutex or reference type.

## Read-Only Operations

Most MLS work happens inside a transaction (see [Transactions and the TransactionContext](transactions.md)), but a handful of read-only operations are available directly on `CoreCrypto` without opening one.
The set of read-only operations available on `CoreCrypto` is intentionally kept narrow.

Any operation that might change state — creating or deleting a conversation, adding members, encrypting or decrypting a message — requires a transaction.

## Lifecycle

A `CoreCrypto` instance is typically created once at application startup and kept alive for the life of the process.
The initialization sequence is:

```typescript
const db = await Database.open(path, key);       // open the keystore
const cc = CoreCrypto.new(db);                   // construct CoreCrypto
await cc.transaction(async (ctx) => {
    await ctx.mlsInit(clientId, transport);      // initialize the MLS session
});
```

After `mlsInit()` is committed, the instance is ready to use.

### Multiple Instances

Only one `CoreCrypto` instance (and its clones) should be active against a given database file at a time.
The iOS client has a file lock which prevents two instances of the CoreCrypto from interfering with each other.
On other clients opening the same database from two independent `CoreCrypto` instances — whether in the same process or different processes — is not supported and will produce undefined behavior.
