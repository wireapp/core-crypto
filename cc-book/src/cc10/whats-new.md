# What's New in CC 10

## New APIs

With CC10 we introduce multiple new types that provide their own new API.

### Database API

- `Database.getLocation()` allows getting the location of a persistent database instance. It returns `null` if the database is in-memory.

- **Typescript Only**: Added `Database.close()` and **removed** `CoreCrypto.close()`. A `Database` should be closed if it is not used anymore. Closing a database makes any `PkiEnvironment` or `CoreCrypto` instance unusable. Calls to these instances will return a `CoreCryptoError.Other`. `CoreCrypto` instances do not need to be closed anymore.

### PKI Environment API

- Added `PkiEnvironment` constructed via `createPkiEnvironment(database: Database, hooks: PkiEnvironmentHooks)`
- Added `PkiEnvironmentHooks` interface which has to be implemented by a client and will be used by CoreCrypto during e2ei flow
- Added `CoreCrypto.setPkiEnvironment()` to set a PkiEnvironment on a `CoreCrypto` instance
- Added `CoreCrypto.getPkiEnvironment()` to get the PkiEnvironment of a `CoreCrypto` instance

### Credential API

- `Credential` is a first-class type representing a cryptographic identity.
  - It can be created at any time and lives in memory.
  - There are two variants of credential: basic and x509. Basic credentials are created with `Credential.basic` static method. **TODO DO NOT RELEASE BEFORE REWRITING THIS** X509 credentials are created with `TODO TODO`.
- Initializing an MLS client no longer automatically generates any credentials. Any stored credentials will be automatically loaded on MLS init.
- To add a credential to the set MLS knows about, after initializing MLS, call `addCredential` on a transaction context.
  - This adds it to the working set, and stores it to the database.
  - Due to limitations inherent in the current implementation, credentials added to a client must currently be distinct on the `(credential type / signature scheme / unix timestamp of creation)` tuple.
    - The time resolution is limited to 1 second.
    - If you have need of multiple credentials for a given signature scheme and credential type, just wait 1 full second between adding each of them.
    - We expect this limitation to be relaxed in the future.
  - This also returns a more lightweight `CredentialRef` which can be used elsewhere in the credential API, uniquely referring to a single credential which has already been added to that client.
- `CredentialRef` is a means of uniquely referring to a single credential without transferring the actual credential data back and forth across FFI all the time.
  - Each credential ref is aware of basic information about the credential it references:
    - client id
    - public key
    - credential type
    - signature scheme
    - earliest validity
- To remove a credential from the set MLS knows about, call `removeCredential` on a transaction context, handing it the appropriate `CredentialRef`.
  - Ensures the credential is not currently in use by any conversation.
  - Removes all key packages generated from this credential.
  - Removes the credential from the current working set and also from the keystore.
- Added a new method to transaction context: `getCredentials`, which produces a `CredentialRef` for each credential known by this client.
- Added a new method to transaction context: `findCredentials`, which produces a `CredentialRef` for each credential known by this client, efficiently filtering them by the specified criteria.

> **Note**
>
> CC v10.0 introduces lots of changes.
> We provide a [migration guide](migration-guide.md).
