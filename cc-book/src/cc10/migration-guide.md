# Migrating from v9.x to v10.0

This page covers breaking changes that are identical across all platforms. For platform-specific migration steps, see
the sub-pages:

- [TypeScript](migration/typescript.md)
- [Swift](migration/swift.md)
- [Kotlin](migration/kotlin.md)

## Credentials

CC10 introduces first-class `Credential` and `CredentialRef` types. Previously, credentials were implicit: `mlsInit()`
created a basic credential for each cipher suite automatically, and every operation that needed a credential selected
one by taking a `(cipherSuite, credentialType)` pair. In CC10 you construct credentials explicitly and refer to them by
`CredentialRef`. The `(cipherSuite, credentialType)` selector has been removed from every call site.

This makes credential operations much more flexible: whereas in the past CC would always implicitly choose the most
recent credential of a given type and cipher suite, clients can simply choose the appropriate credential.

### Creating and registering credentials

1. `mlsInit()` no longer creates any credential or key packages. After initializing MLS, create at least one credential
   yourself. See also [MLS Initialization](#mls-initialization) and [Key Packages](#key-packages).

1. Create a basic credential with the `Credential.basic(cipherSuite, clientId)` static method. To obtain an X509
   credential, use the acquisition flow described in [X509 Credential Acquisition](#x509-credential-acquisition). A
   `Credential` lives in memory and is independent of any client instance.

1. Register the credential with `transactionContext.addCredential(credential)`. This persists it and returns a
   `CredentialRef`: a compact, stable handle you pass to the rest of the API in place of the old selector pair.

   - Credentials registered with a single client must be distinct on the
     `(credentialType, signatureScheme, creation timestamp)` tuple, where the timestamp has one-second resolution. If
     you need several credentials sharing a type and signature scheme, wait one full second between registering each. We
     expect to relax this limitation in the future.

1. On MLS initialization, previously stored credentials are loaded automatically. Enumerate them with
   `getCredentials()`, or filter with `findCredentials(...)`, to recover their `CredentialRef`s.

### Passing credentials to operations

Replace the old `(cipherSuite, credentialType)` arguments with a `CredentialRef`:

| Operation                          | v9.x                                                      | v10.0                                                      |
| ---------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------- |
| Create a conversation              | `createConversation(id, creatorCredentialType, config)`   | `createConversation(id, credentialRef, externalSender?)`   |
| Join by external commit            | `joinByExternalCommit(groupInfo, config, credentialType)` | `joinByExternalCommit(groupInfo, credentialRef)`           |
| Generate key packages              | `clientKeypackages(cipherSuite, credentialType, amount)`  | repeated `generateKeyPackage(credentialRef)`               |
| Switch a conversation's credential | `e2eiRotate(conversationId)`                              | `setConversationCredential(conversationId, credentialRef)` |

A conversation's cipher suite is now derived from its credential, so `createConversation()` no longer accepts a separate
cipher suite.

To remove a credential, call `removeCredential(credentialRef)`. This checks that the credential is not in use by any
conversation, removes every key package derived from it, and deletes it from both the working set and the keystore.

### Public keys

A `Credential` carries a public key but exposes no method to export it. To read the public key, register the credential
with `addCredential` to obtain a `CredentialRef`, then call `coreCrypto.publicKey(credentialRef)` returns the raw public
key bytes. This replaces v9.x's `clientPublicKey(cipherSuite, credentialType)`.

There also exist other helpers to work with public keys:

- `credentialRef.publicKeyHash()` returns the SHA256 hash of the public key.
- `coreCrypto.exportCredentialPem(credentialRef)` serializes the public key of a credential into PEM format

## X509 Credential Acquisition

The enrollment API that previously drove the ACME and OIDC exchanges step-by-step from the client has been **removed**.
The whole ACME / DPoP / OIDC sequence is now hidden behind a single object, `X509CredentialAcquisition`, which the
client constructs once and then calls `finalize()` on to obtain a `Credential`. CoreCrypto reaches back into the client
only via well-defined hook points; the client no longer threads nonces, account responses, order requests, or challenge
payloads through its own code.

Where you previously called `e2eiNewEnrollment`, `e2eiNewActivationEnrollment`, `e2eiNewRotateEnrollment`,
`directoryResponse`, `newAccountRequest`/`Response`, `newOrderRequest`/`Response`, `newAuthzRequest`/`Response`,
`createDpopToken`, `newDpopChallengeRequest`/`Response`, `newOidcChallengeRequest`/`Response`,
`checkOrderRequest`/`Response`, `finalizeRequest`/`Response`, or `certificateRequest` — delete all of it. The new flow
replaces every one of those calls.

### Acquiring an X509 credential

1. **Implement `PkiEnvironmentHooks`**. CoreCrypto will call these hooks during acquisition:

   - `httpRequest` — perform HTTP requests against the ACME server, CRL distributors, and similar.
   - `authenticate` — drive the IdP authorization code flow with PKCE and return the resulting ID token.
   - `getBackendNonce` — obtain a nonce from the Wire backend.
   - `fetchBackendAccessToken` — exchange the DPoP token for a backend access token.

1. **Create a `PkiEnvironment`** with `PkiEnvironment.new(hooks, database)` (TypeScript) or
   `createPkiEnvironment(hooks, database)` (Swift/Kotlin). The `Database` can be the same used by the `CoreCrypto`
   instance or distinct; they use unrelated tables. That said, it is typically more convenient to use a single database.

1. **Build an `X509CredentialAcquisitionConfiguration`** describing the certificate you want:

   - `acmeUrl` - the URL of the ACME server
   - `cipher_suite` — must be one of the four with a JWS-compatible signature scheme: Ed25519, P256, P384, or P521.
     Other cipher suites will fail at construction.
   - `displayName`, `clientId`, `handle`, `domain`, optional `team`
   - `validityPeriodSecs`

1. **Construct the acquisition**: `X509CredentialAcquisition.new(pkiEnvironment, configuration)`.

1. **Call `await acquisition.finalize()`**. This drives the DPoP and OIDC challenges to completion, calling your hooks
   as needed, and returns the acquired `Credential`. The acquisition can only be finalized once; a second call throws.

1. **Attach the credential** to the client with `transactionContext.addCredential(credential)`, exactly as for a basic
   credential. This persists it to the internal database and returns a `CredentialRef`.

### Pausing across the IdP redirect

The IdP authentication flow typically requires an external redirect, after which the app may have been suspended,
backgrounded, or restarted. To support this, the `authenticate` hook receives an `acquisitionSnapshot: bytes` parameter
capturing the acquisition state at the point the DPoP challenge has completed and OIDC is about to begin. Persist these
bytes to encrypted storage before launching the IdP flow.

When the app resumes and is ready to complete acquisition, reconstruct the acquisition from the snapshot with
`X509CredentialAcquisition.fromBytes(pkiEnvironment, snapshot)` and call `finalize()` on the reconstructed instance.
There is no client-visible serialization method on `X509CredentialAcquisition` itself; the snapshot bytes are delivered
to you exclusively through the `authenticate` hook's `acquisitionSnapshot` parameter.

### Checking for expiration and revocation

Call `checkCredentials` at least once every 24 hours to check all X509 credentials for expiration and revocation. It is
recommended to do this during an idle period, because HTTP requests are done to fetch new certificate revocation lists.

## Key Packages

1. We **removed** `CoreCryptoContext.clientKeypackages()`. To generate a desired amount of key packages, make repeated
   calls to `CoreCryptoContext.generateKeyPackage()`.

1. We **removed** `CoreCryptoContext.clientValidKeypackagesCount()`. To count remaining key packages, call
   `CoreCryptoContext.getKeyPackages()`, filter the results as desired, and count the remaining items.

1. We aligned key package spelling to `KeyPackage`:

   - renamed `Keypackage` → `KeyPackage`
   - renamed `KeypackageRef` → `KeyPackageRef`
   - renamed `generateKeypackage` → `generateKeyPackage`
   - renamed `getKeypackages` → `getKeyPackages`
   - renamed `removeKeypackage` → `removeKeyPackage`
   - renamed `removeKeypackagesFor` → `removeKeyPackagesFor`

## MLS Initialization

1. `mlsInit()` was decoupled from key package creation. To create key packages after initializing MLS, call
   `CoreCryptoContext.generateKeyPackage()` in a transaction.

1. Removed `CoreCrypto.provideTransport()`, added `transport` parameter to `CoreCryptoContext.mlsInit()`. Instead of
   providing transport separately from MLS initialization, provide it when calling `mlsInit()`.

## Validated Input Types

In several instances we have replaced parameters which used to be parsed at call time with exported types which are
parsed at instantiation. This simplifies error propagation, because clients now receive parse errors directly at
instantiation. It also simplifies call sites, because they can no longer return parse errors.

1. `GroupInfo.new()` and `Welcome.new()` are now **fallible** constructors. Previously, both accepted any byte sequence
   unconditionally. They now validate the input as a TLS-encoded MLS structure at construction time and throw if the
   bytes are malformed.

1. We **removed** `GroupInfo.copyBytes()` and `Welcome.copyBytes()`. The underlying types no longer store raw bytes and
   cannot be round-tripped back to a byte array.

1. Added `Welcome.serialize()`, which recovers the TLS-serialized bytes (replacing the removed `copyBytes()`). It is
   fallible and throws if serialization fails.

1. `GroupInfo` and `Welcome` no longer support equality comparisons, hashing, or hex string display in generated
   bindings.

1. `createConversation()` now takes a single optional, parsed `ExternalSender` object instead of a list of raw
   external-sender byte arrays carried on the conversation configuration. Parse the external sender ahead of time with:

   - `ExternalSender.parseJwk(jwk)` for the JWK form,
   - `ExternalSender.parsePublicKey(key, signatureScheme)` for the legacy raw public-key form, or
   - `ExternalSender.parse(key, signatureScheme)` to try the JWK form first and fall back to the raw public-key form.

   Parse errors are reported at parse time rather than during conversation creation. Call `externalSender.serialize()`
   to recover the raw public-key bytes; these match the `parsePublicKey` form and the `ExternalSenderKey` returned by
   `getExternalSender()`. Note that `ExternalSender` (the parsed input type) is distinct from `ExternalSenderKey` (the
   raw key type that `getExternalSender()` returns).

## No More Buffering of Unmerged Changes While Decrypting

During decryption, CoreCrypto would previously automatically replay previously executed but unmerged (i.e., not yet
accepted by the delivery service) operations. This behavior has changed: the responsibility of replaying any unmerged
operations is delegated to the consumer.

## MlsTransport Interface

1. Instead of returning an `MlsTransportResponse` to communicate the reason why a message was rejected by the DS, throw
   an `MlsTransportError` instead. `MlsTransportResponse` was removed.

1. Removed `sendMessage` method from `MlsTransport` interface. This wasn't well-documented and wasn't being used in any
   case. We remove it for the purpose of making life easier for everyone.

## Renaming "Ciphersuite" to "Cipher Suite"

We aligned cipher suite spelling to `CipherSuite`:

- renamed `Ciphersuite` → `CipherSuite`
- renamed `ciphersuiteFromU16` → `cipherSuiteFromU16`
- renamed `ciphersuiteDefault` → `cipherSuiteDefault`
- renamed `conversationCiphersuite` → `conversationCipherSuite`
- renamed any parameters and fields `ciphersuite` → `cipherSuite`

## Client ID initialization

Previously, initialization was done via `ClientId.new(bytes)`, where bytes was a string of a specific format with a user
id, device id, and domain. The new constructor takes care of this for you and ensures all client ids conform to this
fomat: `ClientId.new(userId, deviceId, domain)`. `userId` must be an instance of the newly added type `Uuid`, and
`deviceId` a `DeviceId`.

## Other Changes

1. `CoreCrypto.e2eiIsEnvSetup()` can't throw anymore and will always return a boolean.

1. removed `.proteusFingerprintPrekeybundle()` and `.proteusLastResortPrekeyId()` from `CoreCryptoContext`. Both are
   available as static methods on `CoreCrypto`.

1. removed `CoreCryptoContext.proteusReloadSessions()`. Proteus sessions are now loaded on demand by the new per-session
   cache, so explicit reloads are no longer needed. Delete any call sites.

1. `GroupInfoBundle.payload` now contains a byte array instead of a class instance.

1. The `updateDatabaseKey` function has been moved; it is now a static method `Database.updateKey`.

1. removed `CoreCryptoContext.markConversationAsChildOf()`. No client should actually be using this function and all
   existing references to it should be removed.

1. The duplicate signature error when adding members to a conversation now contain debug information about which members
   had duplicate signatures.

1. Removed `WelcomeBundle` type that was returned from `processWelcomeMessage()` and `joinByExternalCommit()`. They
   return a `ConversationId` now only.

1. Removed previously deprecated field `hasEpochChanged` from `DecryptedMessage`. Use the `EpochObserver` interface.
