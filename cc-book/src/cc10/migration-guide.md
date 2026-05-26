# Migrating from v9.x to v10.0

This page covers breaking changes that are identical across all platforms. For platform-specific migration steps, see
the sub-pages:

- [TypeScript](migration/typescript.md)
- [Swift](migration/swift.md)
- [Kotlin](migration/kotlin.md)

## MLS Initialization

1. `mlsInit()` was decoupled from key package creation. To create key packages after initializing MLS, call
   `CoreCryptoContext.generateKeyPackage()` in a transaction.

1. Removed `CoreCrypto.provideTransport()`, added `transport` parameter to `CoreCryptoContext.mlsInit()`. Instead of
   providing transport separately from MLS initialization, provide it when calling `mlsInit()`.

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

1. We aligned cipher suite spelling to `CipherSuite`:

   - renamed `Ciphersuite` -> `CipherSuite`

## Higher-Level Newtypes

1. `GroupInfo.new()` and `Welcome.new()` are now **fallible** constructors. Previously, both accepted any byte sequence
   unconditionally. They now validate the input as a TLS-encoded MLS structure at construction time and throw if the
   bytes are malformed.

1. We **removed** `GroupInfo.copyBytes()` and `Welcome.copyBytes()`. The underlying types no longer store raw bytes and
   cannot be round-tripped back to a byte array.

1. Added `Welcome::serialize()`. We had test functions which required the serialized bytes given a `Welcome` instance,
   so we added the ability to recreate those bytes.

1. `GroupInfo` and `Welcome` no longer support equality comparisons, hashing, or hex string display in generated
   bindings.

1. `exportSecretKey()` now returns a `SecretKey` object instead of a byte array. To access the raw bytes, call
   `secretKey.copyBytes()`.

1. `createConversation()` now takes a parsed `ExternalSender` object instead of raw bytes. Parse the external sender
   ahead of time with `ExternalSender.parseJwk()` for the JWK form, `ExternalSender.parsePublicKey()` for the legacy raw
   public-key form, or `ExternalSender.parse()` to try both in turn. Parse errors are reported at parse time rather than
   during conversation creation. Call `externalSender.serialize()` to recover the raw bytes when needed.

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

## MlsTransport Interface

Instead of returning an `MlsTransportResponse` to communicate the reason why a message was rejected by the DS, throw an
`MlsTransportError` instead. `MlsTransportResponse` was removed.

## No More Buffering of Unmerged Changes While Decrypting

During decryption, CoreCrypto would previously automatically replay previously executed but unmerged (i.e., not yet
accepted by the delivery service) operations. This behavior has changed: the responsibility of replaying any unmerged
operations is delegated to the consumer.

## Other Changes

1. `CoreCrypto.e2eiIsEnvSetup()` can't throw anymore and will always return a boolean.

1. removed `.proteusFingerprintPrekeybundle()` and `.proteusLastResortPrekeyId()` from `CoreCryptoContext`. Both are
   available as static methods on `CoreCrypto`.

1. removed `CoreCryptoContext.proteusReloadSessions()`. Proteus sessions are now loaded on demand by the new per-session
   cache, so explicit reloads are no longer needed. Delete any call sites.

1. `GroupInfoBundle.payload` now contains a byte array instead of a class instance.
