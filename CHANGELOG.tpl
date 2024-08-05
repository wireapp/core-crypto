# Changelog

Platform support legends:

* ✅ = tier 1 support. Things just work.
* ⚠️ = tier 2 support. Things compile but *might* not work as expected. Basically works but with papercuts
    * Note: the papercuts will majorly be with the build process. Things might be very rough to integrate as no polish at all has been given yet.
* ❌ = tier 3 support. It doesn't work just yet, but we plan to make it work.

## [1.0.1] - 2024-08-05

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.1" unreleased=true}}
</details>

* Fixed handling of own commits.
* Enabled dependency locking for reproducible builds.
* Fixed some cases where basic key packages were still returned after enabling E2EI.

## [1.0.0] - 2024-07-18

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0"}}
</details>

* Improved internal crate documentation.
* Added logging facilites for client usage.
* Removed experimental support for Kyber-based KEM.
* Updated uniffi to 0.28, fixing the enum breakage in previous release candidates.
* Various dependency updates and cleanups.

## [1.0.0-rc.60] - 2024-05-06

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.60"}}
</details>

* Fixed an issue on WASM using `createConversation()` with external senders, as the ciphersuite was ignored in parsing External Senders

## [1.0.0-rc.59] - 2024-05-02

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.59"}}
</details>

* Fixed the support of External Senders as the legacy format (raw encoded public keys) for ECDSA-based ciphersuites

## [1.0.0-rc.58] - 2024-04-30

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.58"}}
</details>

* **[BREAKING]** The `deferred_init` following parameters have been removed: `ciphersuite`, `nb_key_packages`.
    * Those parameters were unused anyway so this aims to remove some API cruft.
* Fixed a crash on x86_64 Android
* Android & iOS FFI: Fixed a deadlock in `conversation_create` due to a reentrancy

## [1.0.0-rc.57] - 2024-04-25

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.57"}}
</details>

* **[BREAKING]** The Kotlin and iOS FFI have been updated to use UniFFI 0.27
    * The callback ABI has changed and now all callbacks are `async`/`suspend` to support Async IO workflows.
    * `core_crypto_new()` and `core_crypto_deferred_init()` are now soft-deprecated in favor of an async constructor for the `CoreCrypto` class.
    * There is a slew of other changes in how enums are represented across the FFI
* **[BREAKING]** The TypeScript wrapper now represents enums as their `number` discriminant instead of their `string` representation

## [1.0.0-rc.56] - 2024-04-22

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.56"}}
</details>

* Added full support for NIST-P curves ciphersuites
* Added support for setting MLS ExternalSenders as a JWK

## [1.0.0-rc.55] - 2024-03-28

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.55"}}
</details>

* Introduce `e2ei_verify_group_state()` to preemptively check a group state through its GroupInfo before joining it
* WireIdentity (returned by `getUserIdentities()` & `getDeviceIdentities()`) now also works for Basic credentials. The struct has changed to reflect that ; the X509 related part being moved in a dedicated field
* MLS thumbprint returned by WireIdentity is consistent between X509 & Basic credentials
* Fixed: E2EI enrollment double free on iOS
* Fixed: MLS thumbprint has hash algorithm agility

## [1.0.0-rc.54] - 2024-03-20

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.54"}}
</details>

* Fixed `new_crl_distribution_points` not being deduplicated vs what we have in-store for `add_members_to_conversation`

## [1.0.0-rc.53] - 2024-03-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.53"}}
</details>

* Fixed expired certificates in credentials being verified in MLS

## [1.0.0-rc.52] - 2024-03-14

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.52"}}
</details>

* Fixed the handling of newly seen CRL Distribution Points (`new_crl_distribution_points` field in the relevant structs)
    * The implementation until now had a reversed filter in place, meaning we would *only* return what has already been registered. We want the opposite to happen; Unseen CRL DPs to be forwarded to the consumer.
    * Also fixes the extraction of DPs in External Commits, Self-Commits (in the eventuality of received proposals) and Welcomes

## [1.0.0-rc.51] - 2024-03-13

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.51"}}
</details>

* Fixed the CRL revocation cache that was causing X.509 credentials to be considered valid on 2nd verifications
* Preemptively fixed an issue where an outdated PKI env `time_of_interest` could cause false-negatives in certificate verifications
* **BREAKING FIX**: The TypeScript wrapper now returns enum members for `E2eiConversationState` and `DeviceStatus` values instead of ints.

## [1.0.0-rc.50] - 2024-03-11

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.50"}}
</details>

* Fixed CRL-based revocation handling in some rare cases that were encountered during testing

## [1.0.0-rc.49] - 2024-03-11

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.49"}}
</details>

* We now emit an `OrphanWelcome` error if a LeafNode's HPKE private key is missing from the store
* Web only: Dropped the unique index on MLS Signature Keys' public keys. This should prevent weird issues with x509 vs basic credential handling

## [1.0.0-rc.48] - 2024-03-07

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.48"}}
</details>

* Fix revocation (URIs were not supported when parsing CrlInfo)
* Deduplicate CRL DistributionPoints

## [1.0.0-rc.47] - 2024-03-04

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.47"}}
</details>

* Actually check revocation status instead of mocking it
* Fixed creating an empty PKI env on restore which will help Basic clients verifying (actually ignoring) x509 credentials from other groups
* Upload test results in JUnit format

## [1.0.0-rc.46] - 2024-02-28

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.46"}}
</details>

* Rollback regression introduced in v1.0.0-rc.44

## [1.0.0-rc.45] - 2024-02-28

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.45"}}
</details>

* Fix x509 validation in received messages (especially UpdatePath) lenient since there is no active eviction mechanism in place for ghost clients

## [1.0.0-rc.44] - 2024-02-27

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.44"}}
</details>

* Fix issues when e2ei is turned off on a environment and the PKI env is restored which to validation failures when verifying a GroupInfo.

## [1.0.0-rc.43] - 2024-02-22

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.43"}}
</details>

* Fixed WASM IndexedDB ObjectStores being tentatively created when they already exist during migrations

## [1.0.0-rc.42] - 2024-02-21

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.42"}}
</details>

* Do not assert keypackage expiration when joining a group via external commit

## [1.0.0-rc.41] - 2024-02-21

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.41"}}
</details>

* WASM: Integrated pre-version into the calculation of the IndexedDB store version
    * This issue was preventing migrations between CC 1.0.0-[pre|rc] versions on Web
* Only assert keypackage expiration when being the sender of a commit/proposal
* Internal: Remove the cached flag determining the client's ability to perform E2EI operations.
    * This is precautionary to avoid potential state discrepancies when rotating credentials for example.

## [1.0.0-rc.40] - 2024-02-20

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.40"}}
</details>

* Fixed an issue with incorrect code in TypeScript bindings

## [1.0.0-rc.39] - 2024-02-20

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.39"}}
</details>

* Integrated the display name in the JWT DPoP token
* Reworked and hardened all x.509 verifications (including revocation)
* Added `serialNumber`, `notBefore` and `notAfter` fields to the `WireIdentity` struct. These fields are pulled directly from the relevant fields in End-identity X.509 certificates

## [1.0.0-rc.38] - 2024-02-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.38"}}
</details>

* Add `getExternalSender()` to init a subconversation with the parent external sender
* Fix e2ei issue when intermediates were not registered during the enrollment.

## [1.0.0-rc.37] - 2024-02-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.37"}}
</details>

* Fixed an issue with the WASM FFI where many fields were incorrectly exposed and were leading to constant `undefined` values (i.e. `epochHasChanged` issue)
* Avoided a clone of the signature public key when performing E2EI enrollment
* **API BREAKING CHANGES**:
    * `clientPublicKey` now works with X.509 credentials. This implies that the CredentialType now has to be provided to fetch the correct credential.
    * We now return dedicated errors for commits and proposals from older epochs instead of a generic `WrongEpoch` error. Respectively, we now return `StaleCommit` and `StaleProposal`.
* **BEHAVIORAL BREAKING CHANGES**:
    * We now verify (as per the MLS spec / RFC9420) GroupInfo prior to joining via external commit
    * We also verify Welcomes prior to joining a group
    * We now properly validate X.509 credentials against the set up PKI Environment
        * Note: Expired or Revoked credentials do not constitute hard errors in MLS operations but alter the E2EI status of a conversation

## [1.0.0-rc.36] - 2024-01-30

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.36"}}
</details>

* E2EI:
    * Fix: intermediates certificates registration was not working because extracting the key was not working

## [1.0.0-rc.35] - 2024-01-29

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.35"}}
</details>

* E2EI:
    * **BREAKING CHANGE** `e2eiMlsInitOnly()` also returns CRL Distribution Point
    * Fix: register intermediates at issuance since they're not provided by the /federation endpoint
    * Fix: register CRL Distribution Points on intermediates

## [1.0.0-rc.34] - 2024-01-25

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.34"}}
</details>

* E2EI:
    * **BREAKING CHANGE** change certificate expiry from days to seconds in the public API
    * **BREAKING CHANGE** add the potential new CRL Distribution points to:
        * `decryptMessage`
        * `processWelcomeMessage`
        * `joinByExternalCommit`
        * `addClientsToConversation`
        * `newAddProposal`
        * `e2eiRotateAll`

## [1.0.0-rc.33] - 2024-01-24

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.33"}}
</details>

* E2EI:
    * Fixed a bug on mobile where intermediate certificates & CRLs had a uniqueness constraint
    * Fixed a bug where the PkiEnv was not restored from disk after restarts
    * Ignore TrustAnchor when registering intermediate certificates
    * Remove RefreshToken handling on Web

## [1.0.0-rc.32] - 2024-01-23

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.32"}}
</details>

* E2EI:
    * Fixed a bug with Root CA Trust Anchor registration that wasn't working on native platforms (non-WASM)
    * Fixed a bug with the initialization of our Intermediate CA store causing CRL & End-Identity certificate validation to fail
    * Fixed a missing field in the FFI (CRL distribution-points) and added the logic to fill up the field
    * Fixed an integer overflow in the X.509 expiration setting
* MLS:
    * Fixed errors when a single certificate is contained in a Credential (obsolete check)
* Misc:
    * Updated dependencies in many libraries

## [1.0.0-rc.31] - 2024-01-22

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.31"}}
</details>

* fix(e2ei): use 2 ACME authorizations instead of 1

## [1.0.0-rc.30] - 2024-01-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.30"}}
</details>

* fix(e2ei): include "keyauth" in the ACME authorization, turn challenge non-optional in ACME authorization and stop including keyauth in the ACME challenge request. This version only works with IdP supporting extra OAuth claims (and by consequence only work with Keycloak and not Dex)

## [1.0.0-rc.29] - 2024-01-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.29"}}
</details>

* fix(e2ei): issue with the wrong signature key being used for the client DPoP token

## [1.0.0-rc.28] - 2024-01-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.28"}}
</details>

* fix(e2ei): issue related to invalid 'keyauth'

## [1.0.0-rc.26] - 2024-01-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.26"}}
</details>

* fix(e2ei): e2ei keystore method 'find_all' was unimplemented on WASM for intermediate CAs & CRLs

## [1.0.0-rc.24] - 2024-01-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.24"}}
</details>

* feat(e2ei): add methods to register root/intermediate certificates and CRLs. Also checks revocation status when asking for a conversation/user/device state.
* feat(e2ei): change ClientId & Handle to URIs with the scheme 'wireapp://'. Use '!' as delimiter in the ClientId

## [1.0.0-rc.23] - 2024-01-08

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.23"}}
</details>

* feat(mls)!: remove `PerDomainTrustAnchor` extension from required capabilities. Backward incompatible changes ! If you ever migrate from a previous version to this one take care of deleting all your groups
* fix(e2ei): fix a null pointer in the Javascript API
* fix(e2ei): Swift wrapper for E2eiEnrollment was not used in other methods
* fix: use 'implementation' Gradle configuration not to enforce dependencies version into consumers

## [1.0.0-rc.22] - 2023-12-13

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.22"}}
</details>

* feat(e2ei)!: manage OIDC refreshToken in CoreCrypto's encrypted-at-rest store. As a consequence, some methods went async (all the enrollment ones in WASM). The refreshToken has to be supplied in `newOidcChallengeRequest()` and is persisted in `newOidcChallengeResponse()`. Clients should fetch it back from an `Enrollment` created by `newRotateEnrollment()` with the new `getRefreshToken()` method.
* feat(e2ei)!: remove 'clientId' from `newActivationEnrollment()` & `newRotateEnrollment()`. We can do this now that we expect a specific ClientId format.
* feat(e2ei): add `getCredentialInUse(GroupInfo)` to check the e2ei state from a GroupInfo. This allows verifying the state of a conversation before joining it (and potentially degrading the e2ei state).
* feat(e2ei)!: rename `E2eiConversationState::Degraded` in to `E2eiConversationState::NotVerified`

## [1.0.0-rc.21] - 2023-12-05

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.21"}}
</details>

* feat!: canonicalize ClientId keeping only the regular version where the UserId portion is the hyphenated string representation of the UUID. Also apply this to `getUserIdentities()`

## [1.0.0-rc.20] - 2023-12-04

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.20"}}
</details>

* feat!: `addClientToConversation` API has been simplified. It just requires bare `KeyPackage`s without the `ClientId`
* feat!(e2ei): better errors ; almost got rid of `ImplementationError` used too much so far. This should help debugging
* feat!(e2ei): added `Team` and `Handle` in the client DPoP token
* build: bumped tls_codec from 0.3.0 to 0.4.0

## [1.0.0-rc.19] - 2023-11-20

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.19"}}
</details>

* feat!(e2ei): ~~`get_user_identities`~~ becomes `get_device_identities` and a new `get_user_identities` added to list identities in a group belonging to the same user
* feat!(e2ei): `get_device_identities` now accepts a `ClientId` as it is present in the MLS group and not as present in the Credential's X509
* feat(e2ei): handle is format changed from `im:wireapp={input}` to `im:wireapp=%40{input}@{domain}`
* feat!(e2ei): WireIdentity contains JWK thumbprint of the certificate public key and a validation status (Valid/Expired/Revoked) (even though revocation is not implemented yet)
* fix: X509 signature validation was failing when issuer had a different signature scheme than the subject

## [1.0.0-rc.18] - 2023-10-23

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.18"}}
</details>

* Native platforms only: Preserve database schema upgrade path from 0.8.x, 1.0.0-pre.6+schemafix-0007 and onwards.

## [1.0.0-rc.17] - 2023-10-23

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.17"}}
</details>

* Remove dependency of OpenSSL for Wasm
* Fix linking issue on Android

## [1.0.0-rc.16] - 2023-10-10

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.16"}}
</details>

* **[BREAKING-WASM ONLY]**: We now bundle our TypeScript and WASM bindings using [Bun](https://bun.sh/)
    * This shouldn't result in any fundamental changes API-wise
    * BREAKING NPM Package: The WASM file isn't shipped in the `platforms/web/assets` subfolder anymore. It is shipped in `platforms/web` now.
* Fixed RUSTFLAGS being overridden in CI context

## [1.0.0-rc.15] - 2023-10-10

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.15"}}
</details>

* fix: add '-latomic' flag when building for Android to dynamically link atomic lib which is supposedly causing issues with openssl
* feat: re-export e2ei types

## [1.0.0-rc.14] - 2023-10-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.14"}}
</details>

* fix: backward incompatible database schemas. It only preserves Proteus compatibility when migrating from CC 0.11.0 -> 1.0.0. For anything MLS-related it is recommended to wipe all the groups

## [1.0.0-rc.13] - 2023-09-27

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.13"}}
</details>

* feat!: introduce missing LeafNode validation at different step in the protocol. As a consequence, previous KeyPackages are not compatible with newly created groups and vice versa. It is recommended to purge everything. Otherwise, joining a group is likely to fail with a "InsufficientCapabilities" error.
* feat!: initial number of KeyPackage is now configurable, defaulting to 100
* feat: add e2ei methods for certificate enrollment in Swift wrapper
* fix: in the case where an external commit is used to rejoin a group, buffered messages are ignored since they probably aren't recoverable given this way to use external commit is often a last resort solution.

## [1.0.0-rc.12] - 2023-08-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.12"}}
</details>

* fix: Use sed in cross platform way for ffi build

## [1.0.0-rc.11] - 2023-08-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.11"}}
</details>

* fix!: Fix Kotlin & Swift FFI errors
    * This includes a breaking change where CoreCrypto and E2EI errors are separated, so change accordingly

## [1.0.0-rc.10] - 2023-08-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.10"}}
</details>

* fix: Fix Kotin & Swift wrappers by producing correct symbols

## [1.0.0-rc.9] - 2023-08-30

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.9"}}
</details>

* fix: tentatively fix the Kotlin & Swift wrapper by producing correct symbols
* fix: e2ei enrollment persistence collision (only used by web)
* fix: bump rusty-jwt-tools to v0.5.0 and fix `userId` encoding
* feat: expose `getUserIdentities()` (for e2ei purposes) in the FFI
* feat: add raw X.509 certificate in `WireIdentity` to display the certificate in the app

## [1.0.0-rc.8] - 2023-08-25

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.8"}}
</details>

* **[BREAKING]** regular commits were also (in addition to external commits) impacted by unordered backend messages. As a
consequence, both `commitAccepted` and `decryptMessages` now return buffered messages.
* Improved Kotlin wrapper: documented, tested, type safe
* fix: Rust future was leaked when Kotlin coroutine cancelled
* fix: TLS serialization of x509 Credential which makes this release interoperable with wire-server
* feat: expose `getUserIdentities` to list the identity of MLS group members using e2ei
* increase max past epoch from 2 to 3 to respect backend's configuration

## [1.0.0-rc.7] - 2023-08-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.7"}}
</details>

* **[BREAKING]** `RotateBundle` now returns a `Map<ConversationId, CommitBundle>` instead of a `Vec<CommitBundle>` in order
to correlate the commit with its group id and to merge it afterwards. Note that the `ConversationId` here is hex encoded due to limitations at the FFI boundary.

## [1.0.0-rc.6] - 2023-08-08

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.6"}}
</details>

* Add keystore dump CLI tool to debug internal applications and export the content of the keystore for further analysis
* handle the "orphan welcome" corner case when the client receives a Welcome but already has deleted the associated KeyPackage.
In that case he has to catch & ignore the "OrphanWelcome" error and to rejoin the group with an external commit.
* Fix credential rotation in end-to-end identity was signing the certificate with the wrong keypair part
* Fix `e2eiRotateAll` return type was not correctly wrapped in a object in Typescript

## [1.0.0-rc.5] - 2023-07-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.5"}}
</details>

* Fix WASM publication issues

## [1.0.0-rc.4] - 2023-07-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.4"}}
</details>

* Fix WASM publication issues

## [1.0.0-rc.3] - 2023-07-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.3"}}
</details>


* Ensure that all operations do not leak data (uncleared from the keystore). This was mostly happening with update proposals & credential rotation. Also introduced a separate table for storing epoch keypairs.
* **[BREAKING]** as a consequence (of the new table) all existing conversations are becoming unusable. It is strongly advised to wipe them all.
* Fix method `e2eiRotateAll` was returning undefined on WASM
* Add method `e2eiIsEnabled` to tell if a MLS client has a valid Credential for the given Ciphersuite
* **[BREAKING]** rename ~~`e2eiIsDegraded`~~ into `e2eiConversationState` which returns now an enumeration giving the state of the conversation regarding end-to-end identity.
* Adapt CI to execute WASM tests with chromedriver 115

## [1.0.0-rc.2] - 2023-07-25

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.2"}}
</details>

* Added support for x509 certificate roots and policies in MLS GroupContext through a TrustAnchor GroupContextExtension #346
* Fixed a CI issue that prevented Swift and JVM package publication

## [1.0.0-rc.1] - 2023-07-20

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-rc.1"}}
</details>

* **[BREAKING]** With this release, CoreCrypto is now [RFC9420](https://www.rfc-editor.org/rfc/rfc9420.txt) compliant.
    * This will cause Draft-20 clients to be unable to process keypackages emitted by RFC clients; But the opposite isn't true as RFC clients will ignore the extraneous `Capabilities` Draft-20 clients emit.
* **[BREAKING]** With our update to UniFFI 0.24, the FFI & bindings have significant breaking changes
    * Most if not all APIs are now `async` and will use the platform's executor thanks to UniFFI's integration with them. In terms of platforms, the consequences are the following:
        * Kotlin: Almost all APIs are now `suspend`
        * Swift: Almost all APIs are now `async`
        * TypeScript: A couple more APIs are now `async` compared to before
    * Some other things might have changed - the callbacks ABI has changed but this change should not affect users of our bindings as we try to erase those minute differences by wrapping everything in a stable API
* **[BREAKING]** CoreCrypto now handles self-commits sent by the backend and decrypted by the client.
    * In a particular case, when the backend replays a commit, the client is not to blame.
        * In that case, `decryptMessage` will return a `SelfCommitIgnored` which you should catch and ignore. It means you are likely to already have merged this commit.
* **[BREAKING]** CoreCrypto now handles duplicate application or handshake messages.
    * When such a case happens, `decryptMessage` will return a `DuplicateMessage` error encapsulating a `GenerationOutOfBound` error. The latter variant also has been removed.
* **[BREAKING]** To mitigate unordered messages when joining with an external commit, incoming messages are now buffered until you merge the external commit with `mergePendingGroupFromExternalCommit`.
    * At that point they are replayed and their result return in the method return type ; hence make sure to read and handle it!
    * Note that for messages arriving during the external commit merge window, `decryptMessage` will return a `UnmergedPendingGroup` error which means the edge case has been identified and the message will be reapplied later; so feel free to catch and ignore this error.
* *[SEMI-BREAKING]* CoreCrypto now prevents overwriting an existing conversation when creating a new conversation, joining one with a Welcome or joining with an external commit.
    * This is within an effort to harden our data storage policies and to provide better feedback to API consumers as to what is actually happening.
    * This change also is a breaking behavior change - But you should not be abusing the existing mechanic anyway to replace conversations as this was an unintended bug
* Our CI is now building the Swift bindings with Xcode 14.3.1
* We managed to reduce the size of our libraries by stripping them afterwards
* *[EXPERIMENTAL]* This version of CoreCrypto is the first to ship with a Proteus compatibility layer that uses the same cryptographic primitives as the MLS counterparts
    * This yields in practice performance gains between 20% and 900% depending on the type of operation
    * Again, as this is an experimental change, things *might* break.



## [1.0.0-pre.8] - 2023-07-18

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-pre.8"}}
</details>

* This is a release that contains nothing new. This is to fix the previous Kotlin release that was not correctly built & released.

## [1.0.0-pre.7] - 2023-07-17

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-pre.7"}}
</details>

* **[BREAKING]** We now detect duplicate messages from previous epochs, as such the `GenerationOutOfBound` error is now named `DuplicateMessage`.
* **[BREAKING]** We now throw errors when consumers try to create or join a group via Welcome message BUT the group already exists within our store. This is to prevent accidental group erasure in case of duplicate notifications from the DS. Note that the API does not change with this but presents a breaking behavior change.
* We pinned some private forks under the @wireapp GitHub org to secure our software supply chain.


## [1.0.0-pre.6] - 2023-07-06

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-pre.6"}}
</details>

* feat!: PostQuantum Ciphersuite support ! Using [Xyber768](https://www.ietf.org/archive/id/draft-westerbaan-cfrg-hpke-xyber768d00-02.html) for Key Exchange.
* feat! Credential rotation support (for E2E Identity). It allows to change the local client Credential in a MLS group, replacing it with a X509 Certificate one.
* feat!: remove `export_group_info()` method that wasn't used

## [1.0.0-pre.5] - 2023-06-12

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-pre.5"}}
</details>

* fix: `joinByExternalCommit` was expecting a `GroupInfo` wrapped in a MlsMessage

## [1.0.0-pre.4] - 2023-06-12

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-pre.4"}}
</details>

* build: fixed different sources of tls_codec

## [1.0.0-pre.3] - 2023-06-11

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-pre.3"}}
</details>

* fix: tls_codec had an issue with variable length encoding

## [1.0.0-pre.1] - 2023-06-11

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v1.0.0-pre.1"}}
</details>

* **[BREAKING]**: MLS draft-20 !
  * internally use the latest version of openmls compatible with draft-20 (not yet RFC9420)
  * `Public Group State` methods/fields etc.. have been renamed into `Group Info`
  * `CommitBundle` fields (welcome, commit, group_info) are now wrapped in MLS messages
  * `new_external_proposal()` has been removed
  * By default, partial commits (w/o UpdatePath) are created

## [0.11.0] - 2023-05-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.11.0"}}
</details>

* **[BREAKING]**: fix Ciphersuite lowering for mobile FFI, using either a 16-bit integer (or a List of it) to lower those types across the FFI.
* **[BREAKING]**: removed optional entropy_seed from public API only on mobile since it was not required there and was causing the aforementioned issue with list of ciphersuites.

## [0.10.0] - 2023-05-25

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.10.0"}}
</details>

* **[BREAKING]**: creating a MLS group was consuming an existing KeyPackage which could lead to inconsistencies if the
former isn't pruned on the backend side. As a consequence, `createConversation()` now expects the CredentialType to pick the right credential the author wants to join the group with.
* **[BREAKING]**: fixed unsound bug happening on aarch64 Android devices because of lowering a List of enumerations across
the FFI. Still uncertain about the root cause but to move on all the parameters like: `ciphersuite: List<Ciphersuite>` in the public API have been replaced with a default value
* Fixed Android FFI bug in `e2eiMlsInit` where a reference counter had one too many reference when trying to destroy it

## [0.9.2] - 2023-05-22

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.9.2"}}
</details>

* Fixed migrations not running because of a mistakenly added table in an older migration version

## [0.9.1] - 2023-05-17

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.9.1"}}
</details>

* Fixed excessive bloat in the FFI layer due to emitting rlibs

## [0.9.0] - 2023-05-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.9.0"}}
</details>

* First iteration of multi-ciphersuite support. The API now explicitly requires a Ciphersuite to be supplied anywhere where it's necessary. For now on you should only use the default one. Same thing for `MlsCredentialType`, use `Basic` whenever required
* Allow persisting an e2e identity enrollment for web's needs
* `check_order_response` & `finalize_response` now return the URL for where the next step's payload has to be sent
* ACME challenges now have a "target" field which indicates the URL of the OAuth authorization and the access token endpoint

## [0.8.2] - 2023-04-28

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.8.2"}}
</details>

* build: fix Android packaging (again) by sourcing bindings

## [0.8.1] - 2023-04-27

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.8.1"}}
</details>

* build: fix Android packaging

## [0.8.0] - 2023-04-19

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.8.0"}}
</details>

* **[BREAKING]**(e2e identity): added an expiry in seconds in `create_dpop_token`)

## [0.7.0] - 2023-04-12

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.7.0"}}
</details>

* Please see the previous RC releases for the full changelog
* Fixed a bug in the iOS WAL compatibility layer that didn't specific correct keychain attributes on the stored SQLCipher salt
* Updated internal dependencies
* Implemented E2EI credential identity verification
    * We are now returning extra data on decrypted messages; you'll be able to get the sender's full identity in them.

## [0.7.0-rc.4] - 2023-03-28

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.7.0-rc.4"}}
</details>

* Updated UniFFI to 0.23
    * Might or might not contain breaking changes depending on your use case, please refer to [UniFFI's documentation](https://github.com/mozilla/uniffi-rs/blob/main/CHANGELOG.md)
* Fixed a small bug in the new GroupStore internals that was a bit too eager in limiting memory usage
* **[BREAKING]**: Renamed the WASM `strongRefCount(): number` API to `isLocked(): boolean`.
    * This essentially hides the implementation details across the FFI and should minimize brittleness
* Removed our dependency on [ring](https://github.com/briansmith/ring), an external crypto library. It was mostly used for validating x509 certificates and crafting Certificate Signing Request
    * By removing `ring`, we now support the following MLS Ciphersuites using NIST elliptic curves / ECDSA on WASM:
        * `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (`0x0002`)
        * `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` (`0x0007`)
* **[BREAKING]**: Overhauled parts of the E2EI implementation
      * Moved from a stateless API to a stateful one. As a consequence, methods have less parameters, less structs need to be exposed. All of this is wrapped under Rust's safe sync primitives in order to be able to perform the ACME enrollment in parallel.
      * The new API allows creating a MLS group from the enrollment process.
        * ~~`certificateResponse()`~~ has been removed
        * `e2eiMlsInit()` has been introduced and permits ending the enrollment flow and use the x509 certificate to initialize a MLS client.
      * `ClientId` is now a string as per [RFC8555](https://www.rfc-editor.org/rfc/rfc8555). It does not anymore require to be prefixed (by `impp:wireapp=`) and is exactly the same as the one used for MLS
      * X509 SAN URIs are now prefixed by `im:wireapp=` instead of `impp:wireapp=`
      * This release has been tested against a real OIDC provider ([Dex](https://dexidp.io/)), federating identity from a LDAP server. The OAuth2 flow used for testing is [Authorization Code with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce)
      * Private key materials are now properly zeroized



## [0.7.0-rc.3] - 2023-03-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.7.0-rc.3"}}
</details>

* Fixed a bug where `proteus_new_prekey_auto` returning the same prekey ID in particular cases
    * In case of "gaps" in the prekey id sequence, the previous algorithm (using the number of prekeys stored) would return the same ID over and over. As a consequence, the same prekey id would be overwritten over and over.

## [0.7.0-rc.2] - 2023-03-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.7.0-rc.2"}}
</details>

* Fix on documentation that prevented release on many platforms

## [0.7.0-rc.1] - 2023-03-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.7.0-rc.1"}}
</details>

* **[BREAKING]** proteus_new_prekey_auto() now returns a tuple of (prekey_id, CBOR-serialized PreKeyBundle) for backend requirements
    * On bindings, this translates to a new struct ProteusAutoPrekeyBundle which contains two fields:
        * `id`: the proteus prekey id (`u16`)
        * `pkb`: the CBOR-serialized proteus PreKeyBundle
* **[BREAKING]** Added an API to mark subconversations as child of another one (`mark_conversation_as_child_of`)
    * This is breaking because this now allows us to provide the parent conversation's client list in the `client_is_existing_group_user` callback, which adds a new parameter to it
* **[BREAKING]** `wipe_conversation` is now automatically called when a commit removing the local client is received.
* **[BREAKING]** Huge internal change on how we cache MLS groups and Proteus sessions in memory
    * This affects some APIs that became async on the TS bindings
    * Our previous `HashMap`-based cache could grow indefinitely in the case of massive accounts with many, many groups/conversations, each containing a ton of clients. This replaces this memory store by a LRU cache having the following properties:
        * Limited by number of entries AND occupied memory
            * Defaults for memory: All the available system memory on other platforms / 100MB on WASM
            * Defaults for number of entries:
                * 100 MLS groups
                * 200 Proteus sessions
        * Flow for retrieving a value
            1. Check the LRU store if the value exists, if yes, it's promoted as MRU (Most Recently Used) and returned
            2. If not found, it might have been evicted, so we search the keystore
            3. If found in the keystore, the value is placed as MRU and returned
                * Special case: we evict the store as much as needed to fit the new MRU value in this case. This is designed to infaillible.
            5. If not found, we return a `None` value
    * This approach potentially allows to have an unlimited number of groups/sessions as long as a single item does not exceed the maximum memory limit.
    * As a consequence of the internal mutability requirements of the new map and the automatic keystore fetches, many if not all APIs are now `async`. This does not concern the Mobile FFI.
* **[BREAKING]** Because of Rust 1.68's release, CoreCrypto is now incompatible with Android NDK versions under 25.2 (the LTS version) and Android API level 24.
* **[BREAKING]** E2EI: The API is now compliant with RFC8555
    * Another change will come soon to be able to initialize a MLS client using the X509 certificate issued by the E2EI process
* Enabled the iOS WAL compatibility layer to prevent spurious background kills
* Added a WASM api to check the Arc strongref counter

## [0.6.3] - 2023-02-17

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.3"}}
</details>

* Improve compatbillity with older linux versions when running core-crypto-jvm by building on Ubuntu LTS (22.04).

## [0.6.2] - 2023-02-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.2"}}
</details>

* Fixed a bug in the TypeScript bindings where the `DecryptedMessage` bundle could have `commitDelay` set to `undefined` when it should be 0
    * This could happen in the case of external proposals where the system would determine that the proposals should be immediately committed

## [0.6.1] - 2023-02-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.1" }}
</details>

* Fixed a bug where the Proteus last resort prekey could be overwritten.
* Fixed JVM publishing creating broken packages.
* WASM callbacks return false by default if no promise is returned.
* Benchmarks: Remove redundant save when persisting proteus sessions.

## [0.6.0] - 2023-02-13

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0"}}
</details>

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* armv7-linux-androideabi ✅
* aarch64-linux-android ✅
* i686-linux-android ✅
* x86_64-linux-android ✅
* aarch64-apple-ios ✅
* aarch64-apple-ios-sim ✅
* x86_64-apple-ios ✅
* wasm32-unknown-unknown ✅

### 0.6.0 Release changes

* **[BREAKING CHANGE]** E2EI solution API overhauled from pre-release versions
    * This was made to fix some incompatibilities between the DPoP RFC and our code; The API had to be changed as a consequence
    * Please refer to the following point to see the changes
* First stable version of Wire's end-to-end identity client library. It allows a MLS client to generate a x509 certificate proving possession of its userId, clientId and displayName for a given domain/backend. This certificate will later be used as a MLS credential in place of the only currently supported "basic" one which consists of a public key.
    * To generate such a certificate, use the `new_acme_enrollment` method on a partially initialized CoreCrypto instance. This will generate a temporary key material for the enrollment session with the ACME server. Note that only Ed25519 signature scheme is supported at the moment.
    * Only the "enrollment" flow is defined for the moment. Later on, "refresh" and "revocation" flows will be added.
    * This library is heavily opinionated and only suited for **Wire** custom flow, with [our fork of the acme server](https://github.com/wireapp/smallstep-certificates). Any attempt to use it as a generic purpose acme client library will fail terribly.
    * To make sure this works as expected, this library has been tested against the actual [acme-server](https://github.com/wireapp/smallstep-certificates) thanks to [testcontainers](https://www.testcontainers.org/). Only the OIDC provider has been mocked for the moment due to the fact that the target provider [Dex](https://github.com/dexidp/dex) does not yet support Ed25519 signatures.

### 0.6.0 pre-release changes tl;dr, for information

#### Changes

* Added support for externally-generated MLS clients
    * This allows you to generate a standalone Credential/KeyPair, submit it to your MLS Authentication Service, and then update this credential with a newly-attributed Client ID.
* Added APIs to support Proteus Last Resort Prekeys
* Added support for Proteus error codes
    * WASM:
        * all errors are now instances of `CoreCryptoError` which extends the standard JavaScript `Error` but with additional properties:
            * `rustStackTrace` contains the original Rust error string.
            * `proteusErrorCode` contains the error code for Proteus calls. If it's 0, no error, otherwise it contains the code
        * WASM/TS now has access to the `CoreCrypto.proteusLastErrorCode()` method which allows to retrieve the last-occured proteus error and thus brings it to parity with other FFIs
    * On other platforms, the FFI has gained a `proteus_last_error_code` method.
* Fixed a bug where the keystore would not execute its IndexedDB upgrade handler on WASM, leading to older stores and/or new tables not being structurally consistent
* Added missing Proteus APIs to bindings and FFI:
    * `proteus_new_prekey_auto`: generates a new PreKeyBundle with an automatically incremented ID
        * To do this, CoreCrypto finds the first "free" ID within the `0..u16::MAX - 1` range and creates a PreKey using this ID.
* Added Proteus compatibility layer support
* Added API to export secret key derived from the group and client ids from the members
* Change `DecryptedMessage` signature
    * The `decrypt` API now returns if the decrypted message changed the epoch through the `hasEpochChanged` field
* Members can now rejoin group by external commits
    * Validate received external commits
    * Added `clear_pending_group_from_external_commit`
    * External commit returns a bundle containing the PGS


#### Breaking changes


* **[BREAKING CHANGE]** Changed callbacks to be async
    * This allows consumers to perform async I/O within the callbacks
    * **Note** this doesn't affect the Kotlin/Swift bindings as UniFFI does not support async yet.
* **BREAKING** Renamed callback `client_id_belongs_to_one_of` to `client_is_existing_group_user`
* **BREAKING** WASM: Omitted in last build; `CoreCrypto.deferredInit` now takes an object with the parameters much like `init()` for consistency reasons.
* **BREAKING** No one was probably using it, but the C-FFI has been removed


There has been an extensive pre-release period (with many -pre and -rc releases), the original changelog for those has been collapsed below:

<details>
    <summary>0.6.0 pre-releases changelog</summary>

## [0.6.0-rc.8] - 2023-02-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.8"}}
</details>

* Added support for externally-generated MLS clients
    * This allows you to generate a standalone Credential/KeyPair, submit it to your MLS Authentication Service, and then update this credential with a newly-attributed Client ID.
* **[BREAKING CHANGE]** Changed callbacks to be async
    * This allows consumers to perform async I/O within the callbacks
    * **Note** this doesn't affect the Kotlin/Swift bindings as UniFFI does not support async yet.
* Added APIs to support Proteus Last Resort Prekeys

## [0.6.0-rc.7] - 2023-02-06

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.7"}}
</details>

* Fixed WASM build when imported from the outside
    * Made sure we're not leaking internal/private interfaces anymore and causing issues
    * Also added a test to our JS E2E suite to make sure importing the package with TS is successful and we do not encounter regressions like these anymore
* **BREAKING** WASM: Omitted in last build; `CoreCrypto.deferredInit` now takes an object with the parameters much like `init()` for consistency reasons.


## [0.6.0-rc.6] - 2023-02-01

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.6"}}
</details>

**IMPORTANT: The previous release (0.6.0-rc.5) is non-functional in general. The proteus error reporting does NOT work**

There's a post mortem available here: <https://github.com/wireapp/core-crypto/pull/230#issue-1557053094>

* Fixed support for Proteus error codes
    * WASM:
        * all errors are now instances of `CoreCryptoError` which extends the standard JavaScript `Error` but with additional properties:
            * `rustStackTrace` contains the original Rust error string.
            * `proteusErrorCode` contains the error code for Proteus calls. If it's 0, no error, otherwise it contains the code
        * WASM/TS now has access to the `CoreCrypto.proteusLastErrorCode()` method which allows to retrieve the last-occured proteus error and thus brings it to parity with other FFIs
    * On other platforms, the API is unchanged, but now works.


## [0.6.0-rc.5] - 2023-01-25

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.5"}}
</details>

* **BREAKING**: Changed the signature of the `client_is_existing_group_user` callback to add the group id as the first argument
    * Before: `client_is_existing_group_user(client_id: ClientId, existing_clients: Vec<ClientId>) -> bool`
    * After: `client_is_existing_group_user(conversation_id: ConversationId, client_id: ClientId, existing_clients: Vec<ClientId>) -> bool`
* Added support for Proteus error codes
    * On WASM, the JS Error contains a `proteusError` method that returns the error code as an integer. If there's no error it returns 0.
    * On other platforms, the FFI has gained a `proteus_last_error_code` method.
* Fixed a bug where the keystore would not execute its IndexedDB upgrade handler on WASM, leading to older stores and/or new tables not being structurally consistent
* Updated RustCrypto dependencies
* Tooling: moved code coverage CI from Tarpaulin to LLVM-Cov
    * This lowered the execution time of our codecov CI from ~25-30 minutes down to ~15-20 minutes
    * This leads to more accurate code coverage as well - along with some false negatives such as `#[derive]` statements


## [0.6.0-rc.4] - 2023-01-20

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.4"}}
</details>

* First bytes of end to end identity exposed. Thanks to the ACME protocol, it allows requesting a x509 certificate from an authority and then use it to create a MLS Credential.
* Fixed `cargo-make` Makefile.toml to allow building JVM bindings whatever the platform you're running
    * This is done by adding tests to the relevant tasks, allowing to conditionally execute them.
* Added a Makefile task to build the `core_crypto_ffi` Kotlin binding docs (via Dokka) and integrate them into the doc package
* Updated UniFFI to 0.22
* Other minor improvements on internal build/release tools (mainly our `cargo xtask` command)
* **Semi-breaking**: Behavior change on `ProteusCentral::import_cryptobox` (aka Cryptobox import).
    * WASM: If the provided store `path` is missing or doesn't have the expected tables, we now throw a `CryptoboxMigrationError::ProvidedPathDoesNotExist` error
    * Other platforms: If the provided cryptobox folder at `path` is missing, we now throw a `CryptoboxMigrationError::ProvidedPathDoesNotExist` error
    * Likewise, on all platforms, if the Cryptobox Identity is not present, we now throw a `CryptoboxMigrationError::IdentityNotFound` error and abort the process
* Tooling: Added a custom WASM test runner based on WebDriver (BiDi interactive test progress reporting in progress still)

## [0.6.0-rc.3] - 2022-12-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.3"}}
</details>

* Added missing Proteus APIs to bindings and FFI:
    * `proteus_new_prekey_auto`: generates a new PreKeyBundle with an automatically incremented ID
        * To do this, CoreCrypto finds the first "free" ID within the `0..u16::MAX` range and creates a PreKey using this ID.
* Added missing documentation when it comes to Proteus eager Session persistence.
    * Previously undocumented change, but since `0.6.0-rc.1`, CoreCrypto eagerly persists Proteus Sessions (much like it does with MLS groups) when needed:
        * Decrypting or Encrypting messages, as ratcheting key material can be produced and as such must be persisted
            * We'll add a more "manual" API later on if you want to control when data is persisted (because it is performance heavy)
        * Initializing Sessions through PreKeyBundles or incoming Messages


## [0.6.0-rc.2] - 2022-12-15

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.2"}}
</details>

* This release contains nothing. It's only there to fix the faulty Android release CI.

## [0.6.0-rc.1] - 2022-12-14

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-rc.1"}}
</details>

* Fixed a compilation issue related to the `sha1` crate's ASM
* Added a `restore_from_disk` API to enable using CoreCrypto from various instances
* Various internal improvements to testing to increase resistance to uncommon scenarios
* Proteus:
    * Expose proteus prekey fingerprint
    * Fixed the TypeScript exposed types
    * Fixed Cryptobox import
    * Fixed broken Proteus implementation that led to decryption errors after key import
* MLS:
    * Expose a `WrongEpoch` error
    * Added an error when trying to break PFS
    * **BREAKING**: Tweaked the configuration format, removed and added some options

## [0.6.0-pre.5] - 2022-11-10

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-pre.5"}}
</details>

* chore: Get rid of the C-FFI
* feature: Added support for deferred MLS initialization
* Proteus:
    * Expose Proteus session Fingerprints (local & remote)


## [0.6.0-pre.4] - 2022-11-07

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-pre.4"}}
</details>

* fix: Publication of swift packages [CL-49] by @augustocdias in https://github.com/wireapp/core-crypto/pull/165
* fix: Make tags have semantic versioning names and downgrading to swift 5.5 - CL-49 by @augustocdias in https://github.com/wireapp/core-crypto/pull/166
* feat: Expose session exists through the ffi - CL-101 by @augustocdias in https://github.com/wireapp/core-crypto/pull/167
* chore: fix new clippy warnings in 1.65 by @beltram in https://github.com/wireapp/core-crypto/pull/170
* fix: consistent commits by @beltram in https://github.com/wireapp/core-crypto/pull/169
* fix!: Incorrect handling of enums across WASM FFI [CL-104] by @OtaK in https://github.com/wireapp/core-crypto/pull/168
* test: pure ciphertext by @beltram in https://github.com/wireapp/core-crypto/pull/160
* Release 0.6.0-pre.4 by @augustocdias in https://github.com/wireapp/core-crypto/pull/171


**Full Changelog**: https://github.com/wireapp/core-crypto/blob/develop/CHANGELOG.md

## [0.6.0-pre.3] - 2022-11-01

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-pre.3"}}
</details>

* Move github action for rust to a maintained one. (More info: https://github.com/actions-rs/toolchain/issues/216)

## [0.6.0-pre.2] - 2022-10.21

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-pre.2"}}
</details>

* Enable proteus support

## [0.6.0-pre.1] - 2022-10.21

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.6.0-pre.1"}}
</details>

* Add Apple M1 support for the JVM bindings
* Rename callback `client_id_belongs_to_one_of`
* Added Proteus compatibility layer support
* Added API to export secret key derived from the group and client ids from the members
* Change CommitBundle signature
    * The `decrypt` API now returns if the decrypted message changed the epoch
* Members can now rejoin group by external commits
    * Validate received external commits
    * Added `clear_pending_group_from_external_commit`
    * External commit returns a bundle containing the PGS

</details>

## [0.5.2] - 2022-27-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.5.2"}}
</details>

* Fix: supplied backend's removal key was not TLS serialized but base64 encoded. In this release, it is up to consumer
to base64 decode the key and supply it to core-crypto
* Fix: Typescript enumerations could not be used by value

## [0.5.1] - 2022-21-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.5.1"}}
</details>

* Fix: supplied backend's removal key (used for verifying external remove proposals) was not TLS deserialized
* Fix: incorrect null handing in Typescript wrapper for 'commitPendingProposals' causing an error when there was no proposal to commit
* New test runner for running interoperability tests between various core-crypto clients.
Currently, only native & WASM are supported. Most of all, those tests can be run in our Continuous Integration.

## [0.5.0] - 2022-14-09

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.5.0"}}
</details>

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ✅ (⚠️)
* aarch64-linux-android ✅ (⚠️)
* i686-linux-android ✅ (⚠️)
* x86_64-linux-android ✅ (⚠️)
* aarch64-apple-ios ✅
* aarch64-apple-ios-sim ✅
* x86_64-apple-ios ✅
* wasm32-unknown-unknown ✅

Note: all the platforms marked with (⚠️) above will get a round of polish for the build process & documentation in the next release.

* **[BREAKING]**: `commit_pending_proposals` now returns an optional `CommitBundle`
    * This was made to handle the case where there are no queued proposals to commit and this method would be called, causing the operation to fail.
* **[BREAKING]**: Changed the API for callbacks for clarity
    * This also contains documentation changes that make the use and intent of callbacks easier to understand.
* Fixed the iOS-specific database salt handling to allow using several databases on the same device.
* TypeScript bindings:
    * Removed the use of ES2020-specific operators (`??` Null-coalescing operator) to allow downstream to compile without transpiling.
    * Added callbacks API
    * Removed the usage of `wee_alloc` allocator as it leaks memory: https://github.com/rustwasm/wee_alloc/issues/106
* Kotlin & Swift bindings:
    * Upgraded UniFFI to 0.20 which now generates a correct callback interface in `camelCase` instead of erroneous `snake_case`.
        * Note that you will have to adapt to the aforementioned breaking changes to the callback API anyway so this just makes it a bit nicer

## [0.4.2] - 2022-09-05

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.4.2"}}
</details>

* Fixes runtime issues on Android caused by the [sha2](https://github.com/RustCrypto/hashes/tree/master/sha2) crate.

## [0.4.1] - 2022-09-01

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.4.1"}}
</details>

* Fixes build issues for mobile target

## [0.4.0] - 2022-08-31

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.4.0"}}
</details>

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ✅ (⚠️)
* aarch64-linux-android ✅ (⚠️)
* i686-linux-android ✅ (⚠️)
* x86_64-linux-android ✅ (⚠️)
* aarch64-apple-ios ✅
* aarch64-apple-ios-sim ✅
* x86_64-apple-ios ✅
* wasm32-unknown-unknown ✅

Note: all the platforms marked with (⚠️) above will get a round of polish for the build process & documentation in the next release.

### CoreCrypto

* Allow rollbacking proposals. Now every method for creating a proposal also returns a proposal reference
(unique identifier) one can use later on to `clear_pending_proposal`
* Add `clear_pending_proposal` to wipe out local pending proposals
* Add `clear_pending_commit` to wipe out local pending commit
* Add `conversation_epoch` to get the current conversation's MLS epoch
* Now `decrypt_message` returns the sender client_id when the message is an application message. To use in calling.
* Durability: Now all the mutable operations are checked for durability i.e. would a process crash turn the application
into an inconsistent state. It boils down to verifying that we persist the MLS group in the keystore after every
operation mutating it
* Added a clean and documented Swift wrapper and tasks to build it more easily
* use 128 bytes of padding when encrypting messages instead of 16 previously
* Add some commit methods `final_add_clients_to_conversation`, `final_remove_clients_from_conversation`,
`final_update_keying_material` & `final_commit_pending_proposals` which return a TLS serialized CommitBundle. It cannot
be used now since wire-server does not yet have an endpoint for supplying it. It can be used to test the endpoint.
In the end, the `final_` prefix will removed and the not prefixed methods will be deprecated.
* Benchmarks have been improved and now also cover MLS operations


## [0.3.1] - 2022-08-16

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.3.1"}}
</details>

Maintenance release to prepare for the next release

* Pinned all git dependencies via git tags to avoid breakage in the future


## [0.3.0] - 2022-08-12

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.3.0"}}
</details>

This second major release focuses on expanding our platform support and featureset

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ✅ (⚠️)
* aarch64-linux-android ✅ (⚠️)
* i686-linux-android ✅ (⚠️)
* x86_64-linux-android ✅ (⚠️)
* aarch64-apple-ios ✅ (⚠️)
* aarch64-apple-ios-sim ✅ (⚠️)
* x86_64-apple-ios ✅ (⚠️)
* wasm32-unknown-unknown ✅

Note: all the platforms marked with (⚠️) above will get a round of polish for the build process & documentation in the next release.

### CoreCrypto

* Majorly improved documentation across all crates. Documentation for the `main` branch can be found here. The `HEAD` of this branch should only be a tagged version.
    * This documentation is available here: <https://wireapp.github.io/core-crypto/core_crypto/>
* Moved the codebase to `async`
    * This was a requirement to make everything work on the WASM target, as we cannot block the JavaScript runtime without making the browsers freeze up completely
    * As a consequence, we forked `openmls` to [wireapp/openmls](https://github.com/wireapp/openmls)
        * Our incremental changes, including the `async` rewrite of `openmls` is located [here](https://github.com/wireapp/openmls/pull/4)
* Added support for MLS Group Persistence, as this was preventing clients from continuing use of their joined groups (oops!)
* **All methods creating a commit e.g. `add_clients_to_conversation` now require to call `commit_accepted` when Delivery Service responds `200 OK`. Otherwise, it might indicate there was a `409 CONFLICT`, i.e. another client sent a commit for current epoch before and got accepted. In that case, do nothing and let things get reconciled in `decrypt_message`**
* Added support for lifetime-expired Keypackage pruning
* Added support for external CSPRNG entropy pool seeding
* Dropped the `openmls-rust-crypto-provider` in favour of our `mls-crypto-provider` with support for more ciphersuites and updated dependencies
    * As a consequence, we forked `hpke-rs` to [wireapp/hpke-rs](https://github.com/wireapp/hpke-rs)
        * Our changes can be found [here](https://github.com/wireapp/hpke-rs/tree/fix/updated-deps)
    * Ciphersuite support details:
        * `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ✅
        * `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` ✅
        * `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` ✅
        * `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` ❌
            * There is no suitable `ed448` rust crate yet
        * `MLS_256_DHKEMP521_AES256GCM_SHA512_P521` ❌
            * `p521` RustCrypto crate is a WIP and not ready just yet. It shouldn't take too long though.
        * `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448` ❌
            * There is no suitable `ed448` rust crate yet
        * `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` ✅

* Expanded the API to include:
    * Conversations:
        * Ability to wipe
        * Ability to leave
        * Ability to force clients to update their keying material (i.e. self-update)
    * Support for MLS proposals
        * Exposed methods to create `Add` / `Remove` / `Update` proposals
    * Support for MLS external commits
        * Added ability to export MLS Public Group State for a given conversation
            * A `PublicGroupState` is also returned everytime you create a commit. This comes from the need to keep the MLS Delivery Service up to date on the `PublicGroupState` so that external commits can be made by other clients.
        * Added support for creating an external commit to join a conversation (`join_by_external_commit`)
    * Support for MLS external Add (`new_external_add_proposal`) and Remove Proposal (`new_external_remove_proposal`).
    * Support for X.509 credentials
    * Added a commit delay hint to prevent clients from rushing to commit to the server - which would cause epoch conflicts and high load
        * Returned in `decrypt_message`
* Changed most `message` fields to be named `commit`, as this would cause less confusion for consumers. Those fields always contained MLS commits and should be treated as such.
* All commit methods now return a `CommitBundle` struct containing
      * the commit message
      * an optional `Welcome` if there were pending add proposals
      * a `PublicGroupState` to upload to the Delivery Service
    * `decrypt_message` now returns a `DecryptedMessage` struct containing:
      * an optional application message
      * optional pending proposals renewed for next epoch to fan out
      * a `is_active` boolean indicating if the decrypted commit message caused the client to be removed from the group
      * the aforementioned commit delay

### FFI

* Added WASM bindings support to target `wasm32-unknown-unknown` as a new tier 1 target.
    * Added a full-fledged TypeScript wrapper with a full documentation to abstract the wasm-specific issues.
    * This now means that CoreCrypto is also now a NPM package. It is currently published at [@otak/core-crypto](https://www.npmjs.com/package/@otak/core-crypto)
* Incremental improvements to the Kotlin & Swift UniFFI bindings
    * Caught up the bindings' API to match our internal CoreCrypto APIs
* Added a C-FFI for maybe future work involving other targets than Kotlin & Swift


### Keystore

* Added support for WASM through an AES-GCM256-encrypted IndexedDB backend
    * This introduced a major refactoring to structure the code around having different backends depending on the platform.

## [0.2.0] - 2022-03-22

<details>
    <summary>git-conventional changelog</summary>
{{git-cliff tag="v0.2.0"}}
</details>

Initial stable release with a reduced featureset

Platform support status:

* x86_64-unknown-linux-gnu ✅
* x86_64-apple-darwin ✅
* x86_64-pc-windows-msvc ❌
* armv7-linux-androideabi ⚠️
* aarch64-linux-android ⚠️
* i686-linux-android ⚠️
* x86_64-linux-android ⚠️
* aarch64-apple-ios ⚠️
* aarch64-apple-ios-sim ⚠️
* x86_64-apple-ios ⚠️
* wasm32-unknown-unknown ❌

This release contains the following features:

### CoreCrypto

* Client abstraction
    * Handles creating/retrieving the locally stored client identity automatically
* Conversation handling
    * Ability to create conversations
    * Message encryption/decryption
    * Ability to add/remove users from a conversation
* Encrypted-at-rest Keystore for persistence of client keying material and keypackages

### FFI

* Added Swift and Kotlin bindings through UniFFI

### Keystore

* Added support for Proteus PreKeys
* Fixed iOS-specific WAL behavior to preserve backgrounding capabilities
    * See the comment at `https://wireapp.github.io/core-crypto/src/core_crypto_keystore/connection/platform/generic/mod.rs#99` for more details
* Fix for migrations being incorrectly defined
