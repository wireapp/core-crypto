# Changelog

## v3.0.0 - 2024-12-11

### Highlights

- Fix the 'transaction in progress' error when there was an attempt to perform multiple transactions
  in parallel. This will no longer throw an error, instead the transactions will be queued and performed
  serially one after another.

### Breaking changes

- Added the missing MLS error case OrphanWelcome.

### Bug Fixes

- expose `OrphanWelcome` to clients [WPB-14954] (530b2e4)
- silence verbose logs when performing a transaction [WPB-14953] (b13553d)
- don't swallow transaction errors if they don't originate from the closure [WPB-14895] (124b8a7)
- wait for current transaction to finish when creating a new one [WPB-14895] (73b9d52)

### Testing

- parallel transactions are performed serially (ccc0b32)

## v2.0.0 - 2024-12-02

### Highlights

- The number of public errors has been reduced and simplified. It's no longer necessary to use the
  `proteus_last_error_code` function, since thrown error should contain all the information.
- The logger callback now includes an additional context parameter which contains additional context
  for a log event in the form of a JSON Object string.
- It's now possible to change the logger and log level at runtime (see `setLogLevel` and `setLogger`).

### Breaking changes

- Dropped support for `i686-linux-android` target.
- `CoreCryptoLogger` takes an additional `context` parameter.
- `CoreCryptoError` and its child errors have been refactored to reduce the amount of error we expose and provide explicit 
   errors for Proteus errors. The errors we have removed will appear under the `Other` case.  
   ```
   enum ProteusError {
       SessionNotFound,
       DuplicateMessage,
       RemoteIdentityChanged,
       Other(Int),
   }
  
   pub enum MlsError {
       ConversationAlreadyExists,
       DuplicateMessage,
       BufferedFutureMessage,
       WrongEpoch,
       MessageEpochTooOld,
       SelfCommitIgnored,
       UnmergedPendingGroup,
       StaleProposal,
       StaleCommit,
       Other(String)
   }
   ```

### Features

- include the message of the source error when bundling errors together [WPB-14614] (16bc6e6)
- refactor non-WASM error types (9d41c11)
- proteus error codes are `Option<u16>` not `u32` outside wasm also (52547a0)
- refactor WASM error types (31c860a)
- proteus error codes are `Option<u16>` not `u32` (838c1ce)
- add logging for following the changes in mls groups WPB-11544 (8cc0e7f)
- support logs with a context of key/value pairs (b6ef534)
- disambiguate `WrongEpoch` [WPB-14351] (e6a5e01)
- support changing the logger and log level at runtime WPB-11541 (cd071f0)
- add helper to extract data from within a transaction (c852363)
- relax `Debug` trait bound on `CoreCryptoCommand` and add Rust helper [WPB-12132] (e952a0f)

### Bug Fixes

- bump ios deployment target to 15.0 to fix linker issue (1327b1b)
- improve errors when hitting an idb error during IndexedDB migration (0c0c954)
- don't obfuscate rexie error in keystore v1.0.0 (6ed43e6)
- improve errors when hitting a indexdb error during cryptobox migration (682bd9a)
- build without error without default features (97e2d24)

### Documentation

- improve platform-specific test instructions (a08a3b2)
- improve naming and documentation for `TransactionHelper` (e8b4756)

### Testing

- cause jvm kotlin tests to pass (3b8d930)
- fixup tests broken by recent changes (59db9ed)
- change test for build metadata to achieve closer parity with the kotlin test (ffd4e02)
- use wdio where `bun test` was used previously (9c67569)
- use util functions, migrate tests from puppeteer to wdio [WPB-12176] (fbff47a)
- add test util functions [WPB-12176] (196c877)
- crypto: use world.com instead of wire.com [WPB-14356] (6edcef7)
- crypto: use explicit functions to create certificate bundles [WPB-14356] (c52b9b6)
- crypto: remove From impls for CertificateBundle [WPB-14356] (2f59009)
- add js test for for logs with context data (600ba7c)
- add test that build metadata is available in kotlin via uniffi (87c3ab9)
- add test that build metadata is available in ts (4aa18e6)
- add js binding test verifying that we can replace a logger (30d9db7)
- update js tests after renaming initLogger to setLogger (1c1c949)

## v1.1.2 - 2024-11-27

### Bug Fixes

- improve errors when hitting an idb error during IndexedDB migration (8512391)
- don't obfuscate rexie error in keystore v1.0.0 (3896bab)


## v1.1.1 - 2024-11-26

### Bug Fixes

- Improve errors when hitting an indexdb error during cryptobox migration (3266550)


## v1.1.0 - 2024-11-12

### Highlights

- Transactions are now exposed on `CoreCrypto`, opening the door to substantially improve performance by batching operations.

### Features

- implement set_data() and get_data() on context [WPB-10919] (7e88695)
- implement in-memory cache on transaction (427e0e0)
- create a keystore transaction struct to be used in the context (4c3f487)
- add decode cli tool (6f83796)
- decouple idb version from crate version (06312fe)
- implement idb migration for all remaining entities [WPB-10144] (545b376)
- implement idb migration for one entity [WPB-10144] (32fd279)
- change aad format [WPB-10108] (8e0b7e5)

### Bug Fixes

- avoid spaces in kotlin test names (1e53e64)
- EntityFindParams SQL clause ordering (a768db4)

### Documentation

- README.md: add a note regarding sed on macOS (b8f2f55)
- README.md: replace xtask usage with the update-versions.sh script (59f2530)
- README.md: update release instructions (b63f17d)
- regenerate CHANGELOG.md with plain git-cliff (e02621f)
- remove CHANGELOG.tpl (8a47ba5)
- update README.md (3eba7b3)

### Testing

- add js binding test verifying that we log errors thrown by the logger (1b959e2)
- add js bindning wrapper test for logger (0005d1d)
- fix jvm tests [WPB-11668] (98ce97e)
- add test for upgrading from basic to x509 credentials (9da3b88)
- test migrations for all entities (48ea746)
- factor out random method into its own trait (8fd49b0)
- interop: make sure that there exists platforms/web/index.html (d9fe1c9)
- crypto-ffi: move index.html contents into a separate file (2dab8bf)
- include E2eiEnrollment and MlsEpochEncryptionKeyPair in tests (0e5a466)


## v1.0.2 - 2024-08-16

### Bug Fixes

- run ci to generate junit report on tags [WPB-10608] (5f93f21)
- grouping were randomly failing because it expected query to be ordered (23f5ff8)

### Testing

- add cross signing tests [WPB-7264] (04f6203)
- add utilities to cross sign certificate chains (3aa7ca2)


## v1.0.1 - 2024-08-05

### Bug Fixes

- get_or_create_key_packages() must respect credential type [WPB-10294] (23081e6)
- handle own commit after mls error [WPB-10105] (aadd06c)

### Testing

- test handling invalid own commit (801f3b8)


## v1.0.0 - 2024-07-18

### Features

- add log level to the callback [WPB-7260] (#600) (c9f44fd)
- Expose logging to public API [WPB-7260] (#560) (180de78)
- crypto-ffi: add bindings for conversation_ciphersuite (4d4dd86)
- crypto: mls: add a way to get the conversation ciphersuite (2e887f1)
- Add logging capabilities to CoreCrypto [WPB-7260] (db53683)

### Bug Fixes

- change the log output to json (956a22d)

### Documentation

- add info about bench execution to README.md, add some benchmark descriptions (ca4dde4)
- FFI.md: add instructions on how to add new API to bindings [WPB-9175] (cd2a288)
- README.md: add more documentation on how we work and release [WPB-9172] (db5d94f)
- README.md: update bindings instructions (0a9d2ac)
- document crates (52646f5)

### Testing

- crypto: box the future so we don't blow up the stack (833d7e6)
- crypto: bring back external remove proposal tests (WPB-9184) (9ede2e7)
- pin future to heap in test with overflowing stack [WPB-9543] (24efdbf)
- crypto-ffi: add a test for conversation ciphersuite getter (5e9ecf7)


## v1.0.0-rc.60 - 2024-05-06

### Bug Fixes

- Ciphersuite being ignored on WASM createConversation (581954b)


## v1.0.0-rc.59 - 2024-05-02

### Bug Fixes

- Support legacy external senders with ECDSA (62f9e17)


## v1.0.0-rc.58 - 2024-04-30

### Bug Fixes

- Avoid lock reentrancy on Generic FFI's conversation_create causing deadlocks (71165f2)
- Use Mozilla's hack to fix Android on x86_64 (2064b1e)


## v1.0.0-rc.57 - 2024-04-25

### Bug Fixes

- Convert TS enums to their discriminant repr (8a480ce)


## v1.0.0-rc.56 - 2024-04-22

### Features

- support JWK external sender and fallback to the previous format (8a1981c)
- Support for P521 (2be007f)

### Bug Fixes

- e2ei signature key translation was not working for P384 & P521. Also cleaned the conversion methods (563f0f3)


## v1.0.0-rc.55 - 2024-03-28

### Features

- [**breaking**] borrow enrollment instead of requiring ownership (e700ac5)
- MLS thumbprint has hash algorithm agility (8d5d282)
- [**breaking**] WireIdentity now also wraps Basic credentials (55b75fe)
- [**breaking**] introduce `e2ei_verify_group_state` to preemptively check a group state through its GroupInfo before joining it (09f8bbd)


## v1.0.0-rc.54 - 2024-03-20

### Bug Fixes

- Correctly handle new CRL DPs in add_members (e573f5e)


## v1.0.0-rc.53 - 2024-03-15

### Bug Fixes

- MLS credential verification should ignore expired certificates (d53edef)


## v1.0.0-rc.52 - 2024-03-14

### Bug Fixes

- Correctly handle new CRL DPs (d3e0b84)


## v1.0.0-rc.51 - 2024-03-13

### Bug Fixes

- Various tweaks and fixes for revocation [WPB-6904] (e55c37d)
- refresh time of interest in the PKI env before querying device/user identities (c4a3140)


## v1.0.0-rc.49 - 2024-03-11

### Bug Fixes

- Misc improvements (7d8ea56)
- Remove unique index on SignatureKeypair.pk (4301ac4)
- catch the "NoMatchingEncryptionKey" error from openmls and also return a "OrphanWelcome" one (4990be7)


## v1.0.0-rc.48 - 2024-03-07

### Bug Fixes

- deduplicate CRL DPs (5b8815b)

### Testing

- Add test to assert that a basic client can join a verified conversation (cec3281)
- Add test to assert that revocation works properly (a28c8f6)


## v1.0.0-rc.47 - 2024-03-04

### Features

- Upload unit test results in junit format (WPB-6928) (11e2839)

### Bug Fixes

- check revocation in status (b3857a4)
- Don't create an empty PKI env on restore (4a50632)

### Testing

- remove ignore (and not relevant anymore) test (40fb405)


## v1.0.0-rc.46 - 2024-02-28

### Bug Fixes

- rollback handling of e2ei deactivation since it creates issues in the regular case (6821328)


## v1.0.0-rc.44 - 2024-02-27

### Bug Fixes

- only restore PKI env if client is e2ei capable. This helps client developers when e2ei is turned off (a37b387)


## v1.0.0-rc.43 - 2024-02-22

### Bug Fixes

- Update deps for wasm-browser-run (0b9aae6)

### Testing

- fix joining by external commit test (918c6dc)


## v1.0.0-rc.41 - 2024-02-21

### Bug Fixes

- Remove cached is_e2ei_capable flag (02fde65)
- KeyPackage lifetime validation when receiving messages (b998d03)
- Integrate -pre version to iDB store version (5992227)


## v1.0.0-rc.40 - 2024-02-20

### Bug Fixes

- TS mapping of identities was using experimental methods (487de51)


## v1.0.0-rc.39 - 2024-02-20

### Features

- add serialNumber, notBefore & notAfter in `WireIdentity` object (1a8e092)
- add display name in dpop token (d9891ac)

### Bug Fixes

- Harden x509 validation & revocation checks (8984fc5)

### Documentation

- update all doc warnings including a lot of broken links (e79f99d)

### Testing

- verify that registering a TA twice fails (115e87a)


## v1.0.0-rc.38 - 2024-02-16

### Features

- add getter for external sender to seed subconversations (2b423b1)

### Bug Fixes

- intermediates were not registered during enrollment (da231e5)


## v1.0.0-rc.37 - 2024-02-15

### Features

- [**breaking**] `clientPublicKey` now also works for x509 credentials (60a6889)
- Validate x509 credentials when introduced (b2dbb43)

### Bug Fixes

- [**breaking**] Add dedicated error for stale commits and proposals (bede132)
- verify GroupInfo (52e0fb0)
- Allow revoked Credentials in MLS operations (b5fe5c3)
- Reenable E2EI tests (d71155a)
- Update tests (d898ad8)
- post-rebase fixes (b872550)
- Consider x509 credentials as always valid if no PKI environment is available (df72c15)
- Adapt calls to OpenMLS new async methods (d2f1f3f)
- Disable non working (MissingSki) E2EI tests (ea0f70a)
- Undo WASM binding API mistake (aa3edbc)

### Testing

- Get rid of rcgen-based x509 cert generation (01621a3)


## v1.0.0-rc.35 - 2024-01-29

### Features

- [**breaking**] return CRL Distribution Points when registering intermediate certificates (30dced5)

### Bug Fixes

- register intermediate certificates at issuance since they're not fetchable afterwards (b2b3399)


## v1.0.0-rc.34 - 2024-01-25

### Features

- [**breaking**] change certificate expiry from days to seconds in the public API (fe1ad71)


## v1.0.0-rc.33 - 2024-01-24

### Features

- filter out root CA when registering intermediates in case the provider repeats it (db0d451)
- [**breaking**] remove refreshToken handling from WASM altogether as it is not used (1d84dbb)

### Bug Fixes

- restore pki_env from disk whenever necessary (0af2919)
- relax uniqueness constraint on intermediate certificates and CRLs on sqlite (1c333e9)


## v1.0.0-rc.32 - 2024-01-23

### Features

- Add full PKI test harness (8090577)

### Bug Fixes

- Remove unused test (9e06774)
- Use forked x509-cert to fix WASM compilation (71cbe16)
- Fix tests (4ba3b37)
- Duration overflow in x509 expiration setting (f13bcb8)
- Typo in E2eiAcmeCA registration SQL query (613f8f8)
- Add missing CRLDP field to FFI + fill it up (6c61edf)


## v1.0.0-rc.31 - 2024-01-22

### Bug Fixes

- use 2 acme authorizations instead of 1 (8313977)


## v1.0.0-rc.30 - 2024-01-17

### Features

- [**breaking**] expose keyauth in ACME authz (67f5bb4)

### Bug Fixes

- wrong rusty-jwt-tools pinned in rc30 (a6326b7)


## v1.0.0-rc.29 - 2024-01-16

### Bug Fixes

- pin rusty-jwt-tools v0.8.4 fixing an issue with the wrong signature key being used for the client DPoP token (24fabf9)


## v1.0.0-rc.28 - 2024-01-15

### Bug Fixes

- actually fix keyauth issue (cefed75)


## v1.0.0-rc.27 - 2024-01-15

### Bug Fixes

- use rusty-jwt-tools v0.8.1 which fixes the keyauth issue (d57ff1c)


## v1.0.0-rc.26 - 2024-01-15

### Bug Fixes

- previous fix was not compiling (46f5a01)


## v1.0.0-rc.25 - 2024-01-15

### Bug Fixes

- e2ei keystore method 'find_all' was unimplemented on WASM for intermediate CAs & CRLs (4164adb)


## v1.0.0-rc.24 - 2024-01-15

### Features

- Added support for PKI environment (9478ff5)
- change ClientId & Handle format to URIs (ab62648)

### Bug Fixes

- Pin e2ei package tag (28fc908)
- Add PKI API to bindings (6e88c3e)


## v1.0.0-rc.23 - 2024-01-08

### Features

- [**breaking**] remove PerDomainTrustAnchor extension altogether. Backward incompatible changes ! (be4edd4)

### Bug Fixes

- null pointer in Javascript when calling 'new_oidc_challenge_response' (806ce08)
- Swift wrapper for E2eiEnrollment was not used in other methods (a7ff1d1)
- use 'implementation' Gradle configuration not to enforce dependencies version into consumers. Fixes #451 (48b3fc2)


## v1.0.0-rc.22 - 2023-12-13

### Features

- [**breaking**] remove 'clientId' from activation & rotate enrollment now that we expect a specific ClientId format (9f1a6dc)
- [**breaking**] add `get_credential_in_use()` to check the e2ei state from a GroupInfo (5508dc5)
- [**breaking**] rename `E2eiConversationState::Degraded` in to `E2eiConversationState::NotVerified` (151c5c4)
- [**breaking**] managed OIDC refreshToken (wpb-5012) (62ed3a3)

### Bug Fixes

- README mentions a task which doesn't exist (#445) (68c7a63)
- remove unnecessary boxing of values before persisting them in IndexedDb (82eac29)

### Testing

- verify that clients can create conversation with x509 credentials (f089a03)


## v1.0.0-rc.21 - 2023-12-05

### Features

- [**breaking**] canonicalize ClientId keeping only the regular version where the UserId portion is the hyphenated string representation of the UUID. Also apply this to 'getUserIdentities()' (4ea3a1c)


## v1.0.0-rc.20 - 2023-12-04

### Features

- better errors: 'ImplementationError' was way too often used as a fallback when the developer was too lazy to create a new error. This tries to cure that, especially with e2ei errors. It also tries to distinguish client errors from internal errors (e16624f)
- [**breaking**] simplify API of 'add_clients_to_conversation' by not requiring to repeat the ClientId of the new members alongside their KeyPackage when the former can now be extracted from the latter (3c85678)
- [**breaking**] introduce handle & team in the client dpop token (ac6b87e)

### Testing

- test DB migration from 0.9.2 (9c1e201)


## v1.0.0-rc.19 - 2023-11-20

### Testing

- Add new keystore regression test to CI (2714259)
- Test keystore migration regressions (b040f01)


## v1.0.0-rc.18 - 2023-11-14

### Bug Fixes

- Preserve schema upgrade path between schemafix'd versions and upcoming (1308cfe)


## v1.0.0-rc.17 - 2023-10-30

### Bug Fixes

- Don't depend on OpenSSL on WASM (cda1209)
- dynamic linking issue on Android with the atomic lib (19808e2)


## v1.0.0-rc.16 - 2023-10-12

### Features

- Switch from node to bun (3c6caf9)

### Bug Fixes

- Prevent CI from overriding RUSTFLAGS (c2aa638)
- Added missing d.ts declarations (4a77bad)
- KP test was taking too much time (5e7bae5)

### Documentation

- Updated README.md noting Bun usage (aedbac2)


## v1.0.0-rc.15 - 2023-10-11

### Features

- re-export e2ei types (f765df8)

### Bug Fixes

- add '-latomic' flag when building for Android to dynamically link atomic lib which is supposedly causing issues with openssl (4a100ab)


## v1.0.0-rc.14 - 2023-10-09

### Bug Fixes

- backward incompatible database schemas. It only preserves Proteus compatibility when migrating from CC 0.11.0 -> 1.0.0. For anything MLS-related it is recommended to wipe all the groups (4c95713)


## v1.0.0-rc.13 - 2023-09-27

### Features

- [**breaking**] make initial number of generated KeyPackage configurable (dcd3dc3)
- add e2ei ffi in Swift wrapper (fbd38a9)
- [**breaking**] add LeafNode validation (49caeb8)

### Bug Fixes

- do not reapply buffered messages when rejoining with external commit (2df2d04)
- coarsetime issue causing compilation error on WASM (9585594)

### Testing

- try fixing flaky time-based LeafNode validation tests (5b9f014)


## v1.0.0-rc.12 - 2023-08-31

### Bug Fixes

- use sed in a cross-platform way for kt edits (698fda9)


## v1.0.0-rc.11 - 2023-08-31

### Bug Fixes

- [**breaking**] UniFFI Errors (568bdf3)


## v1.0.0-rc.10 - 2023-08-31

### Bug Fixes

- UniFFI symbol matching (205b8b0)


## v1.0.0-rc.9 - 2023-08-30

### Features

- [**breaking**] return raw PEM certificate in `getUserIdentities` for display purpose (cd6e768)
- [**breaking**] bump rusty-jwt-tools to v0.5.0. Add 'revokeCert' to AcmeDirectory (a8316b3)

### Bug Fixes

- Make UniFFI produce the correct symbol in bindings (9b5ec44)
- change e2ei enrollment identifier causing collision now that keypairs are reused (3e2639c)

### Documentation

- regenerate changelog (a1525e2)


## v1.0.0-rc.8 - 2023-08-25

### Features

- expose `getUserIdentities` through the FFI (6eeb571)
- [**breaking**] also restore buffered messages on the receiver side (a552197)
- increase max past epoch to 3 since backend inordering of messages requires client's config to backend's one + 1 (1d35364)

### Bug Fixes

- TLS serialization of x509 credential (124d7b3)
- [**breaking**] UniFFI Async cancellable routines + bytes (05d660a)
- Make interop runner pick up CHROME_PATH from env (3c4ed23)

### Testing

- fix wasm test hitting a limit. Just split them for now, waiting for a proper solution (1b68f7e)
- fix spinoff 0.8 compilation (4b9987e)


## v1.0.0-rc.7 - 2023-08-09

### Features

- correlate RotateBundle with a GroupId (0077dbe)

### Bug Fixes

- kotlin tests not compiling after methods became async (7f7e015)


## v1.0.0-rc.6 - 2023-08-08

### Features

- [**breaking**] handle the case when a client tries to decrypt a Welcome referring to a KeyPackage he already has deleted locally (ce6e71e)
- Add keystore dump exporter CLI tool (fb0f65d)

### Bug Fixes

- `e2eiRotateAll` return type was not wrapped (7d77b7e)
- Signature KeyPair was rotated when credentials were which was zealous. Also fixes an important bug caused by inverted private & public keypair part when rotating credentials (f607138)

### Testing

- add a roundtrip test for e2ei credential rotation to tackle a false positive regression (52bfa04)


## v1.0.0-rc.5 - 2023-07-31

### Bug Fixes

- e2ei enum for conversation state was unused and failing the Typescript publication. Now CI will have the same compiler flags when checking bindings in order to prevent this again (3744e93)


## v1.0.0-rc.3 - 2023-07-31

### Features

- [**breaking**] rename `e2eiIsDegraded` by `e2eiConversationState` and change return type to an enumeration instead of a boolean to match all the e2ei states a conversation could have. (e7404d8)
- add `e2ei_is_enabled` for clients to spot if their MLS client is enrolled for end-to-end identity (1521ad7)

### Bug Fixes

- Proteus wasm test now uses wasm-browser-run (712e959)
- cargo doc fixes for wasm-browser-run (1455b0e)
- Interop runner now uses wasm-browser-run to install chromedriver (07e6bcc)
- Support chromedriver 115 delivery method (1e2939f)
- `e2ei_rotate_all` was returning 'undefined' on WASM (fdee4c0)
- [**breaking**] entities leaked. Some methods handling the lifecycle of a MLS group were not cleaning created entities correctly. This avoids required storage space to grow linearly. (51a7e13)


## v1.0.0-rc.2 - 2023-07-25

### Features

- [**breaking**] expose 'ClientId' in e2ei methods for credential rotation since the e2ei client identifier differs from the one used in MLS (d687ae3)
- Include certificate roots and certificate policy in GroupContext - WPB-1188 (2ef9892)


## v1.0.0-rc.1 - 2023-07-21

### Features

- buffer pending messages during join by external commit process to tolerate unordered messages (3f20913)
- Use -dalek fast proteus version (2196b23)
- Use RFC9420 OpenMLS [WPB-579] (b7c18cd)

### Bug Fixes

- `merge_pending_group_from_external_commit` FFI incorrect return type (bfd5eed)
- UniFFI bindgen requirements & size tweaks (a9983ff)
- Address review comments (d878bcb)
- Revert bloating up binaries by emitting crate-type=lib (80ae18b)
- Strip mobile libraries (694eebf)
- handles nicely self-commits (4bcb77c)

### Documentation

- Add document to detail our crypto primitives (a149986)


## v1.0.0-pre.8 - 2023-07-18

### Bug Fixes

- use correct env var for maven central credentials (#355) (38207e2)


## v1.0.0-pre.7 - 2023-07-17

### Features

- [**breaking**] prevent conversation overwrite when joining (3149f97)
- [**breaking**] detect duplicate messages from previous epoch and fail with a dedicated error (e8c2588)
- publish to Sonatype instead of Github Packages (#347) (7167bf5)

### Bug Fixes

- make clippy happy (c4fac26)
- xtask release fix for kotlin sonatype publishing (f3649ba)
- Disable stripping to allow FFI to build (1d173ce)
- Incorrect error value in tests (6c9888c)


## v1.0.0-pre.6 - 2023-07-06

### Features

- [**breaking**] credential rotation (fa32918)
- PostQuantum Ciphersuite (ea7a8c6)
- [**breaking**] remove `export_group_info()` (4525084)

### Bug Fixes

- Wrong HPQ ciphersuite identifier (7c2d982)
- Address review & de-flakify cert expiration test (3083771)
- Target correct branches (b2b65a6)
- PQ support for FFI (653f8bc)
- Benches modification (c724f3b)


## v1.0.0-pre.5 - 2023-06-12

### Bug Fixes

- backend sends raw GroupInfo, we were trying to deserialize it from a MlsMessage (5944f84)


## v1.0.0-pre.3 - 2023-06-09

### Bug Fixes

- pin a version of openmls with a fix in tls_codec related to variable length encoding (2a50f8e)

### Testing

- fix external commit test was not merging the external commit (457e796)


## v1.0.0-pre.2 - 2023-06-09

### Bug Fixes

- typo in build xcframework task (bca3660)


## v1.0.0-pre.1 - 2023-06-09

### Features

- CoreCrypto draft-20 upgrade (4e7d907)
- generate XCFramework when releasing for Swift (#330) (19fd4c0)


## v0.11.0 - 2023-06-01

### Features

- add `e2ei_is_degraded` to flag a conversation as degraded when at least 1 member is not using a e2ei certificate (f39a868)


## v0.10.0 - 2023-05-25

### Features

- [**breaking**] hide everywhere `Vec<Ciphersuite>` appears in the public API since it seems to fail for obscure reasons on aarch64 Android devices. Undo when we have a better understanding of the root cause of this (08584e8)

### Bug Fixes

- usize to u64 conversion error on Android in `client_valid_keypackages_count`. Whatever the reason this applies a default meaningful value (2d90576)
- [**breaking**] creating a MLS group does not consume an existing KeyPackage anymore, instead it always generates a new local one. Also, explicitly ask for the credential type of the creator before creating a new MLS group. (254e336)
- mobile FFI was failing when initializing MLS client due to a Arc being incremented one too many times. Also add the E2EI API in the Kotlin wrapper and a test for it (e0a5dcb)


## v0.9.2 - 2023-05-22

### Bug Fixes

- new table was mistakenly in an old migration file (e65d91c)


## v0.9.1 - 2023-05-17

### Bug Fixes

- Size regression on FFI (5cb463b)


## v0.9.0 - 2023-05-16

### Features

- add persistence options to e2ei enrollment instance (e3ace8d)
- [**breaking**] enable multi ciphersuite and multi credential type support (f5e5714)
- [**breaking**] support & expose "target" in ACME challenges (1a77795)

### Bug Fixes

- Reload proteus sessions when `restore_from_disk` is called (c0828b0)
- return finalize & certificate url (448bff0)

### Testing

- have interop runner verify the generic FFI (a00f73c)


## v0.8.1 - 2023-04-27

### Bug Fixes

- native libraries not included in android package (#308) (73d9a3e)
- typescript path has the wrong file extension (#309) (af1ee13)


## v0.7.0 - 2023-04-12

### Features

- verify x509 credential identity and return identity (client_id, handle, display_name, domain) once message is decrypted (45787f4)

### Bug Fixes

- Fixed iOS keychain handling with proper attributes (1f2af04)


## v0.7.0-rc.4 - 2023-03-28

### Features

- remove any transitive crate using ring. As a consequence supports EcDSA on WASM (1588676)
- copy/modify kotlin wrapper from Kalium (#284) (b96507e)
- [**breaking**] support creating a MLS client from an e2e identity certificate (f12dcf9)

### Bug Fixes

- [**breaking**] Tweak WASM API (a3ebfcb)
- use schnellru fork for GroupStore faillible inserts (cdf337c)
- Fixed GroupStore memory limiter behavior (97c9fc5)


## v0.7.0-rc.3 - 2023-03-16

### Bug Fixes

- Proteus auto prekey ids not incrementing (50603e7)


## v0.7.0-rc.1 - 2023-03-15

### Features

- [**breaking**] latest e2e identity iteration. ClientId (from MLS) is used instead of requiring just parts of it (fba4323)
- Added API to check the `Arc` strongref counter (d25a569)
- [**breaking**] Add ability to mark subconversations (e7ed3e0)
- [**breaking**] Change proteus auto prekey return type to include prekey id (f99c458)
- [**breaking**] Added LRU cache-based underlying group store to replace the HashMaps (3d4dd38)

### Bug Fixes

- [**breaking**] Make FFI parameters compliant with rfc8555 (df2e4f1)
- Added missing version() function to Swift bindings (2366539)
- enable ios-wal-compat for iOS builds by default (f8003c1)
- Exclude self from self-remove-commit delay (8378510)
- Fix rustsec advisories on xtask deps (2cf29e6)


## v0.6.2 - 2023-02-16

### Bug Fixes

- Fixed commitDelay being undefined when FFI says 0 (9a81d54)


## v0.6.1 - 2023-02-16

### Bug Fixes

- publishing for JVM generating empty artifacts (#251) (70b9d90)
- Fall back on false when the callback doesn't retrurn a Promise (6db3147)
- Proteus auto prekey might overwrite Last Resort prekey (2e4c5b5)


## v0.6.0 - 2023-02-13

### Features

- adapt with acme client library tested on real acme-server forked. Also some nits & dependencies pinned (efac714)

### Bug Fixes

- xtask release outputs dry-run log unconditionally (9f5d35b)


## v0.6.0-rc.8 - 2023-02-09

### Features

- Added support for Proteus Last Resort PreKeys (boooo!) (8bac78f)
- [**breaking**] Async callbacks (96ad897)
- Externally-generated clients (457ee28)


## v0.6.0-rc.7 - 2023-02-06

### Bug Fixes

- Fixed E2E interop test for breaking api changes (6b3030c)
- New e2eidentityerror enum member wasn't exposed over ffi (35ea9e5)
- TS/WASM build issues & test (9d2bef8)


## v0.6.0-rc.6 - 2023-02-02

### Bug Fixes

- Proteus error system not working (at all) (814590c)
- Force cargo to use git cli to avoid intermittent CI failures (3f9a60c)


## v0.6.0-rc.5 - 2023-01-25

### Features

- Added support for Proteus error codes (20c75df)

### Bug Fixes

- [**breaking**] Added conversation id to clientIsExistingGroupUser callback (b380d3f)
- Increment IndexedDB store version when crate version changes (d3f960c)


## v0.6.0-rc.4 - 2023-01-20

### Features

- expose end to end identity web API (dad51e9)
- add end to end identity bindings (a96a8b6)

### Bug Fixes

- aarch64-apple-ios-sim target not compiling  (#213) (93f47c2)
- Cryptobox import now throws errors on missing/incorrect store (e897a60)


## v0.6.0-rc.3 - 2022-12-15

### Bug Fixes

- Added missing Proteus APIs and docs (8ee833e)


## v0.6.0-rc.2 - 2022-12-15

### Bug Fixes

- Functional Android NDK 21 CI (0d70f29)
- Publish android CI (470ec4f)
- unreachable pub makes docs build fail (4a29191)


## v0.6.0-rc.1 - 2022-12-15

### Features

- expose a 'WrongEpoch' error whenever one attempts to decrypt a message in the wrong epoch (fc87a6f)
- add 'restore_from_disk' to enable using multiple MlsCentral instances in iOS extensions (541674a)
- add specialized error when trying to break forward secrecy (b638a0e)
- add 'out_of_order_tolerance' & 'maximum_forward_distance' to configuration without exposing them and verify they are actually applied (838fb62)
- [**breaking**] change 'client_id' in CoreCrypto constructor from a String to a byte array to remain consistent across the API (e89cbf9)
- Expose proteus prekey fingerprint - CL-107 (09e685d)

### Bug Fixes

- Broken Proteus implementation (f0dc510)
- prevent application messages signed by expired KeyPackages (cfe1837)
- Fix cryptobox import on WASM [CL-119] (c55ec39)
- Incorrect TS return types [CL-118] (89d1e14)

### Testing

- ensure we are immune to duplicate commits and out of order commit/proposal (96a6af8)


## v0.6.0-pre.5 - 2022-11-10

### Features

- Expose proteus session fingerprints (local and remote) - CL-108 (6821800)
- support deferred MLS initialization for proteus purposes [CL-106] (5f20e89)


## v0.6.0-pre.4 - 2022-11-07

### Features

- Expose session exists through the ffi - CL-101 (40f8b5b)

### Bug Fixes

- [**breaking**] Incorrect handling of enums across WASM FFI (dae9a0a)
- commits could lead to inconsistent state in keystore in case PGS serialization fails (95d3d6a)
- Make tags have semantic versioning names and downgrading to swift 5.5 - CL-49 (81c32b8)
- Publication of swift packages (cd80cac)

### Testing

- ensure everything keeps working when pure ciphertext format policy is selected (579c752)


## v0.6.0-pre.3 - 2022-11-01

### Bug Fixes

- Change the internal type of the public group info to Vec<u8> so we don't have extra bytes in the serialized message - FS-1127 (2ee4e18)


## v0.6.0-pre.1 - 2022-10-21

### Features

- [**breaking**] expose a 'PublicGroupStateBundle' struct used in 'CommitBundle' variants (a9bfe56)
- [**breaking**] remove all the final_* methods returning a TLS encoded CommitBundle (62212ad)
- Returning if decrypted message changed the epoch - CL-92 (#152) (a4d4661)
- Exporting secret key derived from the group and client ids from the members - CL-97 - CL-98 (#142) (b8bfa8a)
- Added API to generate Proteus prekeys (cee049a)
- Fixed Cryptobox import for WASM (30d5140)
- Added support for migrating Cryptobox data (f6a3da8)
- Added FFI for CoreCrypto-Proteus (01b0ee5)
- Added support for Proteus (9743949)
- validate received external commits making sure the sender's user already belongs to the MLS group and has the right role (f70ff30)
- [**breaking**] rename callback~~`client_id_belongs_to_one_of`~~ into `client_is_existing_group_user` (36e34ca)
- [**breaking**] external commit returns a bundle containing the PGS (54ba6f5)
- [**breaking**] add `clear_pending_group_from_external_commit` to cleanly abort an external commit. Also renamed `group_state` argument into `public_group_state` wherever found which can be considered a breaking change in some languages (b5db441)
- [**breaking**] rename `MlsConversationInitMessage#group` into `MlsConversationInitMessage#conversation_id` because it was misleading about the actual returned value (9ed7025)

### Bug Fixes

- 'join_by_external_commit' returns a non TLS serialized conversation id (eaa22e4)

### Testing

- fix external commit tests allowing member to rejoin a group by external commit (30641a7)
- add a default impl for 'TestCase', very useful when one has to debug on IntelliJ (d228e39)
- parameterize ciphers (b196450)
- ensure external senders can be inferred when joining by external commit or welcome (46287fa)
- fix rcgen failing on WASM due to some unsupported elliptic curve methods invoked at compile time (eea14db)
- ensure external commit are retriable (7fee252)


## v0.5.2 - 2022-09-27

### Bug Fixes

- wire-server sends a base64 encoded ed25519 key afterall. Consumers are in charge of base64 decoding it and pass it to core-crypto (5d8c480)
- TS Ciphersuite enum not correctly exported (dcbbea6)

### Documentation

- add installation instructions for e2e runner on macos (3271adf)


## v0.5.1 - 2022-09-21

### Bug Fixes

- incorrect null handing in Typescript wrapper for 'commitPendingProposals' (5623214)
- external_senders public key was not TLS deserialized causing rejection of external remove proposals (a8b6124)

### Documentation

- better explanation of what DecryptedMessage#proposals contains (0e2ebfa)


## v0.5.0 - 2022-09-14

### Features

- [**breaking**] 'commit_pending_proposals' now returns an optional CommitBundle when there is no pending proposals to commit (9a7fd84)

### Bug Fixes

- NPM publish workflow missing npm ci + wrong method names in TS bindings (c215d61)
- NPM publish workflow missing npm i (ffb1480)
- rollback openmls & chrono in order to release 0.5.0 (d242532)
- pin openmls without vulnerable chrono (0af35df)
- wee_alloc memory leak + NPM publish issue (f937b18)
- Unreachable pub struct breaks docgen (02d7c16)
- Fixed iOS SQLCipher salt handling within keychain (5e32ad9)
- [**breaking**] Changed misleading callback API and docs (bd25518)
- [**breaking**] Added missing TS API to set CoreCrypto callbacks (74c429d)
- force software implementation for sha2 on target architectures not supporting hardware implementation (i686 & armv7 in our case) (baca163)

### Documentation

- add forgotten 0.4.0 changelog (699e071)


## v0.4.1 - 2022-09-01

### Bug Fixes

- uniffi breaking changes in patch release and ffi error due to unused `TlsMemberAddedMessages` (953ebb5)


## v0.4.0 - 2022-08-31

### Features

- commits and group creation return a TLS serialized CommitBundle. The latter also contains a PublicGroupStateBundle to prepare future evolutions (9215f3d)
- [**breaking**] 'decrypt_message' returns the sender client id (7665f9d)
- use 128 bytes of padding when encrypting messages instead of 16 previously (4a1f3d5)
- Add function to return current epoch of a group [CL-80] (#96) (fde8804)
- Adding a wrapper for the swift API and initial docs [CL-62] (#89) (59e07cf)
- add '#[durable]' macro to verify the method is tolerant to crashes and persists the MLS group in keystore (08e174b)
- expose 'clear_pending_commit' method (7aa5ada)
- allow rollbacking a proposal (67e45e7)
- [**breaking**] expose 'clear_pending_commit' method (72ff109)
- [**breaking**] allow rollbacking a proposal (641bcb4)

### Bug Fixes

- ensure durable methods are well tested and actually durable (912bdf9)

### Testing

- add reminder for x509 certificate tests (55578de)


## v0.3.0 - 2022-08-12

### Features

- review external add proposal validation and remove 'InvalidProposalType' error (f27c882)
- remove required KeyPackage when creating an external add proposal (93af490)
- remove commits auto-merge behaviour (e85f3c0)
- expose GroupInfo after commit operation (d822315)
- use draft-16 implementation of external sender. Expose a correct type through ffi for remove key (12fd96c)
- Add API to wipe specific group from core crypto [CL-55] (#81) (45d9757)
- Adding validation to external proposal [CL-51] (#71) (4fc74d0)
- decrypting a commit now also return a delay when there are pending proposals (983dce8)
- decrypting a commit now also return a delay when there are pending proposals (ae129ee)
- 'commit_delay' now uses openmls provided leaf index instead of computing it ourselves. It is also now infallible. (81913a0)
- ensure consistent state (a657d38)
- [**breaking**] add commit delay when a message with prending proposals is processed [CL-52] (#67) (2ee2827)
- Added KeyPackage Pruning (8ae3ab0)
- Added support for external entropy seed (16c913d)
- join by external commit support - CL-47 (#57) (4828cb6)
- Added Entity testing to keystore (9561c61)
- external remove proposal support (8b8df2e)
- supports and validates x509 certificates as credential (dfcb29d)
- expose function to self update the key package to FFI and Wasm #CL-17 (#48) (d9fdc8e)
- Added support for wasm32-unknown-unknown target (75a91f2)
- support external add proposal (c90aa0b)
- Added method to leave a conversation (bd72c3b)
- enforce (simple) invariants on MlsCentralConfiguration (9801387)
- expose add/update/remove proposal (34001c1)

### Bug Fixes

- Clippy fix impl eq (42ef44d)
- libgcc swizzling for android was removed (d198ca9)
- Cleaned up FFI names for clearer intent (de67752)
- Caught up WASM api with the internal API changes (76eeaac)
- doctests were failing because included markdown snippets were parsed and compiled (808446c)
- defer validation that a callback has to be set for validating external add proposal after incoming proposal identified as such (57edb3f)
- Updated RustCrypto dependencies to match hpke-rs requirements (5f7c08f)
- group was not persisted after decrypting an application message (d46d95d)
- UniFFI wrong type defs (1c033db)
- aes_gcm compilation issue (e6a69cc)
- WASM persistence & CoreCrypto Async edition (5044b7d)
- 'client_keypackages' does not require mutable access on 'mls_client' (4df44a4)
- add_member/remove_member IoError (7ac5422)
- Incorrect number of keypackages returned (7c456fa)
- Added support for MLS Group persistence [CL-5] (0c6f36a)

### Documentation

- Added bindings docs where appropriate + generated gh-pages (c966a42)
- fix Client struct documentation (30acb9a)
- Improving docs of Core-Crypto - [CL-50] (#60) (a9e772b)

### Performance

- avoid cloning conversation extra members when creating the former (0bf20d3)

### Testing

- add tests for 'commit_pending_proposals' (8198d66)
- verify that commit operation are returning a valid welcome if any (9458abf)
- use Index trait to access conversation from Central instead of duplicate accessor (7fc82b8)
- use central instead of conversation (321a60e)
- fix minor clippy lints in tests (dce4c2d)
- apply clippy suggestions on test sources (152d76b)
- reorganize tests in conversation.rs (0b8892f)
- nest conversation tests in dedicated modules (e94830f)
- verify adding a keypackage to a ConversationMember (05a5469)


## v0.2.0 - 2022-03-22

### Features

- add android project (614de7a)
- add tasks for building and copying jvm resources (719772b)
- add jvm project (29f82af)
- WIP hand-written ts bindings (ffcfe76)
- Generate Swift & Kotlin bindings 🎉 (72b8c5e)
- Updated deps (a99976b)
- Added salt in keychain management instead of flat AES-encrypted file (8a9ba96)
- Added WIP DS mockup based on QUIC (28f094f)
- Added ability to create conversations (!!!) (4469b3c)
- Added api support for in-memory keystore (19bb84a)
- Added in-memory faculties for keystore (5e41221)
- Added benches for the MLS key management (5207685)
- Added benches & fixed performance issues (d5ade0d)
- Added integration tests + fixes (df24f90)
- Implemented LRU cache for keystore (c10c080)
- Added support for Proteus PreKeys (88a19d0)
- Progress + fix store compilation to WASM (528d2ca)

### Bug Fixes

- set correct path to toolchain depending on platform & copy bindings (cab317d)
- Fix broken tests (d4bae6c)
- Tests fix (b2b15c5)
- Fixed iOS WAL behavior for SQLite-backed stores (f644e42)
- Fix Keystore trait having update method removed (5eeef67)
- clippy + fmt pass on core-crypto (a230b95)
- fmt + clippy pass (e979a2f)
- Migrations were incorrectly defined (d9a43a6)


