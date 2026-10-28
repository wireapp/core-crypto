# Coming from v9

If you are still on CoreCrypto 9, you can upgrade straight to CC 11. Follow the
[CC 10 migration guide](https://wireapp.github.io/core-crypto/v10.5.3/cc-book/cc10/migration-guide.html) first, and then
the [CC 11 migration guide](migration-guide.md). Some steps in the CC 10 guide were changed again in CC 11, so you can
skip them or take a shorter path. This page lists those steps.

Upgrading straight to CC 11 also gets you the fixes for the v9 data migration. Some clients that upgraded from v9 to v10
lost credentials, and with them their conversations. CC 11 fixes this. See the [release notes](../release_notes.md) for
details.

## DecryptedMessage

In v10.3.0, `DecryptedMessage` changed from a struct with optional fields to an enum with `Text`, `Commit` and
`Proposal` variants. CC 11 renames `Text` to `ApplicationMessage` and adds three more variants. Skip the `Text` step and
go straight to the CC 11 enum, as shown in the [CC 11 migration guide](migration-guide.md#decryptedmessage).

The v9 fields map onto the variants as follows:

| v9 field                       | CC 11                                               |
| ------------------------------ | --------------------------------------------------- |
| `message`                      | `ApplicationMessage.plaintext`                      |
| `senderClientId`               | `ApplicationMessage.senderClientId`                 |
| `isActive`, `bufferedMessages` | `Commit.isActive`, `Commit.bufferedMessages`        |
| `commitDelay`                  | `Proposal.delay`                                    |
| `identity`                     | `identity` on every variant                         |
| `hasEpochChanged`              | removed in CC 10, use the `EpochObserver` interface |

## E2EI Checks

The CC 10 guide says that `e2eiIsPkiEnvSetup` can no longer throw. You can skip that step: CC 11 removes the function
completely, along with `e2eiIsEnabled`. Replace both v9 calls directly:

- `e2eiIsPkiEnvSetup`: call `getPkiEnvironment` and check whether it returns an environment.
- `e2eiIsEnabled`: call `findCredentials` and check whether an X509 credential for the cipher suite exists.

## TypeScript

### Imports

CC 10 moved the browser bindings to `@wireapp/core-crypto/browser`. In CC 11, `@wireapp/core-crypto` contains the
browser bindings again, so you can keep your v9 imports.

### Running outside the browser

If you ran the wasm bindings in Node or another non-browser runtime under v9, switch to `@wireapp/core-crypto-native`.
You don't need the `@wireapp/core-crypto/native` subpath from CC 10. The new package also installs its `@ubjs/core` and
`@ubjs/node` dependencies, so you don't need to add them yourself.

### Closing a Database

CC 10 removed `CoreCrypto.close()` and added `Database.close()`. CC 11 deprecates `Database.close()` again, because
database references are now destroyed when they are garbage-collected. Remove your v9 `close()` calls, and don't adopt
`Database.close()`. If you need to close a database explicitly without relying on the garbage collector, call
`uniffiDestroy()` on the `Database` instance and on any `CoreCrypto` or `PkiEnvironment` instance holding a reference to
it.

### Reseeding

CC 10 renamed `reseedRng()` to `reseed()`. In CC 11, `reseed()` also requires the seed to be exactly 32 bytes long. Make
both changes at once.
