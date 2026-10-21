# Migrating from v10 to v11

This page covers changes that apply to all platforms. Some changes only affect one platform; they are covered on the
[TypeScript](migration/typescript.md), [Swift](migration/swift.md) and [Kotlin](migration/kotlin.md) pages.

## DecryptedMessage

`DecryptedMessage.Text` and `BufferedDecryptedMessage.Text` have been renamed to `DecryptedMessage.ApplicationMessage`
and `BufferedDecryptedMessage.ApplicationMessage`, respectively. Both enums now also include `Transient`,
`TransientTargeted` and `PersistedTargeted` variants. Match on all `DecryptedMessage` variants before accessing their
data:

<!-- langtabs-start -->

```typescript
if (DecryptedMessage.ApplicationMessage.instanceOf(decryptedMessage)) {
    const { plaintext, senderClientId, identity } = decryptedMessage.inner;
    // Handle the application message.
} else if (DecryptedMessage.Commit.instanceOf(decryptedMessage)) {
    const { isActive, bufferedMessages, identity } = decryptedMessage.inner;
    // Handle the commit.
} else if (DecryptedMessage.Proposal.instanceOf(decryptedMessage)) {
    const { delay, identity } = decryptedMessage.inner;
    // Handle the proposal.
} else if (DecryptedMessage.Transient.instanceOf(decryptedMessage)) {
    const { plaintext, senderClientId, identity } = decryptedMessage.inner;
    // Handle the transient message.
} else if (DecryptedMessage.TransientTargeted.instanceOf(decryptedMessage)) {
    const { plaintext, senderClientId, identity } = decryptedMessage.inner;
    // Handle the transient targeted message.
} else if (DecryptedMessage.PersistedTargeted.instanceOf(decryptedMessage)) {
    const { plaintext, senderClientId, identity } = decryptedMessage.inner;
    // Handle the persisted targeted message.
}
```

```swift
switch decryptedMessage {
case let .applicationMessage(plaintext, senderClientId, identity):
    // Handle the application message.
case let .commit(isActive, bufferedMessages, identity):
    // Handle the commit.
case let .proposal(delay, identity):
    // Handle the proposal.
case let .transient(plaintext, senderClientId, identity):
    // Handle the transient message.
case let .transientTargeted(plaintext, senderClientId, identity):
    // Handle the transient targeted message.
case let .persistedTargeted(plaintext, senderClientId, identity):
    // Handle the persisted targeted message.
}
```

```kotlin
when (decryptedMessage) {
    is DecryptedMessage.ApplicationMessage -> {
        val (plaintext, senderClientId, identity) = decryptedMessage
        // Handle the application message.
    }
    is DecryptedMessage.Commit -> {
        val (isActive, bufferedMessages, identity) = decryptedMessage
        // Handle the commit.
    }
    is DecryptedMessage.Proposal -> {
        val (delay, identity) = decryptedMessage
        // Handle the proposal.
    }
    is DecryptedMessage.Transient -> {
        val (plaintext, senderClientId, identity) = decryptedMessage
        // Handle the transient message.
    }
    is DecryptedMessage.TransientTargeted -> {
        val (plaintext, senderClientId, identity) = decryptedMessage
        // Handle the transient targeted message.
    }
    is DecryptedMessage.PersistedTargeted -> {
        val (plaintext, senderClientId, identity) = decryptedMessage
        // Handle the persisted targeted message.
    }
}
```

<!-- langtabs-end -->

## Other

1. `e2eiIsPkiEnvSetup` has been removed. You can call `getPkiEnvironment` to see if it is set.

1. `e2eiIsEnabled` has been removed. You can use `findCredentials` to check whether an X509 credential for a given
   cipher suite exists.

1. `proteusNewPrekey` is deprecated; use `proteusNewPrekeyAuto` instead.

1. `ClientId.deserialize` can now fail. Calling `deserialize` on history client ids throws a `CoreCryptoError`.

1. The documentation for `addCredential` previously stated that credentials registered with a single client must be
   distinct in credential type, signature scheme, and creation timestamp, and that you therefore had to wait a full
   second between registrations. This was never true of any released version; we fixed it before releasing 10.0.0. If
   you added a delay between `addCredential` calls to comply, you can remove it.

1. iOS, Android: `CoreCryptoContext.setData` is now a synchronous function, not async.
