# Migrating from v10.3.0 or later to Unreleased

> [!NOTE]
> These changes will be relevant with the next release of CoreCrypto.

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
