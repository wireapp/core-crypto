# Migrating from v10.0 to Unreleased

> [!NOTE]
> These changes will be relevant with the next release of CoreCrypto.

## Database

1. Deprecated the `key` parameter from in-memory Database constructor. In-memory databases are never encrypted.

1. `Database.getLocation` now returns the absolute path to the database file for non-web platforms.

## DecryptedMessage

`DecryptedMessage` is now an enum with `Text`, `Commit`, and `Proposal` variants. Data that was previously exposed
through optional properties is now carried by the corresponding variant. Match on the variant before accessing its data:

<!-- langtabs-start -->

```typescript
if (DecryptedMessage.Text.instanceOf(decryptedMessage)) {
    const { plaintext, senderClientId, identity } = decryptedMessage.inner;
    // Handle the application message.
} else if (DecryptedMessage.Commit.instanceOf(decryptedMessage)) {
    // Handle the commit.
    const { isActive, bufferedMessages, identity } = decryptedMessage.inner;
} else if (DecryptedMessage.Proposal.instanceOf(decryptedMessage)) {
    const { delay, identity } = decryptedMessage.inner;
    // Handle the proposal.
}
```

```swift
switch decryptedMessage {
case let .text(plaintext, senderClientId, identity):
    // Handle the application message.
case let .commit(isActive, bufferedMessages, identity):
    // Handle the commit.
case let .proposal(delay, identity):
    // Handle the proposal.
}
```

```kotlin
when (decryptedMessage) {
    is DecryptedMessage.Text -> {
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
}
```

<!-- langtabs-end -->
