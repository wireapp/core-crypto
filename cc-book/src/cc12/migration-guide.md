# Migrating from v11 to v12

The migrations in this file apply to all platforms. In addition, there are some migrations required for particular
platforms:

- [Typescript](migration/typescript.md)

## New `decrypt_message` API

- `DecryptedMessage.Commit` lost its `bufferedMessages` field; these messages now appear in the list returned by
  `decryptMessage`.
- `BufferedDecryptedMessage` no longer exists; remove any related helpers.
- The following errors have been converted to outcomes. Any `catch` blocks which existed only to suppress them must be
  deleted; those with behavior should be rewritten to trigger based on inspection of the outcomes.
  - `BufferedFutureMessage`
  - `BufferedCommit`
  - `UnmergedPendingGroup`
  - `DuplicateMessage`
  - `StaleCommit`
  - `StaleProposal`
  - `MessageEpochTooOld`
  - `WrongEpoch`

<!-- langtabs-start -->

```typescript
const outcomes = await ctx.decryptMessage(conversationId, messageBytes);
for (const outcome of outcomes) {
    // example: we care about buffered commits
    if (
        DecryptionOutcome.Deferred.instanceOf(outcome) &&
        DeferralReason.MissingProposal.instanceOf(outcome.inner.deferralReason)
    ) {
        handleBufferedCommit();
    }
    // and decrypted messages can go through the normal path
    else if (DecryptionOutcome.Decrypted.instanceOf(outcome)) {
        handleDecryptedMessage(outcome.inner.decryptedMessage);
    }
    // any outcomes we don't care about can be dropped
}
```

```swift
let outcomes = try await ctx.decryptMessage(conversationId: conversationId, payload: messageBytes)
for outcome in outcomes {
    switch outcome {
    // example: we care about buffered commits
    case .deferred(.missingProposal):
        handleBufferedCommit()
    // and decrypted messages can go through the normal path
    case .decrypted(let decryptedMessage):
        handleDecryptedMessage(decryptedMessage)
    // any outcomes we don't care about can be dropped
    default:
        break
    }
}
```

```kotlin
val outcomes = ctx.decryptMessage(conversationId, messageBytes)
for (outcome in outcomes) {
    when (outcome) {
        // example: we care about buffered commits
        is DecryptionOutcome.Deferred ->
            if (outcome.deferralReason is DeferralReason.MissingProposal) handleBufferedCommit()
        // and decrypted messages can go through the normal path
        is DecryptionOutcome.Decrypted -> handleDecryptedMessage(outcome.decryptedMessage)
        // any outcomes we don't care about can be dropped
        else -> {}
    }
}
```

<!-- langtabs-end -->
