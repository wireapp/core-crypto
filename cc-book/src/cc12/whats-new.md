# What's New in CC 12

CC 12 changes the MLS `decrypt_message` API.

> [!NOTE]
> Some of these changes break existing code. We provide a [migration guide](migration-guide.md).

## New `decrypt_message` API

In CC 11 and earlier, `decrypt_message` returned a single value, the primary message. This implementation had many
quirks: clients had to capture several error variants to ensure that they wouldn't cause the transaction to roll back,
and in case the primary message was a commit, it had to be inspected for potential buffered decrypted messages.
Sometimes, the primary message wasn't even the message passed in to `decrypt_message`!

In CC 12, `decrypt_message` returns a list of outcomes. The list is never empty; the first outcome is always that of
decrypting the actual message passed in. If decrypting this message unblocked some previously-buffered messages, then
the outcomes of those decrypted messages are simply appended to the list in replay order.

There are three possible outcomes:

- `Decrypted`, which contains nearly the same `DecryptedMessage` type from earlier CC versions, and indicates successful
  decryption.
- `Deferred` indicates that the input message was not processable yet, but was buffered in the expectation that a future
  message will make decryption possible automatically. Deferred messages can be waiting for a future epoch, a missing
  proposal, or a pending join; the deferral variant contains a reason indicating which of these was the case.
- `Rejected` messages are unable to be used. This isn't an [infrastructural error](#infrastructural-errors); it's a
  problem with the message itself. Replay will produce the same result. The rejected variant also contains a reason
  explaining why the message was rejected.

Clients do not need to do anything in particular when decryption produces a `Deferred` or `Rejected` outcome; these
outcomes are informational. They might be useful for logging or user feedback.

Several `MlsError` variants were replaced by `Deferred` or `Rejected` variants. Clients no longer need to catch these to
handle them; existing error-catching code should simply adjust what the handlers watch for:

- `BufferedFutureMessage` -> `Deferred(FutureEpoch)`
- `BufferedCommit` -> `Deferred(MissingProposal)`
- `UnmergedPendingGroup` -> `Deferred(PendingJoin)`
- `WrongEpoch` -> `Rejected(UnbufferedFarFutureMessage)`
- `DuplicateMessage`, `StaleCommit`, `StaleProposal`, `MessageEpochTooOld` -> `Rejected` with the same variant name

In addition, several failures that used to surface as `MlsError.Other` are now rejections.

### Infrastructural errors

Decryption now distinguishes between two categories of error: those that are infrastructural, and those which are not.

An infrastructural error is one arising from the infrastructure: the underlying database, transaction machinery, and the
like. They do not arise from the message being decrypted.

The general heuristic is: if we tried the operation again in a healthy environment, an infrastructural error would
succeed; a non-infrastructural error would fail in the same way.

### Behavioral changes

As deferrals and rejections are no longer errors, clients require much less strict error-matching to avoid inadvertently
canceling the transaction. The errors which are produced are intended to be those for which canceling the transaction is
the appropriate response.

When a proposal completes a buffered commit, CC 11 and earlier would drop the outcome of the proposal, returning the
un-buffered `Commit` as the primary message. Now, you get `[Proposal, Commit, ... replayed messages]`.

`isActive` on a `Commit` used to be set from the state after all replays, not the state as of that particular commit.
With these new changes, it is set `false` only for the decrypted commit which actually removed the device from the
conversation. However, as message processing stops when a commit removes this device from the group, callers need only
check the final outcome to determine whether or not they have been removed from the conversation.

A replayed message that is rejected now produces a `Rejected` outcome. CC 11 and earlier used to log and drop them.

Infrastructural errors during replay now propagate. For example, if the database runs out of space during replay, the
outermost call returns that error instead of the outcomes list, so that the transaction rolls back. In earlier CC
versions, errors during replay were swallowed.
