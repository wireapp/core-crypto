# What's New in CC 11

CC 11 adds two new kinds of MLS message and a set of post-quantum cipher suites. It also includes various smaller
changes.

> [!NOTE]
> Some of these changes break existing code. We provide a [migration guide](migration-guide.md).

## Transient and Targeted Messages

Regular MLS application messages go to every member of a conversation and advance the group's cryptographic state.
That's the right choice for chat messages, but it's a poor fit for content that only matters to some members or only
matters right now. CC 11 adds two new kinds of message for these cases. Neither of them changes the group's
cryptographic state.

### Transient messages

`encryptTransientMessage(conversationId, message)` encrypts a message for all members of a conversation. Transient
messages are meant to go only to members who are online at the time they are sent.

### Targeted messages

`encryptTargetedMessage(conversationId, recipient, policy, message)` encrypts a message for a single member of a
conversation, identified by their `ClientId`. This is what makes read receipts possible in MLS conversations: sending
each receipt as a regular MLS message would flood every member with messages that only matter to one of them.

The `policy` argument tells the delivery service how to handle the message:

- `TargetedMessagePolicy.Transient`: delivered only to the recipient if they are online, and dropped otherwise.
- `TargetedMessagePolicy.Persisted`: may be stored by the delivery service, so a recipient who is offline still gets it
  later.

### Receiving

There is no new decryption API. `decryptMessage` handles all of these messages and returns them as the new
`DecryptedMessage.Transient`, `DecryptedMessage.TransientTargeted` and `DecryptedMessage.PersistedTargeted` variants.
Each one carries the plaintext, the sender's client id and the sender's identity, just like
`DecryptedMessage.ApplicationMessage`. The [migration guide](migration-guide.md#decryptedmessage) shows how to match on
them.

> [!WARNING]
> Transient and targeted messages have weaker security guarantees than regular MLS application messages. Any feature
> built on them must explain why that is acceptable for its use case, or how the difference is mitigated.

## Post-Quantum Cipher Suites

CoreCrypto now supports 11 post-quantum cipher suites, as defined in the
[MLS post-quantum cipher suites draft](https://www.ietf.org/archive/id/draft-ietf-mls-pq-ciphersuites-06.html).

Six of them use a hybrid key exchange, combining ML-KEM with a classical algorithm:

- `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`
- `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519`
- `MLS_128_MLKEM768P256_AES128GCM_SHA256_P256`
- `MLS_128_MLKEM768P256_AES256GCM_SHA384_P256`
- `MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44`
- `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384`

The other five use a pure post-quantum key exchange:

- `MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519`
- `MLS_128_MLKEM768_AES256GCM_SHA384_P256`
- `MLS_192_MLKEM1024_AES256GCM_SHA384_P384`
- `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65`
- `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`

Only the three suites ending in `MLDSA*` also use post-quantum signatures. The others keep a classical signature scheme.

X509 credentials don't work yet with post-quantum signatures, so the `MLDSA*` suites only support basic credentials.

## SQLite via OPFS/JSPI in browsers

OPFS enables running real SQLite in browsers. However, OPFS's synchronous file access is only available in web workers.
To enable waiting on the OPFS worker without blocking the main thread, we're using _JS Promise Integration_ (JSPI), a
relatively new feature that allows wasm to block on JS promises without blocking DOM rendering. Therefore, browsers
using CoreCrypto must support JSPI. See the _JS Promise Integration_ row at
<https://webassembly.org/features/?categories=browsers>.
