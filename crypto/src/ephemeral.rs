//! Utilities for ephemeral CoreCrypto instances.
//!
//! Ephemeral instances are intended to support history sharing. History sharing works like this:
//! every history-enabled conversation has a passive "history client" as a member. This client
//! is a member of the MLS group (and can therefore decrypt messages), but it is not actively running
//! on any device or decrypting any messages.
//!
//! Approximately once daily, and whenever a member is removed from the group, a new history-sharing era
//! begins. The client submitting the commit which instantiates the new history-sharing era is responsible
//! for ensuring that the old history client is removed from the group, and new one is added. Additionally,
//! one of the first application messages in the new history-sharing era contains the serialized history
//! secret.
//!
//! When a new client joins the history-enabled conversation, they receive a list of history secrets
//! and their associated history-sharing eras (identified by the epoch number at which they start).
//! For each history-sharing era, they can instantiate an ephemeral client from the history secret,
//! and use that client to decrypt all messages in this era.
//!
//! Though ephemeral clients are full instances of `CoreCrypto` and contain the same API, they should
//! not be used to generate messages for sending. They should also not be instantiated to follow along with
//! new messages as they are received, as that's pointless; the individual credentials suffice.

use openmls::prelude::Credential;

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HistorySecret {
    client_id: String,
    key_package: Vec<u8>,
    credential: Credential,
}
