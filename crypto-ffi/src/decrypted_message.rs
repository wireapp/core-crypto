use std::sync::Arc;

use core_crypto::DecryptedMessage as CcDecryptedMessage;

use crate::{ClientId, WireIdentity};

/// Represents the items a consumer might require after decrypting a message.
//
// Implementation note: from a pure rust perspective, it would be desirable to use tuple-struct-like variants where
// structure is equal. However, uniffi's generated code isn't particularly nice with those kind of variants, because it
// generates classes with members named after their index in the tuple, which isn't idiomatic in any of our target
// languages.
#[derive(Debug, uniffi::Enum)]
pub enum DecryptedMessage {
    /// The decrypted message is an MLS application message.
    ApplicationMessage {
        /// Decrypted message.
        plaintext: Vec<u8>,
        /// The sender's `ClientId`.
        sender_client_id: Arc<ClientId>,
        /// Identity claims present in the sender credential.
        identity: WireIdentity,
    },
    /// The decrypted message is a commit.
    Commit {
        /// False if processing this message caused the client to be removed from the group, i.e. due to a Remove
        /// commit.
        is_active: bool,
        /// Identity claims present in the sender credential.
        identity: WireIdentity,
    },
    /// The decrypted message is a proposal.
    Proposal {
        /// Commit delay in seconds.
        ///
        /// When set, clients must delay by this time interval before processing a commit. This reduces load on the
        /// backend, which otherwise would receive epoch change notifications from all clients simultaneously.
        delay: Option<u64>,
        /// Identity claims present in the sender credential.
        identity: WireIdentity,
    },
    /// The decrypted message is a transient message.
    Transient {
        /// Decrypted message.
        plaintext: Vec<u8>,
        /// The sender's `ClientId`.
        sender_client_id: Arc<ClientId>,
        /// Identity claims present in the sender credential.
        identity: WireIdentity,
    },
    /// The decrypted message is a transient targeted message.
    TransientTargeted {
        /// Decrypted message.
        plaintext: Vec<u8>,
        /// The sender's `ClientId`.
        sender_client_id: Arc<ClientId>,
        /// Identity claims present in the sender credential.
        identity: WireIdentity,
    },
    /// The decrypted message is a persisted targeted message.
    PersistedTargeted {
        /// Decrypted message.
        plaintext: Vec<u8>,
        /// The sender's `ClientId`.
        sender_client_id: Arc<ClientId>,
        /// Identity claims present in the sender credential.
        identity: WireIdentity,
    },
}

impl From<CcDecryptedMessage> for DecryptedMessage {
    fn from(from: CcDecryptedMessage) -> Self {
        match from {
            CcDecryptedMessage::ApplicationMessage(message) => Self::ApplicationMessage {
                plaintext: message.plaintext,
                sender_client_id: Arc::new(message.sender_client_id.into()),
                identity: message.identity.into(),
            },
            CcDecryptedMessage::Commit(commit) => Self::Commit {
                is_active: commit.is_active,
                identity: commit.identity.into(),
            },
            CcDecryptedMessage::Proposal(proposal) => Self::Proposal {
                delay: proposal.delay,
                identity: proposal.identity.into(),
            },
            CcDecryptedMessage::Transient(message) => Self::Transient {
                plaintext: message.plaintext,
                sender_client_id: Arc::new(message.sender_client_id.into()),
                identity: message.identity.into(),
            },
            CcDecryptedMessage::TransientTargeted(message) => Self::TransientTargeted {
                plaintext: message.plaintext,
                sender_client_id: Arc::new(message.sender_client_id.into()),
                identity: message.identity.into(),
            },
            CcDecryptedMessage::PersistedTargeted(message) => Self::PersistedTargeted {
                plaintext: message.plaintext,
                sender_client_id: Arc::new(message.sender_client_id.into()),
                identity: message.identity.into(),
            },
        }
    }
}
