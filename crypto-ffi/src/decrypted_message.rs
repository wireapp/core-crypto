use std::sync::Arc;

use core_crypto::{BufferedDecryptedMessage as CcBufferedDecryptedMessage, DecryptedMessage as CcDecryptedMessage};

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
        /// Contains buffered messages for next epoch which were received before the commit creating the epoch
        /// because the DS did not fan them out in order.
        buffered_messages: Option<Vec<BufferedDecryptedMessage>>,
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
                buffered_messages: commit
                    .buffered_messages
                    .map(|messages| messages.into_iter().map(Into::into).collect()),
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

/// A decrypted message that was buffered due to out-of-order delivery by the delivery service.
/// It represents messages for the new epoch that arrived before the commit that created it.
#[derive(Debug, uniffi::Enum)]
pub enum BufferedDecryptedMessage {
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
        ///Commit delay in seconds.
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

impl From<CcBufferedDecryptedMessage> for BufferedDecryptedMessage {
    fn from(from: CcBufferedDecryptedMessage) -> Self {
        match from {
            CcBufferedDecryptedMessage::ApplicationMessage(message) => Self::ApplicationMessage {
                plaintext: message.plaintext,
                sender_client_id: Arc::new(message.sender_client_id.into()),
                identity: message.identity.into(),
            },
            CcBufferedDecryptedMessage::Commit(commit) => Self::Commit {
                is_active: commit.is_active,
                identity: commit.identity.into(),
            },
            CcBufferedDecryptedMessage::Proposal(proposal) => Self::Proposal {
                delay: proposal.delay,
                identity: proposal.identity.into(),
            },
            CcBufferedDecryptedMessage::Transient(message) => Self::Transient {
                plaintext: message.plaintext,
                sender_client_id: Arc::new(message.sender_client_id.into()),
                identity: message.identity.into(),
            },
            CcBufferedDecryptedMessage::TransientTargeted(message) => Self::TransientTargeted {
                plaintext: message.plaintext,
                sender_client_id: Arc::new(message.sender_client_id.into()),
                identity: message.identity.into(),
            },
            CcBufferedDecryptedMessage::PersistedTargeted(message) => Self::PersistedTargeted {
                plaintext: message.plaintext,
                sender_client_id: Arc::new(message.sender_client_id.into()),
                identity: message.identity.into(),
            },
        }
    }
}
