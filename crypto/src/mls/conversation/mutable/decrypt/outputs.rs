use crate::{ClientId, WireIdentity};

/// Decrypted Bytes
#[derive(Debug)]
pub struct DecryptedBytes {
    /// Decrypted content
    pub plaintext: Vec<u8>,
    /// The sender's [ClientId].
    pub sender_client_id: ClientId,
    /// Identity claims present in the sender credential
    pub identity: WireIdentity,
}

/// The data relevant after a Proposal was processed.
#[derive(Debug)]
pub struct Proposal {
    /// Delay time in seconds to feed caller timer for committing
    pub delay: Option<u64>,
    /// Identity claims present in the sender credential
    pub identity: WireIdentity,
}

/// The data relevant after a Commit was processed.
#[derive(Debug)]
pub struct Commit {
    /// Is the conversation still active after receiving this commit, i.e., has the user been removed from the group
    pub is_active: bool,
    /// Contains buffered messages for next epoch which were received before the commit creating the epoch
    /// because the DS did not fan them out in order.
    pub buffered_messages: Option<Vec<BufferedDecryptedMessage>>,
    /// Identity claims present in the sender credential
    pub identity: WireIdentity,
}

/// The data relevant after a buffered Commit was processed.
#[derive(Debug)]
pub struct BufferedCommit {
    /// Is the conversation still active after receiving this commit, i.e., has the user been removed from the group
    pub is_active: bool,
    /// Identity claims present in the sender credential
    pub identity: WireIdentity,
}

/// Represents the items a consumer might require after decrypting a message.
#[derive(Debug, enum_as_inner::EnumAsInner)]
pub enum DecryptedMessage {
    /// The decrypted message is an MLS application message.
    ApplicationMessage(DecryptedBytes),
    /// The decrypted message is a commit.
    Commit(Commit),
    /// The decrypted message is a proposal.
    Proposal(Proposal),
    /// The decrypted message is a transient message.
    Transient(DecryptedBytes),
    /// The decrypted message is a transient targeted message.
    TransientTargeted(DecryptedBytes),
    /// The decrypted message is a persisted targeted message.
    PersistedTargeted(DecryptedBytes),
}

impl DecryptedMessage {
    /// Identity claims present in the sender credential
    pub fn identity(&self) -> &WireIdentity {
        match self {
            DecryptedMessage::ApplicationMessage(decrypted_bytes)
            | DecryptedMessage::Transient(decrypted_bytes)
            | DecryptedMessage::TransientTargeted(decrypted_bytes)
            | DecryptedMessage::PersistedTargeted(decrypted_bytes) => &decrypted_bytes.identity,
            DecryptedMessage::Commit(commit) => &commit.identity,
            DecryptedMessage::Proposal(proposal) => &proposal.identity,
        }
    }
}

/// A decrypted message that was buffered due to out-of-order delivery by the delivery service.
/// It represents messages for the new epoch that arrived before the commit that created it.
#[derive(Debug)]
pub enum BufferedDecryptedMessage {
    /// The decrypted message is an MLS application message.
    ApplicationMessage(DecryptedBytes),
    /// The decrypted message is a commit.
    Commit(BufferedCommit),
    /// The decrypted message is a proposal.
    Proposal(Proposal),
    /// The decrypted message is a transient message.
    Transient(DecryptedBytes),
    /// The decrypted message is a transient targeted message.
    TransientTargeted(DecryptedBytes),
    /// The decrypted message is a persisted targeted message.
    PersistedTargeted(DecryptedBytes),
}

impl From<DecryptedMessage> for BufferedDecryptedMessage {
    fn from(value: DecryptedMessage) -> Self {
        match value {
            DecryptedMessage::ApplicationMessage(message) => Self::ApplicationMessage(message),
            DecryptedMessage::Commit(commit) => Self::Commit({
                BufferedCommit {
                    is_active: commit.is_active,
                    identity: commit.identity,
                }
            }),
            DecryptedMessage::Proposal(proposal) => Self::Proposal(proposal),
            DecryptedMessage::Transient(decrypted_bytes) => Self::Transient(decrypted_bytes),
            DecryptedMessage::TransientTargeted(decrypted_bytes) => Self::TransientTargeted(decrypted_bytes),
            DecryptedMessage::PersistedTargeted(decrypted_bytes) => Self::PersistedTargeted(decrypted_bytes),
        }
    }
}

impl From<BufferedDecryptedMessage> for DecryptedMessage {
    fn from(value: BufferedDecryptedMessage) -> Self {
        match value {
            BufferedDecryptedMessage::ApplicationMessage(message) => Self::ApplicationMessage(message),
            BufferedDecryptedMessage::Commit(buffered_commit) => Self::Commit(Commit {
                is_active: buffered_commit.is_active,
                buffered_messages: None,
                identity: buffered_commit.identity,
            }),
            BufferedDecryptedMessage::Proposal(proposal) => Self::Proposal(proposal),
            BufferedDecryptedMessage::Transient(decrypted_bytes) => Self::Transient(decrypted_bytes),
            BufferedDecryptedMessage::TransientTargeted(decrypted_bytes) => Self::TransientTargeted(decrypted_bytes),
            BufferedDecryptedMessage::PersistedTargeted(decrypted_bytes) => Self::PersistedTargeted(decrypted_bytes),
        }
    }
}
