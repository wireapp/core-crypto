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

/// A reason why processing this message had to be deferred.
#[derive(Debug)]
pub enum DeferralReason {
    /// Message comes from a future epoch and can be processed once we arrive in that epoch
    FutureEpoch {
        /// The epoch at which this message should become decryptable.
        epoch: u64,
    },
    /// Message attempts to commit a proposal by reference, but we have not yet received the referenced proposal
    MissingProposal,
    /// Message was delivered for a pending group which we haven't fully joined yet.
    PendingJoin,
}

/// Outcome of attempting to decrypt a message.
//
// We don't mind the size difference between variants here; the big variant is the happy path.
#[cfg_attr(not(target_os = "unknown"), expect(clippy::large_enum_variant))]
#[derive(Debug, derive_more::From, derive_more::IsVariant)]
pub enum DecryptionOutcome {
    /// The message was successfully decrypted.
    Decrypted(DecryptedMessage),
    /// The message could not be processed yet, but is expected to be processable in the future.
    Deferred(DeferralReason),
}

/// A change in state due to this message being processed
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Effect {
    /// The message was just a message.
    None,
    /// The message was a proposal, which was stored.
    ProposalStored,
    /// The message was a commit, which advanced the epoch.
    EpochAdvanced {
        /// the new epoch value
        new_epoch: u64,
        /// whether we are still a member of this conversation after this commit
        is_active: bool,
    },
}
