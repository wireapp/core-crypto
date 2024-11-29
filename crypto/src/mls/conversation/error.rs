//! MLS errors

use super::config::MAX_PAST_EPOCHS;

/// Module-specific wrapper aroud a [Result][core::result::Result].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// MLS client errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Message body type was not suitable for restoration
    #[error("Message body type not suitable for restoration")]
    InappropriateMessageBodyType,
    /// Parent group cannot be found
    #[error("The specified parent group has not been found in the keystore")]
    ParentGroupNotFound,
    /// Authorization error
    #[error("The current client id isn't authorized to perform this action")]
    Unauthorized,
    /// This error is emitted when the requested conversation couldn't be found in our store
    #[error("Couldn't find conversation")]
    ConversationNotFound(crate::prelude::ConversationId),
    /// This error is emitted when the requested conversation already exists with the given id
    #[error("Conversation already exists")]
    ConversationAlreadyExists(crate::prelude::ConversationId),
    /// We already decrypted this message once
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    /// Message epoch is too old
    #[error("The epoch in which message was encrypted is older than {MAX_PAST_EPOCHS}")]
    MessageEpochTooOld,
    /// Incoming message is from a prior epoch
    #[error("Incoming message is from a prior epoch")]
    StaleMessage,
    /// Incoming message is for a future epoch. We will buffer it until the commit for that epoch arrives
    #[error("Incoming message is for a future epoch. We will buffer it until the commit for that epoch arrives")]
    BufferedFutureMessage,
    /// Incoming message is from an epoch too far in the future to buffer.
    #[error("Incoming message is from an epoch too far in the future to buffer.")]
    UnbufferedFarFutureMessage,
    /// The received commit is deemed stale and is from an older epoch
    #[error("The received commit is deemed stale and is from an older epoch.")]
    StaleCommit,
    /// The received proposal is deemed stale and is from an older epoch
    #[error("The received proposal is deemed stale and is from an older epoch.")]
    StaleProposal,
    /// An application message failed to decrypt
    #[error("An application message failed to decrypt")]
    DecryptionError,
    /// MLS Client was not initialized the right way
    #[error("MLS Client was not initialized the right way")]
    IdentityInitializationError,
    /// The MLS group is in an invalid state for an unknown reason
    #[error("MLS group is in an invalid state: {0}")]
    MlsGroupInvalidState(&'static str),
    /// The MLS message is in an invalid state for an unknown reason
    #[error("MLS message is in an invalid state: {0}")]
    MlsMessageInvalidState(&'static str),
    /// The group lacks an ExternalSender extension whereas it should have at least one
    #[error("The group lacks an ExternalSender extension whereas it should have at least one")]
    MissingExternalSenderExtension,
    /// This error is emitted when a pending proposal couldn't be found in MLS group
    #[error("Couldn't find pending proposal {0}")]
    PendingProposalNotFound(crate::mls::proposal::MlsProposalRef),
    /// This error is emitted when a pending commmit couldn't be found in MLS group
    #[error("Couldn't find pending commit")]
    PendingCommitNotFound,
    /// Happens when a client creates a commit, sends it to the DS which accepts it but then client
    /// clears this pending commit and creates another commit. This is triggered when the client
    /// tries to decrypt the original commit. This means something is very wrong in the client's
    /// code and has to be fixed immediately
    #[error("Happens when a client creates a commit, sends it to the DS which accepts it but then client \
    clears this pending commit and creates another commit. This is triggered when the client tries to decrypt the original commit.\
    This means something is very wrong in the client's code and has to be fixed immediately")]
    ClearingPendingCommitError,
    /// Tried to decrypt a commit created by self which is likely to have been replayed by the DS
    #[error("Tried to decrypt a commit created by self which is likely to have been replayed by the DS")]
    SelfCommitIgnored,
    /// This proposal variant cannot be renewed
    #[error("This proposal variant cannot be renewed")]
    PropopsalVariantCannotBeRenewed,
    /// Unexpectedly failed to retrieve group info
    ///
    /// This may be an implementation error. Adding errors shold always generate a new commit.
    #[error("unexpectedly failed to retrieve group info")]
    MissingGroupInfo,
    /// The caller of this function used it wrong
    #[error("caller error: {0}")]
    CallerError(&'static str),
    /// This happens when the DS cannot flag KeyPackages as claimed or not. It this scenario, a client
    /// requests their old KeyPackages to be deleted but one has already been claimed by another client to create a Welcome.
    /// In that case the only solution is that the client receiving such a Welcome tries to join the group
    /// with an External Commit instead
    #[error("Although this Welcome seems valid, the local KeyPackage it references has already been deleted locally. Join this group with an external commit")]
    OrphanWelcome,
    /// A key store operation failed
    //
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        /// What happened in the keystore
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// What the caller was doing at the time
        context: &'static str,
    },
    /// Serializing an item for tls
    #[error("Serializing {item} for TLS")]
    TlsSerialize {
        /// What was being serialized
        item: &'static str,
        /// What happened during serialization
        #[source]
        source: tls_codec::Error,
    },
    /// Deserializing an item for tls
    #[error("Deserializing {item} for TLS")]
    TlsDeserialize {
        /// What was being deserialized
        item: &'static str,
        /// What happened during deserialization
        #[source]
        source: tls_codec::Error,
    },
    /// Client error
    #[error("{context}")]
    Client {
        /// What the caller was doing at the time
        context: &'static str,
        /// What happened in the client
        #[source]
        source: Box<crate::mls::client::error::Error>,
    },
    /// E2E Identity error
    #[error("{context}")]
    E2eIdentity {
        /// What the caller was doing at the time
        context: &'static str,
        /// What happened in e2e identity
        #[source]
        source: Box<crate::e2e_identity::error::Error>,
    },
    /// A MLS operation failed
    #[error("{context}")]
    MlsOperation {
        /// What the caller was doing at the time
        context: &'static str,
        /// What happened in MLS
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Something in the MLS credential went wrong
    #[error("{context}")]
    MlsCredential {
        /// What was happening when the error was thrown
        context: &'static str,
        /// The inner error which was produced
        #[source]
        source: Box<crate::mls::credential::error::Error>,
    },
    /// Compatibility wrapper
    ///
    /// This should be removed before merging this branch, but it allows an easier migration path to module-specific errors.
    #[deprecated]
    #[error(transparent)]
    CryptoError(Box<crate::CryptoError>),
}

impl From<crate::CryptoError> for Error {
    fn from(value: crate::CryptoError) -> Self {
        Self::CryptoError(Box::new(value))
    }
}

impl Error {
    pub(crate) fn keystore<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |err| Self::Keystore {
            context,
            source: Box::new(err),
        }
    }

    pub(crate) fn tls_serialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsSerialize { item, source }
    }

    pub(crate) fn tls_deserialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsDeserialize { item, source }
    }

    pub(crate) fn client(context: &'static str) -> impl FnOnce(crate::mls::client::error::Error) -> Self {
        move |source| Self::Client {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn e2e_identity(context: &'static str) -> impl FnOnce(crate::e2e_identity::error::Error) -> Self {
        move |source| Self::E2eIdentity {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn mls_operation<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |source| Self::MlsOperation {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn credential(context: &'static str) -> impl FnOnce(crate::mls::credential::error::Error) -> Self {
        move |source| Self::MlsCredential {
            context,
            source: Box::new(source),
        }
    }

    /// Attempt to downcast this error as a specific MLS error variant.
    ///
    /// Most useful for testing.
    pub(crate) fn downcast_mls<T>(&self) -> Option<(&T, &'static str)>
    where
        T: 'static + std::error::Error + Send + Sync,
    {
        let Self::MlsOperation { context, source } = self else {
            return None;
        };
        source.downcast_ref::<T>().map(|t| (t, *context))
    }
}
