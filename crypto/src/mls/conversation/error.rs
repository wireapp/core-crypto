//! MLS conversation errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

use crate::{LeafError, RecursiveError};

use super::config::MAX_PAST_EPOCHS;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Message body type not suitable for restoration")]
    InappropriateMessageBodyType,
    #[error("The specified parent group has not been found in the keystore")]
    ParentGroupNotFound,
    #[error("The current client id isn't authorized to perform this action")]
    Unauthorized,
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    #[error("The epoch in which message was encrypted is older than {MAX_PAST_EPOCHS}")]
    MessageEpochTooOld,
    #[error("Incoming message is from a prior epoch")]
    StaleMessage,
    #[error("Incoming message is for a future epoch. We will buffer it until the commit for that epoch arrives")]
    BufferedFutureMessage,
    #[error("Incoming message is from an epoch too far in the future to buffer.")]
    UnbufferedFarFutureMessage,
    #[error("The received commit is deemed stale and is from an older epoch.")]
    StaleCommit,
    #[error("The received proposal is deemed stale and is from an older epoch.")]
    StaleProposal,
    #[error("An application message failed to decrypt")]
    DecryptionError,
    #[error("MLS Client was not initialized the right way")]
    IdentityInitializationError,
    #[error("MLS group is in an invalid state: {0}")]
    MlsGroupInvalidState(&'static str),
    #[error("MLS message is in an invalid state: {0}")]
    MlsMessageInvalidState(&'static str),
    #[error("The group lacks an ExternalSender extension whereas it should have at least one")]
    MissingExternalSenderExtension,
    #[error("Couldn't find pending proposal {0}")]
    PendingProposalNotFound(crate::mls::proposal::MlsProposalRef),
    #[error("Couldn't find pending commit")]
    PendingCommitNotFound,
    #[error("Happens when a client creates a commit, sends it to the DS which accepts it but then client \
    clears this pending commit and creates another commit. This is triggered when the client tries to decrypt the original commit.\
    This means something is very wrong in the client's code and has to be fixed immediately")]
    ClearingPendingCommitError,
    #[error("Tried to decrypt a commit created by self which is likely to have been replayed by the DS")]
    SelfCommitIgnored,
    #[error("This proposal variant cannot be renewed")]
    PropopsalVariantCannotBeRenewed,
    #[error("caller error: {0}")]
    CallerError(&'static str),
    /// This happens when the DS cannot flag KeyPackages as claimed or not. It this scenario, a client
    /// requests their old KeyPackages to be deleted but one has already been claimed by another client to create a Welcome.
    /// In that case the only solution is that the client receiving such a Welcome tries to join the group
    /// with an External Commit instead
    #[error("Although this Welcome seems valid, the local KeyPackage it references has already been deleted locally. Join this group with an external commit")]
    OrphanWelcome,
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error("Serializing {item} for TLS")]
    TlsSerialize {
        item: &'static str,
        #[source]
        source: tls_codec::Error,
    },
    #[error("Deserializing {item} for TLS")]
    TlsDeserialize {
        item: &'static str,
        #[source]
        source: tls_codec::Error,
    },
    #[error("{context}")]
    MlsOperation {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(transparent)]
    Leaf(#[from] LeafError),
    #[error(transparent)]
    Recursive(#[from] RecursiveError),
}

impl Error {
    pub(crate) fn tls_serialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsSerialize { item, source }
    }

    pub(crate) fn tls_deserialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsDeserialize { item, source }
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
