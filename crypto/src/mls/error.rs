//! MLS errors

/// Module-specific wrapper for [Result][core::result::Result]
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// MLS root errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// This error is emitted when the requested conversation couldn't be found in our store
    #[error("Couldn't find conversation")]
    ConversationNotFound(crate::prelude::ConversationId),
    /// This error is emitted when the requested conversation already exists with the given if
    #[error("Conversation already exists")]
    ConversationAlreadyExists(crate::prelude::ConversationId),
    /// This error is emitted when the requested client couldn't be found in MLS group
    #[error("Couldn't find client")]
    ClientNotFound(crate::prelude::ClientId),
    /// You tried to join with an external commit but did not merge it yet. We will reapply this message for you when you merge your external commit
    #[error(
        "You tried to join with an external commit but did not merge it yet. We will reapply this message for you when you merge your external commit"
    )]
    UnmergedPendingGroup,
    /// The ciphersuite identifier presented does not map to a known ciphersuite.
    #[error("Unknown ciphersuite")]
    UnknownCiphersuite,
    /// Unexpectedly failed to retrieve group info
    ///
    /// This may be an implementation error.
    #[error("unexpectedly failed to retrieve group info")]
    MissingGroupInfo,
    /// Callbacks are not provided
    #[error("The callbacks needed for CoreCrypto to operate were not set")]
    CallbacksNotSet,
    /// External Add Proposal Validation failed
    #[error("External add proposal validation failed: only users already in the group are allowed")]
    UnauthorizedExternalAddProposal,
    /// External Commit sender was not authorized to perform such
    #[error("External Commit sender was not authorized to perform such")]
    UnauthorizedExternalCommit,
    /// When looking for a X509 credential for a given ciphersuite and it has not been done
    #[error("End-to-end identity enrollment has not been done")]
    E2eiEnrollmentNotDone,
    /// This error is emitted when we find a malformed (i.e. not uuid) or empty identifier
    #[error("Malformed or empty identifier found: {0}")]
    MalformedIdentifier(&'static str),
    /// A key store operation failed
    //
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        /// What happened witht the keystore
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// What was happening in the caller
        context: &'static str,
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
    /// Something happened in the client
    #[error("{context}")]
    MlsClient {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::mls::client::error::Error>,
    },
    /// Something happened in the conversation
    #[error("{context}")]
    MlsConversation {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::mls::conversation::error::Error>,
    },
    /// Something happened with a credential
    #[error("{context}")]
    MlsCredential {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::mls::credential::error::Error>,
    },
    /// Something happened with an e2e identity
    #[error("{context}")]
    E2e {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::e2e_identity::error::Error>,
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

    pub(crate) fn mls_operation<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |source| Self::MlsOperation {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn client(context: &'static str) -> impl FnOnce(crate::mls::client::error::Error) -> Self {
        move |source| Self::MlsClient {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn conversation(context: &'static str) -> impl FnOnce(crate::mls::conversation::error::Error) -> Self {
        move |source| Self::MlsConversation {
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

    pub(crate) fn e2e(context: &'static str) -> impl FnOnce(crate::e2e_identity::error::Error) -> Self {
        move |source| Self::E2e {
            context,
            source: Box::new(source),
        }
    }
}
