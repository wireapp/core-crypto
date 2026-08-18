//! MLS errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Supplied client id was not of the format `<user-id:device-id@domain>`")]
    InvalidQualifiedClientId,
    #[error("Supplied user id was not valid")]
    InvalidUserId,
    #[error("A MLS operation was requested but MLS hasn't been initialized on this instance")]
    MlsNotInitialized,
    /// This error is emitted when the requested conversation couldn't be found in our store
    #[error("Couldn't find conversation")]
    ConversationNotFound(crate::ConversationId),
    #[error("No credential of type ({0:?}) was found in this session")]
    NoCredentialWithType(crate::CredentialType),
    #[error("An EpochObserver has already been registered; reregistration is not possible")]
    EpochObserverAlreadyExists,
    #[error("An HistoryHandler has already been registered; reregistration is not possible")]
    HistoryObserverAlreadyExists,
    #[error(transparent)]
    OpenMls(#[from] crate::OpenMlsError),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}
