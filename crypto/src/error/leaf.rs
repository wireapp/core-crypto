/// These errors can be raised from several different modules, so we centralize the definitions here
/// to ease error-handling.
#[derive(Debug, thiserror::Error)]
pub enum LeafError {
    /// This error is emitted when the requested conversation already exists with the given if
    #[error("Conversation already exists")]
    ConversationAlreadyExists(crate::prelude::ConversationId),
    /// This error is emitted when the requested conversation couldn't be found in our store
    #[error("Couldn't find conversation")]
    ConversationNotFound(crate::prelude::ConversationId),
    /// When looking for a X509 credential for a given ciphersuite and it has not been done
    #[error("End-to-end identity enrollment has not been done")]
    E2eiEnrollmentNotDone,
    /// The MLS group is in an invalid state for an unknown reason
    #[error("The MLS group is in an invalid state for an unknown reason")]
    InternalMlsError,
    /// Unexpectedly failed to retrieve group info
    ///
    /// This may be an implementation error.
    #[error("unexpectedly failed to retrieve group info")]
    MissingGroupInfo,
}
