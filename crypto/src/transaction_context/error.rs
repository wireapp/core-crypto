// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

use crate::{ConversationId, CredentialRef, mls::conversation::PendingConversation};

/// A module-specific [Result][core::result::Result] type with a default error variant.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Errors produced during a transaction
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("caller error: {0}")]
    CallerError(&'static str),
    #[error("This transaction context has already been finished and can no longer be used.")]
    InvalidTransactionContext,
    /// This error is emitted when the requested conversation already exists with the given id
    #[error("Conversation already exists")]
    ConversationAlreadyExists(ConversationId),
    /// This error is emitted when the requested conversation couldn't be found in our store
    #[error("Couldn't find conversation")]
    ConversationNotFound(ConversationId),
    #[error("The conversation with the specified id is pending")]
    PendingConversation(PendingConversation),
    #[error("Proteus client hasn't been initialized")]
    ProteusNotInitialized,
    #[error("PKI Environment must be set before calling this function")]
    PkiEnvironmentUnset,
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    OpenMls(#[from] crate::OpenMlsError),
    #[error("this credential is still in use by the conversation with id \"{}\"", hex::encode(.0))]
    CredentialStillInUse(ConversationId),
    #[error("The supplied credential does not match the id this CC instance was initialized with")]
    WrongCredential,
    #[error(
        "There are invalid CredentialRefs that should be removed. Hex encoded sha256 hashes: {}",
        format_invalid_credential_refs(.0)
    )]
    InvalidCredentials(Vec<CredentialRef>),
    #[error("something went wrong when generating and storing a new keypackage: {0}")]
    KeypackageNew(String),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}

fn format_invalid_credential_refs(credential_refs: &[CredentialRef]) -> String {
    credential_refs
        .iter()
        .map(|credential_ref| credential_ref.public_key_hash().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl Error {
    pub fn key_package_new<E: std::error::Error>() -> impl FnOnce(E) -> Self {
        move |source| Self::KeypackageNew(source.to_string())
    }
}
