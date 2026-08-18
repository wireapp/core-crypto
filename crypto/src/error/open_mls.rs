/// A MLS operation failed, but we captured some context about how it did so
pub type OpenMlsError = super::wrapper::WrappedContextualError<OpenMlsErrorKind>;

/// Openmls produces these kinds of error
#[derive(Debug, thiserror::Error)]
pub enum OpenMlsErrorKind {
    /// Welcome error
    #[error(transparent)]
    MlsWelcomeError(#[from] openmls::prelude::WelcomeError<core_crypto_keystore::CryptoKeystoreError>),
    /// Generic error type that indicates unrecoverable errors in the library. See [openmls::error::LibraryError]
    #[error(transparent)]
    MlsLibraryError(#[from] openmls::error::LibraryError),
    /// Create message error
    #[error(transparent)]
    MlsInvalidMessageError(#[from] openmls::prelude::CreateMessageError),
    /// An error that occurs in methods of a [openmls::credentials::Credential].
    #[error(transparent)]
    MlsCredentialError(#[from] openmls::prelude::CredentialError),
    /// New group error
    #[error(transparent)]
    MlsNewGroupError(#[from] openmls::prelude::NewGroupError<core_crypto_keystore::CryptoKeystoreError>),
    /// Add members error
    #[error(transparent)]
    MlsAddMembersError(#[from] openmls::prelude::AddMembersError<core_crypto_keystore::CryptoKeystoreError>),
    /// Remove members error
    #[error(transparent)]
    MlsRemoveMembersError(#[from] openmls::prelude::RemoveMembersError<core_crypto_keystore::CryptoKeystoreError>),
    /// Parse message error
    #[error(transparent)]
    MlsMessageError(#[from] openmls::prelude::ProcessMessageError),
    /// `KeyPackageBundle` new error
    #[error(transparent)]
    MlsKeyPackageBundleNewError(
        #[from] openmls::prelude::KeyPackageNewError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// Self update error
    #[error(transparent)]
    MlsSelfUpdateError(#[from] openmls::prelude::SelfUpdateError<core_crypto_keystore::CryptoKeystoreError>),
    /// Group state error
    #[error(transparent)]
    MlsGroupStateError(#[from] openmls::prelude::MlsGroupStateError),
    /// Propose add members error
    #[error(transparent)]
    ProposeAddMemberError(#[from] openmls::prelude::ProposeAddMemberError),
    /// Propose remove members error
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] openmls::prelude::ProposeRemoveMemberError),
    /// Commit to pending proposals error
    #[error(transparent)]
    MlsCommitToPendingProposalsError(
        #[from] openmls::prelude::CommitToPendingProposalsError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// Errors that are thrown by TLS serialization crate.
    #[error(transparent)]
    MlsTlsCodecError(#[from] tls_codec::Error),
    /// This type represents all possible errors that can occur when serializing or
    /// deserializing JSON data.
    #[error(transparent)]
    MlsKeystoreSerializationError(#[from] serde_json::Error),
    /// External Commit error
    #[error(transparent)]
    MlsExternalCommitError(#[from] openmls::prelude::ExternalCommitError),
    /// OpenMls crypto error
    #[error(transparent)]
    MlsCryptoError(#[from] openmls::prelude::CryptoError),
    /// OpenMls Export Secret error
    #[error(transparent)]
    MlsExportSecretError(#[from] openmls::prelude::ExportSecretError),
    /// OpenMLS merge commit error
    #[error(transparent)]
    MlsMergeCommitError(#[from] openmls::prelude::MergeCommitError<core_crypto_keystore::CryptoKeystoreError>),
    /// OpenMLS Commit merge error
    #[error(transparent)]
    MlsMergePendingCommitError(
        #[from] openmls::prelude::MergePendingCommitError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// OpenMLS encrypt message error
    #[error(transparent)]
    MlsEncryptMessageError(#[from] openmls::framing::errors::MlsMessageError),
    /// OpenMLS GroupInfo error
    #[error(transparent)]
    GroupInfoError(#[from] openmls::messages::group_info::GroupInfoError),
    /// Provider Error
    #[error(transparent)]
    ProviderError(#[from] crate::mls_provider::Error),
    /// Keystore Error
    #[error(transparent)]
    KeystoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    /// Signature Error
    #[error(transparent)]
    SignatureError(#[from] openmls::prelude::SignatureError),
}
