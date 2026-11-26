/// An MLS operation failed, but we captured some context about how it did so
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
    MlsMessageError(#[from] openmls::prelude::ProcessMessageError<core_crypto_keystore::CryptoKeystoreError>),
    /// `KeyPackageBundle` new error
    #[error(transparent)]
    MlsKeyPackageBundleNewError(#[from] openmls::prelude::KeyPackageNewError),
    /// Self update error
    #[error(transparent)]
    MlsSelfUpdateError(#[from] openmls::prelude::SelfUpdateError<core_crypto_keystore::CryptoKeystoreError>),
    /// Group state error
    #[error(transparent)]
    MlsGroupStateError(#[from] openmls::prelude::MlsGroupStateError),
    /// Propose add members error
    #[error(transparent)]
    ProposeAddMemberError(#[from] openmls::prelude::ProposeAddMemberError<core_crypto_keystore::CryptoKeystoreError>),
    /// Propose remove members error
    #[error(transparent)]
    ProposeRemoveMemberError(
        #[from] openmls::prelude::ProposeRemoveMemberError<core_crypto_keystore::CryptoKeystoreError>,
    ),
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
    MlsExternalCommitError(#[from] openmls::prelude::ExternalCommitError<core_crypto_keystore::CryptoKeystoreError>),
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
    /// Verifying a group or building an external commit failed
    #[error(transparent)]
    MlsExternalCommitBuilderError(
        #[from] openmls::prelude::ExternalCommitBuilderError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// Finalizing an external commit failed
    #[error(transparent)]
    MlsExternalCommitBuilderFinalizeError(
        #[from] openmls::prelude::ExternalCommitBuilderFinalizeError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// A key package failed validation
    #[error(transparent)]
    MlsKeyPackageVerifyError(#[from] openmls::prelude::KeyPackageVerifyError),
    /// Creating a commit failed
    #[error(transparent)]
    MlsCreateCommitError(#[from] openmls::prelude::CreateCommitError),
    /// Staging a commit failed
    #[error(transparent)]
    MlsCommitBuilderStageError(
        #[from] openmls::prelude::CommitBuilderStageError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// Removing a pending proposal failed
    #[error(transparent)]
    MlsRemoveProposalError(#[from] openmls::group::RemoveProposalError<core_crypto_keystore::CryptoKeystoreError>),
    /// An extension is invalid where it was used
    #[error(transparent)]
    MlsInvalidExtensionError(#[from] openmls::prelude::InvalidExtensionError),
    /// Signature Error
    #[error(transparent)]
    SignatureError(#[from] openmls::prelude::SignatureError),
}
