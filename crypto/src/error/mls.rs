/// A MLS operation failed, but we captured some context about how it did so
pub type MlsError = super::wrapper::WrappedContextualError<MlsErrorKind>;

/// Openmls produces these kinds of error
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum MlsErrorKind {
    /// Welcome error
    #[error(transparent)]
    MlsWelcomeError(#[from] openmls::prelude::WelcomeError<core_crypto_keystore::CryptoKeystoreError>),
    /// Generic error type that indicates unrecoverable errors in the library. See [openmls::error::LibraryError]
    #[error(transparent)]
    MlsLibraryError(#[from] openmls::error::LibraryError),
    /// Create message error
    #[error(transparent)]
    MlsInvalidMessageError(#[from] openmls::prelude::CreateMessageError),
    /// EmptyInput error
    #[error(transparent)]
    MlsEmptyInputError(#[from] openmls::prelude::EmptyInputError),
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
    MlsMlsGroupStateError(#[from] openmls::prelude::MlsGroupStateError),
    /// Propose add members error
    #[error(transparent)]
    ProposeAddMemberError(#[from] openmls::prelude::ProposeAddMemberError),
    /// Propose self update error
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] openmls::prelude::ProposeSelfUpdateError<core_crypto_keystore::CryptoKeystoreError>),
    /// Propose remove members error
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] openmls::prelude::ProposeRemoveMemberError),
    /// Commit to pending proposals error
    #[error(transparent)]
    MlsCommitToPendingProposalsError(
        #[from] openmls::prelude::CommitToPendingProposalsError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// Export public group state error
    #[error(transparent)]
    MlsExportGroupInfoError(#[from] openmls::prelude::ExportGroupInfoError),
    /// Errors that are thrown by TLS serialization crate.
    #[error(transparent)]
    MlsTlsCodecError(#[from] tls_codec::Error),
    /// This type represents all possible errors that can occur when serializing or
    /// deserializing JSON data.
    #[error(transparent)]
    MlsKeystoreSerializationError(#[from] serde_json::Error),
    /// A wrapper struct for an error string. This can be used when no complex error
    /// variant is needed.
    #[error(transparent)]
    MlsErrorString(#[from] openmls::error::ErrorString),
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
    /// OpenMLS keypackage validation error
    #[error(transparent)]
    MlsKeyPackageValidationError(#[from] openmls::prelude::KeyPackageVerifyError),
    /// OpenMLS Commit merge error
    #[error(transparent)]
    MlsMergePendingCommitError(
        #[from] openmls::prelude::MergePendingCommitError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// OpenMLS encrypt message error
    #[error(transparent)]
    MlsEncryptMessageError(#[from] openmls::framing::errors::MlsMessageError),
    /// OpenMLS delete KeyPackage error
    #[error(transparent)]
    MlsDeleteKeyPackageError(
        #[from] openmls::key_packages::errors::KeyPackageDeleteError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// OpenMLS update extensions error
    #[error(transparent)]
    MlsUpdateExtensionsError(
        #[from] openmls::prelude::UpdateExtensionsError<core_crypto_keystore::CryptoKeystoreError>,
    ),
    /// OpenMLS LeafNode validation error
    #[error(transparent)]
    MlsLeafNodeValidationError(#[from] openmls::prelude::LeafNodeValidationError),
    /// OpenMLS LeafNode validation error
    #[error(transparent)]
    RatchetTreeError(#[from] openmls::treesync::RatchetTreeError),
    /// OpenMLS GroupInfo error
    #[error(transparent)]
    GroupInfoError(#[from] openmls::messages::group_info::GroupInfoError),
    /// Provider Error
    #[error(transparent)]
    ProviderError(#[from] mls_crypto_provider::MlsProviderError),
}
