pub(crate) trait Infrastructural {
    /// `true` when this error came from the infrastructure (keystore, transaction, etc)
    /// and not the input being processed. These want to be propagated where input errors might be swallowed.
    ///
    /// The general rule is: if we tried the operation again in a healthy environment, would we expect it to succeed?
    /// If yes, then the error was an infrastructure error.
    fn is_infrastructure(&self) -> bool;
}

impl Infrastructural for crate::Error {
    fn is_infrastructure(&self) -> bool {
        match self {
            // the client hasn't finished setting us up, or the network failed; the input is fine
            Self::MlsTransportNotProvided | Self::ProteusNotInitialized | Self::ErrorDuringMlsTransport(_) => true,
            Self::Keystore(_) => true,
            Self::OpenMls(openmls) => openmls.is_infrastructure(),
            Self::Recursive(recursive) => recursive.is_infrastructure(),
            _ => false,
        }
    }
}

impl Infrastructural for crate::mls::conversation::Error {
    // Every variant is listed, so that adding one forces a decision about whether it is infrastructure. Replaying a
    // message from the inbox swallows anything which isn't, so getting this wrong loses the message.
    fn is_infrastructure(&self) -> bool {
        match self {
            Self::Keystore(_) | Self::SessionDropped => true,
            Self::OpenMls(openmls) => openmls.is_infrastructure(),
            Self::Recursive(recursive) => recursive.is_infrastructure(),
            Self::InappropriateMessageBodyType
            | Self::MemberNotFound(_)
            | Self::TntMessageCounterOverflow
            | Self::MessageRejected { .. }
            | Self::DuplicateMessage
            | Self::MessageEpochTooOld
            | Self::UnbufferedFarFutureMessage
            | Self::StaleCommit
            | Self::StaleProposal
            | Self::DecryptionError
            | Self::IdentityInitializationError
            | Self::MlsGroupInvalidState(_)
            | Self::MlsMessageInvalidState(_)
            | Self::InvalidTransientMessageEpoch { .. }
            | Self::MissingExternalSenderExtension
            | Self::MissingGroupInfo
            | Self::PendingCommitNotFound
            | Self::PendingConversationNotFound
            | Self::ClearingPendingCommitError
            | Self::SelfCommitIgnored
            | Self::CallerError(_)
            | Self::OrphanWelcome
            | Self::DuplicateSignature { .. }
            | Self::Tls(_) => false,
        }
    }
}

impl Infrastructural for crate::transaction_context::Error {
    // Every variant is listed, so that adding one forces a decision about whether it is infrastructure.
    fn is_infrastructure(&self) -> bool {
        match self {
            Self::Keystore(_)
            | Self::InvalidTransactionContext
            | Self::ProteusNotInitialized
            | Self::PkiEnvironmentUnset => true,
            Self::OpenMls(openmls) => openmls.is_infrastructure(),
            Self::Recursive(recursive) => recursive.is_infrastructure(),
            Self::CallerError(_)
            | Self::ConversationAlreadyExists(_)
            | Self::ConversationNotFound(_)
            | Self::PendingConversation(_)
            | Self::CredentialStillInUse
            | Self::WrongCredential
            | Self::InvalidCredentials(_)
            | Self::KeypackageNew(_) => false,
        }
    }
}

impl Infrastructural for crate::mls::session::Error {
    fn is_infrastructure(&self) -> bool {
        match self {
            Self::Keystore(_) | Self::MlsNotInitialized => true,
            Self::OpenMls(openmls) => openmls.is_infrastructure(),
            Self::Recursive(recursive) => recursive.is_infrastructure(),
            _ => false,
        }
    }
}

impl Infrastructural for crate::mls::credential::Error {
    fn is_infrastructure(&self) -> bool {
        match self {
            // x509 identities can't be checked until the client sets up the PKI environment
            Self::Keystore(_) | Self::MissingPKIEnvironment => true,
            Self::OpenMls(openmls) => openmls.is_infrastructure(),
            Self::Recursive(recursive) => recursive.is_infrastructure(),
            _ => false,
        }
    }
}

impl Infrastructural for wire_e2e_identity::E2eIdentityError {
    fn is_infrastructure(&self) -> bool {
        // The PKI environment reads its trust anchors and CRLs from the keystore.
        matches!(
            self,
            Self::PkiEnvError(wire_e2e_identity::pki_env::Error::KeystoreError(_))
        )
    }
}

#[cfg(test)]
impl Infrastructural for crate::test_utils::TestError {
    fn is_infrastructure(&self) -> bool {
        match self {
            Self::Recursive(recursive) => recursive.is_infrastructure(),
            Self::ImplementationError => false,
        }
    }
}

impl Infrastructural for crate::OpenMlsError {
    fn is_infrastructure(&self) -> bool {
        self.source.is_infrastructure()
    }
}

// openmls writes through our keystore, and reports a failure there as a `StorageError` variant, either directly or
// nested inside another error. Errors without such a variant can't carry one.
impl Infrastructural for crate::OpenMlsErrorKind {
    fn is_infrastructure(&self) -> bool {
        use openmls::prelude::{
            AddMembersError, CommitToPendingProposalsError, ExternalCommitBuilderError,
            ExternalCommitBuilderFinalizeError, ExternalCommitError, KeyPackageNewError, MergePendingCommitError,
            NewGroupError, ProcessMessageError, ProposeAddMemberError, ProposeRemoveMemberError, RemoveMembersError,
            SelfUpdateError, WelcomeError,
        };

        match self {
            Self::KeystoreError(_) => true,
            // a failure of the process's source of randomness, not of the input
            Self::ProviderError(
                crate::mls_provider::Error::RngLockPoison | crate::mls_provider::Error::InsufficientEntropy,
            ) => true,
            Self::MlsWelcomeError(WelcomeError::StorageError(_))
            | Self::MlsNewGroupError(NewGroupError::StorageError(_))
            | Self::MlsAddMembersError(AddMembersError::StorageError(_))
            | Self::MlsRemoveMembersError(RemoveMembersError::StorageError(_))
            | Self::MlsSelfUpdateError(SelfUpdateError::StorageError(_))
            | Self::MlsCommitToPendingProposalsError(CommitToPendingProposalsError::StorageError(_))
            | Self::MlsMessageError(ProcessMessageError::StorageError(_))
            | Self::MlsExternalCommitError(ExternalCommitError::StorageError(_))
            | Self::MlsExternalCommitBuilderError(ExternalCommitBuilderError::StorageError(_))
            | Self::MlsExternalCommitBuilderFinalizeError(ExternalCommitBuilderFinalizeError::StorageError(_))
            | Self::ProposeAddMemberError(ProposeAddMemberError::StorageError(_))
            | Self::ProposeRemoveMemberError(ProposeRemoveMemberError::StorageError(_))
            | Self::MlsKeyPackageBundleNewError(KeyPackageNewError::StorageError)
            | Self::MlsRemoveProposalError(openmls::group::RemoveProposalError::Storage(_)) => true,
            Self::MlsCommitBuilderStageError(err)
            | Self::MlsAddMembersError(AddMembersError::CommitBuilderStageError(err))
            | Self::MlsRemoveMembersError(RemoveMembersError::CommitBuilderStageError(err))
            | Self::MlsSelfUpdateError(SelfUpdateError::CommitBuilderStageError(err))
            | Self::MlsCommitToPendingProposalsError(CommitToPendingProposalsError::CommitBuilderStageError(err)) => {
                matches!(err, openmls::prelude::CommitBuilderStageError::KeyStoreError(_))
            }
            Self::MlsMergeCommitError(err)
            | Self::MlsMergePendingCommitError(MergePendingCommitError::MergeCommitError(err))
            | Self::MlsExternalCommitBuilderFinalizeError(ExternalCommitBuilderFinalizeError::MergeCommitError(
                MergePendingCommitError::MergeCommitError(err),
            )) => {
                matches!(err, openmls::prelude::MergeCommitError::StorageError(_))
            }
            _ => false,
        }
    }
}
