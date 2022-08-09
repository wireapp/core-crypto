// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

/// CoreCrypto errors
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// This error is emitted when the requested conversation couldn't be found in our store
    #[error("Couldn't find conversation")]
    ConversationNotFound(crate::ConversationId),
    /// This error is emitted when the requested client couldn't be found in MLS group
    #[error("Couldn't find client")]
    ClientNotFound(crate::ClientId),
    /// This error is emitted when we find a malformed (i.e. not uuid) or empty identifier
    #[error("Malformed identifier found: {0}")]
    MalformedIdentifier(String),
    /// The keystore has no knowledge of such client; this shouldn't happen as Client::init is failsafe (find-else-create)
    #[error("The provided client signature has not been found in the keystore")]
    ClientSignatureNotFound,
    /// The keystore has found the client, but the provided signature doesn't match against what is stored
    #[error("The provided client signature doesn't match the keystore's")]
    ClientSignatureMismatch,
    /// !!!! Something went very wrong and one of our locks has been poisoned by an in-thread panic !!!!
    #[error("One of the locks has been poisoned")]
    LockPoisonError,
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    ImplementationError,
    /// A conversation member is out of local stored keypackages - if it does happen something went wrong
    #[error("Member #{0:x?} is out of keypackages")]
    OutOfKeyPackage(crate::member::MemberId),
    /// Errors that are sent by our MLS Provider
    #[error(transparent)]
    MlsProviderError(#[from] mls_crypto_provider::MlsProviderError),
    /// Errors that are sent by our Keystore
    #[error(transparent)]
    KeyStoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    /// MLS Internal Errors
    #[error(transparent)]
    MlsError(#[from] MlsError),
    /// UUID-related errors
    #[cfg(test)]
    #[error(transparent)]
    UuidError(#[from] uuid::Error),
    /// Error when parsing `str`s that are not UTF-8
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
    /// Error when parsing `String`s that are not UTF-8
    #[error(transparent)]
    StringUtf8Error(#[from] std::string::FromUtf8Error),
    /// Error when trying to coerce ints into Strings
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    /// Error when trying to convert integer sizes - usually when they don't fit
    #[error(transparent)]
    ConvertIntError(#[from] std::num::TryFromIntError),
    /// Error when trying to coerce a Vec<u8> into a [u8 ; N]
    #[error("Byte array supplied did not have the expected size {0}")]
    InvalidByteArrayError(usize),
    /// Standard I/O Error
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Authorization error
    #[error("The current client id isn't authorized to perform this action")]
    Unauthorized,
    /// Calbacks are not informed
    #[error("The callback interface in the MlsCentral was not informed")]
    CallbacksNotSet,
    /// External Add Proposal Validation failed
    #[error("External add proposal validation failed: only users already in the group are allowed")]
    ExternalAddProposalError,
}

/// A simpler definition for Result types that the Error is a [CryptoError]
pub type CryptoResult<T> = Result<T, CryptoError>;

/// MLS-specific error wrapper - see github.com/openmls/openmls for details
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// Welcome error
    #[error(transparent)]
    MlsWelcomeError(#[from] openmls::prelude::WelcomeError),
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
    MlsNewGroupError(#[from] openmls::prelude::NewGroupError),
    /// Add members error
    #[error(transparent)]
    MlsAddMembersError(#[from] openmls::prelude::AddMembersError),
    /// Remove members error
    #[error(transparent)]
    MlsRemoveMembersError(#[from] openmls::prelude::RemoveMembersError),
    /// Unverified message error
    #[error(transparent)]
    MlsUnverifiedMessageError(#[from] openmls::prelude::UnverifiedMessageError),
    /// Parse message error
    #[error(transparent)]
    MlsParseMessageError(#[from] openmls::prelude::ParseMessageError),
    /// [openmls::key_packages::KeyPackageBundle] new error
    #[error(transparent)]
    MlsKeyPackageBundleNewError(#[from] openmls::prelude::KeyPackageBundleNewError),
    /// Self update error
    #[error(transparent)]
    MlsSelfUpdateError(#[from] openmls::prelude::SelfUpdateError),
    /// Group state error
    #[error(transparent)]
    MlsMlsGroupStateError(#[from] openmls::prelude::MlsGroupStateError),
    /// MlsMessage error
    #[error(transparent)]
    MlsMessageError(#[from] openmls::framing::errors::MlsMessageError),
    /// Propose add members error
    #[error(transparent)]
    ProposeAddMemberError(#[from] openmls::prelude::ProposeAddMemberError),
    /// Propose self update error
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] openmls::prelude::ProposeSelfUpdateError),
    /// Propose remove members error
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] openmls::prelude::ProposeRemoveMemberError),
    /// Commit to pending proposals error
    #[error(transparent)]
    MlsCommitToPendingProposalsError(#[from] openmls::prelude::CommitToPendingProposalsError),
    /// Export public group state error
    #[error(transparent)]
    MlsExportPublicGroupStateError(#[from] openmls::prelude::ExportPublicGroupStateError),
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
    /// External Commit error
    #[error(transparent)]
    MlsCryptoError(#[from] openmls::prelude::CryptoError),
}
