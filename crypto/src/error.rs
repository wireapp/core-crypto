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
    /// This error is emitted when we find a malformed (i.e. not uuid) or empty identifier
    #[error("Malformed identifier found: {0}")]
    MalformedIdentifier(String),
    /// The keystore has no knowledge of such client; this shouldn't happen as Client::init is failsafe (find-else-create)
    #[error("The provided client signature has not been found in the keystore")]
    ClientSignatureNotFound,
    /// !!!! Something went very wrong and one of our locks has been poisoned by an in-thread panic !!!!
    #[error("One of the locks has been poisoned")]
    LockPoisonError,
    /// A conversation member is out of local stored keypackages - if it does happen something went wrong
    #[error("Member #{0:x?} is out of keypackages")]
    OutOfKeyPackage(crate::member::MemberId),
    /// There was an issue when configuring a new conversation
    #[error(transparent)]
    ConversationConfigurationError(#[from] crate::conversation::MlsConversationConfigurationBuilderError),
    #[error(transparent)]
    CentralConfigurationError(#[from] crate::MlsCentralConfigurationBuilderError),
    /// Errors that are sent by our Keystore
    #[error(transparent)]
    KeyStoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    /// MLS Internal Errors
    #[error(transparent)]
    MlsError(#[from] MlsError),
    /// UUID-related errors
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
    #[error("The current client id isn't authorized to perform this action")]
    Unauthorized,
    /// Other thingies
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

/// MLS-specific error wrapper - see github.com/openmls/openmls for details
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error(transparent)]
    MlsWelcomeError(#[from] openmls::prelude::WelcomeError),
    #[error(transparent)]
    MlsLibraryError(#[from] openmls::error::LibraryError),
    #[error(transparent)]
    MlsInvalidMessageError(#[from] openmls::prelude::CreateMessageError),
    #[error(transparent)]
    MlsEmptyInputError(#[from] openmls::prelude::EmptyInputError),
    #[error(transparent)]
    MlsCredentialError(#[from] openmls::prelude::CredentialError),
    #[error(transparent)]
    MlsNewGroupError(#[from] openmls::prelude::NewGroupError),
    #[error(transparent)]
    MlsLeaveGroupError(#[from] openmls::prelude::LeaveGroupError),
    #[error(transparent)]
    MlsAddMembersError(#[from] openmls::prelude::AddMembersError),
    #[error(transparent)]
    MlsRemoveMembersError(#[from] openmls::prelude::RemoveMembersError),
    #[error(transparent)]
    MlsUnverifiedMessageError(#[from] openmls::prelude::UnverifiedMessageError),
    #[error(transparent)]
    MlsParseMessageError(#[from] openmls::prelude::ParseMessageError),
    #[error(transparent)]
    MlsKeyPackageBundleNewError(#[from] openmls::prelude::KeyPackageBundleNewError),
    #[error(transparent)]
    MlsSelfUpdateError(#[from] openmls::prelude::SelfUpdateError),
    #[error(transparent)]
    MlsMlsGroupStateError(#[from] openmls::prelude::MlsGroupStateError),
    #[error(transparent)]
    MlsMessageError(#[from] openmls::framing::errors::MlsMessageError),
    #[error(transparent)]
    MlsTlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    MlsErrorString(#[from] openmls::error::ErrorString),
}
