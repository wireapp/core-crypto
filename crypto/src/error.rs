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

use crate::mls::conversation::config::MAX_PAST_EPOCHS;
use crate::prelude::{E2eIdentityError, MlsCredentialType};

/// CoreCrypto errors
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum CryptoError {
    /// End to end identity error
    #[error("End to end identity error")]
    E2eiError(#[from] E2eIdentityError),
    /// This error is emitted when the requested conversation couldn't be found in our store
    #[error("Couldn't find conversation")]
    ConversationNotFound(crate::prelude::ConversationId),
    /// This error is emitted when the requested conversation already exists with the given if
    #[error("Conversation already exists")]
    ConversationAlreadyExists(crate::prelude::ConversationId),
    /// This error is emitted when the requested client couldn't be found in MLS group
    #[error("Couldn't find client")]
    ClientNotFound(crate::prelude::ClientId),
    /// This error is emitted when a pending proposal couldn't be found in MLS group
    #[error("Couldn't find pending proposal {0}")]
    PendingProposalNotFound(crate::mls::proposal::MlsProposalRef),
    /// This error is emitted when a pending commmit couldn't be found in MLS group
    #[error("Couldn't find pending commit")]
    PendingCommitNotFound,
    /// This error is emitted when we find a malformed (i.e. not uuid) or empty identifier
    #[error("Malformed or empty identifier found: {0}")]
    MalformedIdentifier(&'static str),
    /// The keystore has no knowledge of such client; this shouldn't happen as Client::init is failsafe (find-else-create)
    #[error("The provided client signature has not been found in the keystore")]
    ClientSignatureNotFound,
    /// The keystore already has a stored identity. As such, we cannot create a new raw identity
    #[error("The keystore already contains a stored identity. Cannot create a new one!")]
    IdentityAlreadyPresent,
    /// This error occurs when we cannot find any provisional keypair in the store, indicating that the `generate_raw_keypair` method hasn't been called.
    #[error(
        r#"The externally-generated client ID initialization cannot continue - there's no provisional keypair in-store!

        Have you called `CoreCrypto::generate_raw_keypair` ?"#
    )]
    NoProvisionalIdentityFound,
    /// This error occurs when during the MLS external client generation, we end up with more than one client identity in store.
    ///
    /// This is usually not possible, unless there's some kind of concurrency issue
    /// on the consumer (creating an ext-gen client AND a normal one at the same time for instance)
    #[error(
        "Somehow CoreCrypto holds more than one MLS identity. Something might've gone very wrong with this client!"
    )]
    TooManyIdentitiesPresent,
    /// !!!! Something went very wrong and one of our locks has been poisoned by an in-thread panic !!!!
    #[error("One of the locks has been poisoned")]
    LockPoisonError,
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    ImplementationError,
    /// Tried to insert an already existing CredentialBundle
    #[error("Tried to insert an already existing CredentialBundle")]
    CredentialBundleConflict,
    /// The consumer of this library has misused it
    #[error("The consumer of this library has misused it")]
    ConsumerError,
    /// Errors that are sent by our MLS Provider
    #[error(transparent)]
    MlsProviderError(#[from] mls_crypto_provider::MlsProviderError),
    /// Errors that are sent by our Keystore
    #[error(transparent)]
    KeyStoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    /// MLS Internal Errors
    #[error(transparent)]
    MlsError(MlsError),
    /// UUID-related errors
    #[cfg(test)]
    #[error(transparent)]
    UuidError(#[from] uuid::Error),
    /// Error when parsing `str`s that are not valid UTF-8
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
    /// Error when parsing `String`s that are not valid UTF-8
    #[error(transparent)]
    StringUtf8Error(#[from] std::string::FromUtf8Error),
    /// Error when trying to coerce ints into Strings
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    /// Error when trying to convert integer sizes - usually when they don't fit
    #[error(transparent)]
    ConvertIntError(#[from] std::num::TryFromIntError),
    /// Error when trying to decode an hex-encoded string. Usually that means that the length of the hex string is odd - should be always even
    #[error(transparent)]
    HexDecodeError(#[from] hex::FromHexError),
    /// Error when trying to coerce a `Vec<u8>` into a `[u8; N]`
    #[error("Byte array supplied did not have the expected size {0}")]
    InvalidByteArrayError(usize),
    /// Standard I/O Error
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Authorization error
    #[error("The current client id isn't authorized to perform this action")]
    Unauthorized,
    /// Callbacks are not provided
    #[error("The callbacks needed for CoreCrypto to operate were not set")]
    CallbacksNotSet,
    /// External Add Proposal Validation failed
    #[error("External add proposal validation failed: only users already in the group are allowed")]
    UnauthorizedExternalAddProposal,
    /// External Commit sender was not authorized to perform such
    #[error("External Commit sender was not authorized to perform such")]
    UnauthorizedExternalCommit,
    /// A supplied [`HashReference`] is not of the expected size: 16
    #[error("A supplied reference is not of the expected size: 16")]
    InvalidHashReference,
    /// Tried to decrypt a message in the wrong epoch
    #[error("Decrypted an application message from the wrong epoch")]
    DecryptionError,
    /// Incoming message is for the wrong epoch
    #[error("Incoming message is for the wrong epoch")]
    WrongEpoch,
    /// Incoming message is for a future epoch. We will buffer it until the commit for that epoch arrives
    #[error("Incoming message is for a future epoch. We will buffer it until the commit for that epoch arrives")]
    BufferedFutureMessage,
    /// Proteus Error Wrapper
    #[error(transparent)]
    ProteusError(#[from] ProteusError),
    /// Cryptobox migration error wrapper
    #[error(transparent)]
    CryptoboxMigrationError(#[from] CryptoboxMigrationError),
    /// The proteus client has been called but has not been initialized yet
    #[error("Proteus client hasn't been initialized")]
    ProteusNotInitialized,
    /// CoreCrypto hasn't been built with the `proteus` feature enabled, meaning proteus isn't built in
    #[error("CoreCrypto hasn't been built with Proteus support enabled; The feature `{0}` isn't enabled")]
    ProteusSupportNotEnabled(String),
    /// A MLS operation was requested but MLS hasn't been initialized on this instance
    #[error("A MLS operation was requested but MLS hasn't been initialized on this instance")]
    MlsNotInitialized,
    /// Decrypted message uses an invalid KeyPackage (probably expired)
    #[error("Decrypted message uses an invalid KeyPackage")]
    InvalidKeyPackage,
    /// Client presented an invalid identity
    #[error("Client presented an invalid identity")]
    InvalidIdentity,
    /// MLS Client was not initialized the right way
    #[error("MLS Client was not initialized the right way")]
    IdentityInitializationError,
    /// Parent group cannot be found
    #[error("The specified parent group has not been found in the keystore")]
    ParentGroupNotFound,
    /// Message epoch is too old
    #[error("The epoch in which message was encrypted is older than {MAX_PAST_EPOCHS}")]
    MessageEpochTooOld,
    /// When looking for a X509 credential for a given ciphersuite and it has not been done
    #[error("End-to-end identity enrollment has not been done")]
    E2eiEnrollmentNotDone,
    /// A Credential was not found locally which is very likely an implementation error
    #[error("A Credential of type {0:?} was not found locally which is very likely an implementation error")]
    CredentialNotFound(MlsCredentialType),
    /// The MLS group is in an invalid state for an unknown reason
    #[error("The MLS group is in an invalid state for an unknown reason")]
    InternalMlsError,
    /// We already decrypted this message once
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    /// This method leaks entities whereas it's not supposed to
    #[cfg(test)]
    #[error("This method leaks entities whereas it's not supposed to")]
    LeakEntities,
    /// This method does not create new entities whereas it's supposed to
    #[cfg(test)]
    #[error("This method does not create new entities whereas it's supposed to")]
    NoEntityCreated,
    /// Happens when a client creates a commit, sends it to the DS which accepts it but then client
    /// clears this pending commit and creates another commit. This is triggered when the client
    /// tries to decrypt the original commit. This means something is very wrong in the client's
    /// code and has to be fixed immediately
    #[error("Happens when a client creates a commit, sends it to the DS which accepts it but then client \
    clears this pending commit and creates another commit. This is triggered when the client tries to decrypt the original commit.\
    This means something is very wrong in the client's code and has to be fixed immediately")]
    ClearingPendingCommitError,
    /// Tried to decrypt a commit created by self which is likely to have been replayed by the DS
    #[error("Tried to decrypt a commit created by self which is likely to have been replayed by the DS")]
    SelfCommitIgnored,
    /// You tried to join with an external commit but did not merge it yet. We will reapply this message for you when you merge your external commit
    #[error(
        "You tried to join with an external commit but did not merge it yet. We will reapply this message for you when you merge your external commit"
    )]
    UnmergedPendingGroup,
    /// see [`x509_cert::der::Error`]
    #[error(transparent)]
    X509CertDerError(#[from] x509_cert::der::Error),
    /// see [`pem::PemError`]
    #[error(transparent)]
    PemError(#[from] pem::PemError),
    /// Domain name not found in the certificate
    #[error("Could not find domain name in the certificate")]
    DomainNameNotFound,
    /// The provided domain name and the one found in the certificate don't match
    #[error("The provided domain name and the one found in the certificate don't match")]
    DomainNamesDontMatch,
    /// A trust anchor with the provided domain name already exists in the group's context
    /// extensions
    #[error("A trust anchor with the provided domain name already exists in the group's context extensions")]
    DuplicateDomainName,
    /// The certificate chain is invalid or not complete
    #[error("The certificate chain is invalid or not complete")]
    InvalidCertificateChain,
    /// Emtpy trust anchor update
    #[error("The update anchors parameters can't be empty")]
    EmptyTrustAnchorUpdate,
    /// Adding a certificate chain already in the group's context
    #[error("The certificate chain is already in the group's context")]
    DuplicateCertificateChain,
    /// This happens when the DS cannot flag KeyPackages as claimed or not. It this scenario, a client
    /// requests their old KeyPackages to be deleted but one has already been claimed by another client to create a Welcome.
    /// In that case the only solution is that the client receiving such a Welcome tries to join the group
    /// with an External Commit instead
    #[error("Although this Welcome seems valid, the local KeyPackage it references has already been deleted locally. Join this group with an external commit")]
    OrphanWelcome,
    /// The encountered ClientId does not match Wire's definition
    #[error("The encountered ClientId does not match Wire's definition")]
    InvalidClientId,
    /// Json error
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}

impl From<MlsError> for CryptoError {
    fn from(err: MlsError) -> Self {
        match err {
            MlsError::MlsAddMembersError(openmls::prelude::AddMembersError::KeyPackageVerifyError(
                openmls::key_packages::errors::KeyPackageVerifyError::InvalidLeafNode(
                    openmls::prelude::LeafNodeValidationError::InvalidCredential(
                        openmls::credentials::errors::CredentialError::AuthenticationServiceValidationFailure(
                            openmls_traits::authentication_service::CredentialAuthenticationStatus::Invalid,
                        ),
                    ),
                ),
            )) => Self::InvalidIdentity,
            e => Self::MlsError(e),
        }
    }
}

/// A simpler definition for Result types that the Error is a [CryptoError]
pub type CryptoResult<T> = Result<T, CryptoError>;

impl CryptoError {
    /// Returns the proteus error code
    pub fn proteus_error_code(&self) -> u32 {
        let Self::ProteusError(e) = self else {
            return 0;
        };
        e.error_code()
    }
}

/// MLS-specific error wrapper - see github.com/openmls/openmls for details
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum MlsError {
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
    /// [openmls::key_packages::KeyPackageBundle] new error
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
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
/// Wrapper for Proteus-related errors
pub enum ProteusError {
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    /// Error when decoding CBOR and/or decrypting Proteus messages
    ProteusDecodeError(#[from] proteus_wasm::DecodeError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    /// Error when encoding CBOR and/or decrypting Proteus messages
    ProteusEncodeError(#[from] proteus_wasm::EncodeError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    /// Various internal Proteus errors
    ProteusInternalError(#[from] proteus_wasm::error::ProteusError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    /// Error when there's a critical error within a proteus Session
    ProteusSessionError(#[from] proteus_wasm::session::Error<core_crypto_keystore::CryptoKeystoreError>),
}

impl ProteusError {
    /// Returns the proteus error code
    pub fn error_code(&self) -> u32 {
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                use proteus_traits::ProteusErrorCode as _;
                match self {
                    ProteusError::ProteusDecodeError(e) => e.code() as u32,
                    ProteusError::ProteusEncodeError(e) => e.code() as u32,
                    ProteusError::ProteusSessionError(e) => e.code() as u32,
                    ProteusError::ProteusInternalError(e) => e.code() as u32,
                }
            } else {
                0
            }
        }
    }
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
/// Wrapper for errors that can happen during a Cryptobox migration
pub enum CryptoboxMigrationError {
    #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))]
    #[error(transparent)]
    /// IndexedDB Error
    RexieError(#[from] rexie::Error),
    #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))]
    #[error(transparent)]
    /// Error when parsing/serializing JSON payloads from the WASM boundary
    JsonParseError(#[from] serde_wasm_bindgen::Error),
    #[cfg(all(feature = "cryptobox-migrate", target_family = "wasm"))]
    #[error(transparent)]
    /// Error when decoding base64
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("The targeted value does not possess the targeted key ({0})")]
    /// Error when trying to fetch a certain key from a structured value
    MissingKeyInValue(String),
    #[error("The value cannot be coerced to the {0} type")]
    /// Error when trying to coerce a certain value to a certain type
    WrongValueType(String),
    #[cfg_attr(target_family = "wasm", error("The provided path [{0}] could not be found."))]
    #[cfg_attr(
        not(target_family = "wasm"),
        error("The provided path store [{0}] is either non-existent or has an incorrect shape.")
    )]
    /// Error when trying to open a Cryptobox store that doesn't exist
    ProvidedPathDoesNotExist(String),
    #[error("The Cryptobox identity at path [{0}] could not be found.")]
    /// Error when inspecting a Cryptobox store that doesn't contain an Identity
    IdentityNotFound(String),
}
