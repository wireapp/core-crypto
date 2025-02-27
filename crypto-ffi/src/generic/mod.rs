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

use std::{
    collections::{BTreeMap, HashMap},
    ops::Deref,
    sync::{Arc, LazyLock, Once},
};

use log::{
    Level, LevelFilter, Metadata, Record,
    kv::{self, Key, Value, VisitSource},
};
use log_reload::ReloadLog;
use tls_codec::Deserialize;

use self::context::CoreCryptoContext;
use crate::{UniffiCustomTypeConverter, proteus_impl};
pub use core_crypto::prelude::ConversationId;
use core_crypto::{
    InnermostErrorMessage, RecursiveError,
    prelude::{
        EntropySeed, MlsBufferedConversationDecryptMessage, MlsCentral, MlsCentralConfiguration, MlsCiphersuite,
        MlsCommitBundle, MlsConversationDecryptMessage, MlsCustomConfiguration, MlsGroupInfoBundle, MlsProposalBundle,
        VerifiableGroupInfo,
    },
};

pub mod context;

#[allow(dead_code)]
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

#[uniffi::export]
pub fn version() -> String {
    VERSION.to_string()
}

#[derive(uniffi::Record)]
/// Metadata describing the conditions of the build of this software.
pub struct BuildMetadata {
    /// Build Timestamp
    pub timestamp: String,
    /// Whether this build was in Debug mode (true) or Release mode (false)
    pub cargo_debug: String,
    /// Features enabled for this build
    pub cargo_features: String,
    /// Optimization level
    pub opt_level: String,
    /// Build target triple
    pub target_triple: String,
    /// Git branch
    pub git_branch: String,
    /// Output of `git describe`
    pub git_describe: String,
    /// Hash of current git commit
    pub git_sha: String,
    /// `true` when the source code differed from the commit at the most recent git hash
    pub git_dirty: String,
}

#[uniffi::export]
pub fn build_metadata() -> BuildMetadata {
    BuildMetadata {
        timestamp: core_crypto::BUILD_METADATA.timestamp.to_string(),
        cargo_debug: core_crypto::BUILD_METADATA.cargo_debug.to_string(),
        cargo_features: core_crypto::BUILD_METADATA.cargo_features.to_string(),
        opt_level: core_crypto::BUILD_METADATA.opt_level.to_string(),
        target_triple: core_crypto::BUILD_METADATA.target_triple.to_string(),
        git_branch: core_crypto::BUILD_METADATA.git_branch.to_string(),
        git_describe: core_crypto::BUILD_METADATA.git_describe.to_string(),
        git_sha: core_crypto::BUILD_METADATA.git_sha.to_string(),
        git_dirty: core_crypto::BUILD_METADATA.git_dirty.to_string(),
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MlsError {
    #[error("Conversation already exists")]
    ConversationAlreadyExists(core_crypto::prelude::ConversationId),
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    #[error("Incoming message is for a future epoch. We will buffer it until the commit for that epoch arrives")]
    BufferedFutureMessage,
    #[error("Incoming message is from an epoch too far in the future to buffer.")]
    WrongEpoch,
    #[error(
        "Incoming message is a commit for which we have not yet received all the proposals. Buffering until all proposals have arrived."
    )]
    BufferedCommit,
    #[error("The epoch in which message was encrypted is older than allowed")]
    MessageEpochTooOld,
    #[error("Tried to decrypt a commit created by self which is likely to have been replayed by the DS")]
    SelfCommitIgnored,
    #[error(
        "You tried to join with an external commit but did not merge it yet. We will reapply this message for you when you merge your external commit"
    )]
    UnmergedPendingGroup,
    #[error("The received proposal is deemed stale and is from an older epoch.")]
    StaleProposal,
    #[error("The received commit is deemed stale and is from an older epoch.")]
    StaleCommit,
    /// This happens when the DS cannot flag KeyPackages as claimed or not. It this scenario, a client
    /// requests their old KeyPackages to be deleted but one has already been claimed by another client to create a Welcome.
    /// In that case the only solution is that the client receiving such a Welcome tries to join the group
    /// with an External Commit instead
    #[error(
        "Although this Welcome seems valid, the local KeyPackage it references has already been deleted locally. Join this group with an external commit"
    )]
    OrphanWelcome,
    /// Message rejected by the delivery service
    #[error("Message rejected by the delivery service. Reason: {reason}")]
    MessageRejected {
        /// Why was the message rejected by the delivery service?
        reason: String,
    },
    #[error("{0}")]
    Other(String),
}

impl From<core_crypto::MlsError> for MlsError {
    #[inline]
    fn from(e: core_crypto::MlsError) -> Self {
        Self::Other(e.innermost_error_message())
    }
}

#[cfg(feature = "proteus")]
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ProteusError {
    #[error("The requested session was not found")]
    SessionNotFound,
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    #[error("The remote identity has changed")]
    RemoteIdentityChanged,
    #[error("Another Proteus error occurred but the details are probably irrelevant to clients")]
    Other(u16),
}

#[cfg(feature = "proteus")]
impl ProteusError {
    pub fn from_error_code(code: u16) -> Self {
        match code {
            102 => Self::SessionNotFound,
            204 => Self::RemoteIdentityChanged,
            209 => Self::DuplicateMessage,
            _ => Self::Other(code),
        }
    }

    pub fn error_code(&self) -> u16 {
        match self {
            Self::SessionNotFound => 102,
            Self::RemoteIdentityChanged => 204,
            Self::DuplicateMessage => 209,
            Self::Other(code) => *code,
        }
    }
}

#[cfg(feature = "proteus")]
impl From<core_crypto::ProteusError> for ProteusError {
    fn from(value: core_crypto::ProteusError) -> Self {
        type SessionError = proteus_wasm::session::Error<core_crypto_keystore::CryptoKeystoreError>;
        match value.source {
            core_crypto::ProteusErrorKind::ProteusSessionError(SessionError::InternalError(
                proteus_wasm::internal::types::InternalError::NoSessionForTag,
            )) => Self::SessionNotFound,
            core_crypto::ProteusErrorKind::ProteusSessionError(SessionError::DuplicateMessage) => {
                Self::DuplicateMessage
            }
            core_crypto::ProteusErrorKind::ProteusSessionError(SessionError::RemoteIdentityChanged) => {
                Self::RemoteIdentityChanged
            }
            _ => Self::Other(value.source.error_code().unwrap_or_default()),
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreCryptoError {
    #[error(transparent)]
    Mls(#[from] MlsError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    Proteus(#[from] ProteusError),
    #[error("End to end identity error: {0}")]
    E2eiError(String),
    #[error("error from client: {0}")]
    ClientError(String),
    #[error("{0}")]
    Other(String),
}

/// Prepare and dispatch a log message reporting this error.
///
/// We want to ensure consistent logging every time we pass a log message across the FFI boundary,
/// as we cannot guarantee the method, format, or existence of error logging once the result crosses.
/// Unfortunately, as there is no single point at which we convert internal errors to trans-ffi
/// errors, we need to extract the logging procedure and ensure it's called at each relevant point.
///
/// This has the further disadvantage that we have very little context information at the point of
/// logging. We'll try this out for now anyway; if it turns out that we need to add more tracing
/// in the future, we can figure out our techniques then.
fn log_error(error: &dyn std::error::Error) {
    // we exclude the original error message from the chain
    let chain = {
        let mut error = error;
        let mut chain = Vec::new();
        while let Some(inner) = error.source() {
            chain.push(inner.to_string());
            error = inner;
        }
        chain
    };
    let msg = error.to_string();
    let err = serde_json::json!({"msg": msg, "chain": chain});
    // even though there exists a `:err` formatter, it only captures the top-level
    // message from the error, so it's still worth building our own inner error formatter
    // and using serde here
    log::warn!(target: "core-crypto", err:serde; "core-crypto returning this error across ffi; see recent log messages for context");
}

impl From<RecursiveError> for CoreCryptoError {
    fn from(error: RecursiveError) -> Self {
        log_error(&error);

        // check if the innermost error is any kind of e2e error
        let innermost = {
            let mut err: &dyn std::error::Error = &error;
            while let Some(inner) = err.source() {
                err = inner;
            }
            err
        };

        if let Some(err) = innermost.downcast_ref::<core_crypto::e2e_identity::Error>() {
            return CoreCryptoError::E2eiError(err.to_string());
        }

        // What now? We only really care about the innermost variants, not the error stack, but that produces
        // an arbitrary set of types. We can't match against that!
        //
        // Or at least, not without the power of macros. We can use them to match against heterogenous types.

        /// Like [`matches!`], but with an out expression which can reference items captured by the pattern.
        ///
        /// Hopefully only ever use this in conjunction with `interior_matches!`, because for most sane
        /// circumstances, `if let` is the better design pattern.
        macro_rules! matches_option {
            ($val:expr, $pattern:pat $(if $guard:expr)? => $out:expr) => {
                match ($val) {
                    $pattern $(if $guard)? => Some($out),
                    _ => None,
                }
            };
        }

        /// This is moderately horrific and we hopefully will not require it anywhere else, but
        /// it solves a real problem here: how do we match against the innermost error variants,
        /// when we have a heterogenous set of types to match against?
        macro_rules! match_heterogenous {
            ($err:expr => {
                $( $pattern:pat $(if $guard:expr)? => $var:expr, )*
                ||=> $default:expr,
            }) => {{
                if false {unreachable!()}
                $(
                    else if let Some(v) = matches_option!($err.downcast_ref(), Some($pattern) $(if $guard)? => $var) {
                        v
                    }
                )*
                else {
                    $default
                }
            }};
        }

        match_heterogenous!(innermost => {
            core_crypto::LeafError::ConversationAlreadyExists(id) => MlsError::ConversationAlreadyExists(id.clone()).into(),
            core_crypto::mls::conversation::Error::BufferedFutureMessage{..} => MlsError::BufferedFutureMessage.into(),
            core_crypto::mls::conversation::Error::DuplicateMessage => MlsError::DuplicateMessage.into(),
            core_crypto::mls::conversation::Error::MessageEpochTooOld => MlsError::MessageEpochTooOld.into(),
            core_crypto::mls::conversation::Error::SelfCommitIgnored => MlsError::SelfCommitIgnored.into(),
            core_crypto::mls::conversation::Error::StaleCommit => MlsError::StaleCommit.into(),
            core_crypto::mls::conversation::Error::StaleProposal => MlsError::StaleProposal.into(),
            core_crypto::mls::conversation::Error::UnbufferedFarFutureMessage => MlsError::WrongEpoch.into(),
            core_crypto::mls::conversation::Error::BufferedCommit => MlsError::BufferedCommit.into(),
            core_crypto::mls::conversation::Error::MessageRejected { reason } => MlsError::MessageRejected { reason: reason.clone() }.into(),
            core_crypto::mls::conversation::Error::OrphanWelcome => MlsError::OrphanWelcome.into(),
            core_crypto::mls::Error::UnmergedPendingGroup => MlsError::UnmergedPendingGroup.into(),
            ||=> MlsError::Other(error.innermost_error_message()).into(),
        })
    }
}

// This implementation is intended to be temporary; we're going to be completely restructuring the way we handle
// errors in `core-crypto` soon. We can replace this with better error patterns when we do.
//
// Certain error mappings could apply to both MLS and Proteus. In all such cases, we map them to the MLS variant.
// When we redesign the errors in `core-crypto`, these ambiguities should disappear anyway.
impl From<core_crypto::Error> for CoreCryptoError {
    fn from(error: core_crypto::Error) -> Self {
        log_error(&error);

        // we can take care of the _simple_ error-mapping up here.
        #[cfg(feature = "proteus")]
        if let core_crypto::Error::Proteus(proteus) = &error {
            if let Some(code) = proteus.source.error_code() {
                if code != 0 {
                    return Self::Proteus(ProteusError::from_error_code(code));
                }
            }
        }
        match error {
            core_crypto::Error::ProteusNotInitialized => Self::Other("proteus not initialized".to_string()),
            core_crypto::Error::Proteus(proteus) => Self::Other(proteus.innermost_error_message()),
            core_crypto::Error::Mls(mls) => Self::Mls(MlsError::from(mls)),
            core_crypto::Error::InvalidContext => Self::Other(error.to_string()),
            core_crypto::Error::MlsTransportNotProvided => Self::Other(error.to_string()),
            core_crypto::Error::ErrorDuringMlsTransport(error_message) => Self::Other(error_message),
            core_crypto::Error::Keystore(keystore_error) => Self::Other(keystore_error.innermost_error_message()),
            core_crypto::Error::CryptoboxMigration(cryptobox) => Self::Other(cryptobox.innermost_error_message()),
            core_crypto::Error::Recursive(recursive_error) => recursive_error.into(),
            core_crypto::Error::FeatureDisabled(_) => Self::Other(error.to_string()),
        }
    }
}

/// We can't do a generic `impl<E: ToRecursiveError> From<E> for CoreCryptoError`
/// because that has the potential to cause breaking conflicts later on: what if
/// core-crypto later did `impl ToRecursiveError for core_crypto::Error`? That would
/// cause a duplicate `From` impl.
///
/// Instead, we explicitly specify every variant which can be converted to a
/// `CoreCryptoError`, and implement its `From` block directly.
macro_rules! impl_from_via_recursive_error {
    ($($t:ty),+ $(,)?) => {
        $(
            impl From<$t> for CoreCryptoError {
                fn from(error: $t) -> Self {
                    use core_crypto::ToRecursiveError;
                    error
                        .construct_recursive("this context string does not matter and gets immediately stripped")
                        .into()
                }
            }
        )*
    };
}

impl_from_via_recursive_error!(
    core_crypto::mls::Error,
    core_crypto::mls::conversation::Error,
    core_crypto::e2e_identity::Error,
);

impl From<uniffi::UnexpectedUniFFICallbackError> for CoreCryptoError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::ClientError(value.reason)
    }
}

impl CoreCryptoError {
    fn generic<E>() -> impl FnOnce(E) -> Self
    where
        E: ToString,
    {
        |err| Self::Other(err.to_string())
    }
}

type CoreCryptoResult<T> = Result<T, CoreCryptoError>;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ClientId(core_crypto::prelude::ClientId);

uniffi::custom_type!(ClientId, Vec<u8>);

impl UniffiCustomTypeConverter for ClientId {
    type Builtin = Vec<u8>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(Self(core_crypto::prelude::ClientId::from(val)))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.to_vec()
    }
}

#[derive(Debug, Clone, derive_more::From, derive_more::Into)]
pub struct NewCrlDistributionPoints(Option<Vec<String>>);

uniffi::custom_newtype!(NewCrlDistributionPoints, Option<Vec<String>>);

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
#[repr(u16)]
pub enum CiphersuiteName {
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
}

#[derive(Debug, Clone)]
pub struct Ciphersuite(core_crypto::prelude::CiphersuiteName);

uniffi::custom_type!(Ciphersuite, u16);

impl From<core_crypto::prelude::CiphersuiteName> for Ciphersuite {
    fn from(cs: core_crypto::prelude::CiphersuiteName) -> Self {
        Self(cs)
    }
}

impl From<Ciphersuite> for core_crypto::prelude::CiphersuiteName {
    fn from(cs: Ciphersuite) -> Self {
        cs.0
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    fn from(cs: Ciphersuite) -> Self {
        cs.0.into()
    }
}

impl UniffiCustomTypeConverter for Ciphersuite {
    type Builtin = u16;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        core_crypto::prelude::CiphersuiteName::try_from(val)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        (&obj.0).into()
    }
}

#[derive(Debug, Default, Clone)]
pub struct Ciphersuites(Vec<core_crypto::prelude::CiphersuiteName>);

impl From<Vec<core_crypto::prelude::CiphersuiteName>> for Ciphersuites {
    fn from(cs: Vec<core_crypto::prelude::CiphersuiteName>) -> Self {
        Self(cs)
    }
}

impl From<Ciphersuites> for Vec<core_crypto::prelude::CiphersuiteName> {
    fn from(cs: Ciphersuites) -> Self {
        cs.0
    }
}

impl<'a> From<&'a Ciphersuites> for Vec<MlsCiphersuite> {
    fn from(cs: &'a Ciphersuites) -> Self {
        cs.0.iter().fold(Vec::with_capacity(cs.0.len()), |mut acc, c| {
            acc.push((*c).into());
            acc
        })
    }
}

uniffi::custom_type!(Ciphersuites, Vec<u16>);

impl UniffiCustomTypeConverter for Ciphersuites {
    type Builtin = Vec<u16>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        val.iter().try_fold(Self(vec![]), |mut acc, c| -> uniffi::Result<Self> {
            let cs = core_crypto::prelude::CiphersuiteName::try_from(*c)?;
            acc.0.push(cs);
            Ok(acc)
        })
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.into_iter().map(|c| (&c).into()).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
/// Supporting struct for CRL registration result
pub struct CrlRegistration {
    /// Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
    pub dirty: bool,
    /// Optional expiration timestamp
    pub expiration: Option<u64>,
}

impl From<core_crypto::e2e_identity::CrlRegistration> for CrlRegistration {
    fn from(value: core_crypto::e2e_identity::CrlRegistration) -> Self {
        Self {
            dirty: value.dirty,
            expiration: value.expiration,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProteusAutoPrekeyBundle {
    pub id: u16,
    pub pkb: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
/// see [core_crypto::prelude::MlsConversationCreationMessage]
pub struct WelcomeBundle {
    pub id: ConversationId,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl From<core_crypto::prelude::WelcomeBundle> for WelcomeBundle {
    fn from(w: core_crypto::prelude::WelcomeBundle) -> Self {
        Self {
            id: w.id,
            crl_new_distribution_points: w.crl_new_distribution_points.into(),
        }
    }
}

#[derive(Debug, uniffi::Record)]
pub struct CommitBundle {
    pub welcome: Option<Vec<u8>>,
    pub commit: Vec<u8>,
    pub group_info: GroupInfoBundle,
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let (welcome, commit, group_info) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            group_info: group_info.into(),
        })
    }
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum MlsGroupInfoEncryptionType {
    /// Unencrypted `GroupInfo`
    Plaintext = 1,
    /// `GroupInfo` encrypted in a JWE
    JweEncrypted = 2,
}

impl From<core_crypto::prelude::MlsGroupInfoEncryptionType> for MlsGroupInfoEncryptionType {
    fn from(value: core_crypto::prelude::MlsGroupInfoEncryptionType) -> Self {
        match value {
            core_crypto::prelude::MlsGroupInfoEncryptionType::Plaintext => Self::Plaintext,
            core_crypto::prelude::MlsGroupInfoEncryptionType::JweEncrypted => Self::JweEncrypted,
        }
    }
}

impl From<MlsGroupInfoEncryptionType> for core_crypto::prelude::MlsGroupInfoEncryptionType {
    fn from(value: MlsGroupInfoEncryptionType) -> Self {
        match value {
            MlsGroupInfoEncryptionType::Plaintext => Self::Plaintext,
            MlsGroupInfoEncryptionType::JweEncrypted => Self::JweEncrypted,
        }
    }
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum MlsRatchetTreeType {
    /// Plain old and complete `GroupInfo`
    Full = 1,
    /// Contains `GroupInfo` changes since previous epoch (not yet implemented)
    /// (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
    Delta = 2,
    ByRef = 3,
}

impl From<core_crypto::prelude::MlsRatchetTreeType> for MlsRatchetTreeType {
    fn from(value: core_crypto::prelude::MlsRatchetTreeType) -> Self {
        match value {
            core_crypto::prelude::MlsRatchetTreeType::Full => Self::Full,
            core_crypto::prelude::MlsRatchetTreeType::Delta => Self::Delta,
            core_crypto::prelude::MlsRatchetTreeType::ByRef => Self::ByRef,
        }
    }
}

impl From<MlsRatchetTreeType> for core_crypto::prelude::MlsRatchetTreeType {
    fn from(value: MlsRatchetTreeType) -> Self {
        match value {
            MlsRatchetTreeType::Full => Self::Full,
            MlsRatchetTreeType::Delta => Self::Delta,
            MlsRatchetTreeType::ByRef => Self::ByRef,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupInfoBundle {
    pub encryption_type: MlsGroupInfoEncryptionType,
    pub ratchet_tree_type: MlsRatchetTreeType,
    pub payload: Vec<u8>,
}

impl From<MlsGroupInfoBundle> for GroupInfoBundle {
    fn from(gi: MlsGroupInfoBundle) -> Self {
        Self {
            encryption_type: gi.encryption_type.into(),
            ratchet_tree_type: gi.ratchet_tree_type.into(),
            payload: gi.payload.bytes(),
        }
    }
}

#[derive(Debug, uniffi::Record)]
pub struct ProposalBundle {
    pub proposal: Vec<u8>,
    pub proposal_ref: Vec<u8>,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsProposalBundle> for ProposalBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsProposalBundle) -> Result<Self, Self::Error> {
        let (proposal, proposal_ref, crl_new_distribution_points) = msg.to_bytes()?;
        Ok(Self {
            proposal,
            proposal_ref,
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::prelude::decrypt::MlsConversationDecryptMessage]
pub struct DecryptedMessage {
    pub message: Option<Vec<u8>>,
    pub proposals: Vec<ProposalBundle>,
    pub is_active: bool,
    pub commit_delay: Option<u64>,
    pub sender_client_id: Option<ClientId>,
    pub has_epoch_changed: bool,
    pub identity: WireIdentity,
    pub buffered_messages: Option<Vec<BufferedDecryptedMessage>>,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

#[derive(Debug, uniffi::Record)]
/// because Uniffi does not support recursive structs
pub struct BufferedDecryptedMessage {
    pub message: Option<Vec<u8>>,
    pub proposals: Vec<ProposalBundle>,
    pub is_active: bool,
    pub commit_delay: Option<u64>,
    pub sender_client_id: Option<ClientId>,
    pub has_epoch_changed: bool,
    pub identity: WireIdentity,
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsConversationDecryptMessage> for DecryptedMessage {
    type Error = CoreCryptoError;

    fn try_from(from: MlsConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(ProposalBundle::try_from)
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        let buffered_messages = from
            .buffered_messages
            .map(|bm| {
                bm.into_iter()
                    .map(TryInto::try_into)
                    .collect::<CoreCryptoResult<Vec<_>>>()
            })
            .transpose()?;

        Ok(Self {
            message: from.app_msg,
            proposals,
            is_active: from.is_active,
            commit_delay: from.delay,
            sender_client_id: from.sender_client_id.map(ClientId),
            has_epoch_changed: from.has_epoch_changed,
            identity: from.identity.into(),
            buffered_messages,
            crl_new_distribution_points: from.crl_new_distribution_points.into(),
        })
    }
}

impl TryFrom<MlsBufferedConversationDecryptMessage> for BufferedDecryptedMessage {
    type Error = CoreCryptoError;

    fn try_from(from: MlsBufferedConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(ProposalBundle::try_from)
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        Ok(Self {
            message: from.app_msg,
            proposals,
            is_active: from.is_active,
            commit_delay: from.delay,
            sender_client_id: from.sender_client_id.map(ClientId),
            has_epoch_changed: from.has_epoch_changed,
            identity: from.identity.into(),
            crl_new_distribution_points: from.crl_new_distribution_points.into(),
        })
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::prelude::WireIdentity]
pub struct WireIdentity {
    pub client_id: String,
    pub status: DeviceStatus,
    pub thumbprint: String,
    pub credential_type: MlsCredentialType,
    pub x509_identity: Option<X509Identity>,
}

impl From<core_crypto::prelude::WireIdentity> for WireIdentity {
    fn from(i: core_crypto::prelude::WireIdentity) -> Self {
        Self {
            client_id: i.client_id,
            status: i.status.into(),
            thumbprint: i.thumbprint,
            credential_type: i.credential_type.into(),
            x509_identity: i.x509_identity.map(Into::into),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, uniffi::Enum)]
#[repr(u8)]
pub enum DeviceStatus {
    /// All is fine
    Valid = 1,
    /// The Credential's certificate is expired
    Expired = 2,
    /// The Credential's certificate is revoked (not implemented yet)
    Revoked = 3,
}

impl From<core_crypto::prelude::DeviceStatus> for DeviceStatus {
    fn from(value: core_crypto::prelude::DeviceStatus) -> Self {
        match value {
            core_crypto::prelude::DeviceStatus::Valid => Self::Valid,
            core_crypto::prelude::DeviceStatus::Expired => Self::Expired,
            core_crypto::prelude::DeviceStatus::Revoked => Self::Revoked,
        }
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::prelude::X509Identity]
pub struct X509Identity {
    pub handle: String,
    pub display_name: String,
    pub domain: String,
    pub certificate: String,
    pub serial_number: String,
    pub not_before: u64,
    pub not_after: u64,
}

impl From<core_crypto::prelude::X509Identity> for X509Identity {
    fn from(i: core_crypto::prelude::X509Identity) -> Self {
        Self {
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
            certificate: i.certificate,
            serial_number: i.serial_number,
            not_before: i.not_before,
            not_after: i.not_after,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
/// See [core_crypto::prelude::MlsConversationConfiguration]
pub struct ConversationConfiguration {
    pub ciphersuite: Ciphersuite,
    pub external_senders: Vec<Vec<u8>>,
    pub custom: CustomConfiguration,
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, uniffi::Enum)]
#[repr(u8)]
pub enum MlsWirePolicy {
    /// Handshake messages are never encrypted
    #[default]
    Plaintext = 1,
    /// Handshake messages are always encrypted
    Ciphertext = 2,
}

impl From<core_crypto::prelude::MlsWirePolicy> for MlsWirePolicy {
    fn from(value: core_crypto::prelude::MlsWirePolicy) -> Self {
        match value {
            core_crypto::prelude::MlsWirePolicy::Plaintext => Self::Plaintext,
            core_crypto::prelude::MlsWirePolicy::Ciphertext => Self::Ciphertext,
        }
    }
}

impl From<MlsWirePolicy> for core_crypto::prelude::MlsWirePolicy {
    fn from(value: MlsWirePolicy) -> core_crypto::prelude::MlsWirePolicy {
        match value {
            MlsWirePolicy::Plaintext => core_crypto::prelude::MlsWirePolicy::Plaintext,
            MlsWirePolicy::Ciphertext => core_crypto::prelude::MlsWirePolicy::Ciphertext,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
/// See [core_crypto::prelude::MlsCustomConfiguration]
pub struct CustomConfiguration {
    pub key_rotation_span: Option<std::time::Duration>,
    pub wire_policy: Option<MlsWirePolicy>,
}

impl From<CustomConfiguration> for MlsCustomConfiguration {
    fn from(cfg: CustomConfiguration) -> Self {
        Self {
            key_rotation_span: cfg.key_rotation_span,
            wire_policy: cfg.wire_policy.unwrap_or_default().into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
/// Dummy comment
pub struct E2eiDumpedPkiEnv {
    pub root_ca: String,
    pub intermediates: Vec<String>,
    pub crls: Vec<String>,
}

impl From<core_crypto::e2e_identity::E2eiDumpedPkiEnv> for E2eiDumpedPkiEnv {
    fn from(value: core_crypto::e2e_identity::E2eiDumpedPkiEnv) -> Self {
        Self {
            root_ca: value.root_ca,
            intermediates: value.intermediates,
            crls: value.crls,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Enum)]
#[repr(u8)]
pub enum MlsCredentialType {
    /// Basic credential i.e. a KeyPair
    #[default]
    Basic = 0x01,
    /// A x509 certificate generally obtained through e2e identity enrollment process
    X509 = 0x02,
}

impl From<core_crypto::prelude::MlsCredentialType> for MlsCredentialType {
    fn from(value: core_crypto::prelude::MlsCredentialType) -> Self {
        match value {
            core_crypto::prelude::MlsCredentialType::Basic => Self::Basic,
            core_crypto::prelude::MlsCredentialType::X509 => Self::X509,
        }
    }
}

impl From<MlsCredentialType> for core_crypto::prelude::MlsCredentialType {
    fn from(value: MlsCredentialType) -> core_crypto::prelude::MlsCredentialType {
        match value {
            MlsCredentialType::Basic => core_crypto::prelude::MlsCredentialType::Basic,
            MlsCredentialType::X509 => core_crypto::prelude::MlsCredentialType::X509,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MlsTransportResponse {
    /// The message was accepted by the distribution service
    Success,
    /// A client should have consumed all incoming messages before re-trying.
    Retry,
    /// The message was rejected by the delivery service and there's no recovery.
    Abort { reason: String },
}

impl From<MlsTransportResponse> for core_crypto::MlsTransportResponse {
    fn from(value: MlsTransportResponse) -> Self {
        match value {
            MlsTransportResponse::Success => Self::Success,
            MlsTransportResponse::Retry => Self::Retry,
            MlsTransportResponse::Abort { reason } => Self::Abort { reason },
        }
    }
}

impl From<core_crypto::MlsTransportResponse> for MlsTransportResponse {
    fn from(value: core_crypto::MlsTransportResponse) -> Self {
        match value {
            core_crypto::MlsTransportResponse::Success => Self::Success,
            core_crypto::MlsTransportResponse::Retry => Self::Retry,
            core_crypto::MlsTransportResponse::Abort { reason } => Self::Abort { reason },
        }
    }
}

#[derive(Debug)]
struct MlsTransportWrapper(Arc<dyn MlsTransport>);

#[async_trait::async_trait]
impl core_crypto::prelude::MlsTransport for MlsTransportWrapper {
    async fn send_commit_bundle(
        &self,
        commit_bundle: MlsCommitBundle,
    ) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        let commit_bundle = CommitBundle::try_from(commit_bundle)
            .map_err(|e| core_crypto::Error::ErrorDuringMlsTransport(e.to_string()))?;
        Ok(self.0.send_commit_bundle(commit_bundle).await.into())
    }

    async fn send_message(&self, mls_message: Vec<u8>) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        Ok(self.0.send_message(mls_message).await.into())
    }
}

/// Used by core crypto to send commits or application messages to the delivery service.
/// This trait must be implemented before calling any functions that produce commits.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MlsTransport: std::fmt::Debug + Send + Sync {
    async fn send_commit_bundle(&self, commit_bundle: CommitBundle) -> MlsTransportResponse;
    async fn send_message(&self, mls_message: Vec<u8>) -> MlsTransportResponse;
}

static INIT_LOGGER: Once = Once::new();
static LOGGER: LazyLock<ReloadLog<CoreCryptoLoggerWrapper>> = LazyLock::new(|| {
    ReloadLog::new(CoreCryptoLoggerWrapper {
        logger: Arc::new(DummyLogger {}),
    })
});

/// Initializes the logger
///
/// NOTE: in a future  release we will remove `level` argument.
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn CoreCryptoLogger>, level: CoreCryptoLogLevel) {
    set_logger_only(logger);
    set_max_log_level(level);
}

/// Initializes the logger
#[uniffi::export]
pub fn set_logger_only(logger: Arc<dyn CoreCryptoLogger>) {
    // unwrapping poisoned lock error which shouldn't happen since we don't panic while replacing the logger
    LOGGER.handle().replace(CoreCryptoLoggerWrapper { logger }).unwrap();

    INIT_LOGGER.call_once(|| {
        log::set_logger(LOGGER.deref()).unwrap();
        log::set_max_level(LevelFilter::Warn);
    });
}

/// Set maximum log level forwarded to the logger
#[uniffi::export]
pub fn set_max_log_level(level: CoreCryptoLogLevel) {
    log::set_max_level(level.into());
}

/// This trait is used to provide a callback mechanism to hook up the rerspective platform logging system
#[uniffi::export(with_foreign)]
pub trait CoreCryptoLogger: std::fmt::Debug + Send + Sync {
    /// Function to setup a hook for the logging messages. Core Crypto will call this method
    /// whenever it needs to log a message.
    fn log(&self, level: CoreCryptoLogLevel, message: String, context: Option<String>);
}

struct KeyValueVisitor<'kvs>(BTreeMap<Key<'kvs>, Value<'kvs>>);

impl<'kvs> VisitSource<'kvs> for KeyValueVisitor<'kvs> {
    #[inline]
    fn visit_pair(&mut self, key: Key<'kvs>, value: Value<'kvs>) -> Result<(), kv::Error> {
        self.0.insert(key, value);
        Ok(())
    }
}
#[derive(Debug)]
struct DummyLogger {}

impl CoreCryptoLogger for DummyLogger {
    #[allow(unused_variables)]
    fn log(&self, level: CoreCryptoLogLevel, json_msg: String, context: Option<String>) {}
}

#[derive(Clone)]
struct CoreCryptoLoggerWrapper {
    logger: std::sync::Arc<dyn CoreCryptoLogger>,
}

impl CoreCryptoLoggerWrapper {
    fn adjusted_log_level(&self, metadata: &Metadata) -> Level {
        match (metadata.level(), metadata.target()) {
            // increase log level for refinery_core::traits since they are too verbose in transactions
            (level, "refinery_core::traits") if level >= Level::Info => Level::Debug,
            (level, "refinery_core::traits::sync") if level >= Level::Info => Level::Debug,
            (level, _) => level,
        }
    }
}

impl log::Log for CoreCryptoLoggerWrapper {
    fn enabled(&self, metadata: &Metadata) -> bool {
        log::max_level() >= self.adjusted_log_level(metadata)
    }

    fn log(&self, record: &Record) {
        let kvs = record.key_values();
        let mut visitor = KeyValueVisitor(BTreeMap::new());
        let _ = kvs.visit(&mut visitor);

        if !self.enabled(record.metadata()) {
            return;
        }

        let message = format!("{}", record.args());
        let context = serde_json::to_string(&visitor.0).ok();
        self.logger.log(
            CoreCryptoLogLevel::from(&self.adjusted_log_level(record.metadata())),
            message,
            context,
        );
    }

    fn flush(&self) {}
}

/// Defines the log level for a CoreCrypto
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum CoreCryptoLogLevel {
    Off,
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<CoreCryptoLogLevel> for LevelFilter {
    fn from(value: CoreCryptoLogLevel) -> LevelFilter {
        match value {
            CoreCryptoLogLevel::Off => LevelFilter::Off,
            CoreCryptoLogLevel::Trace => LevelFilter::Trace,
            CoreCryptoLogLevel::Debug => LevelFilter::Debug,
            CoreCryptoLogLevel::Info => LevelFilter::Info,
            CoreCryptoLogLevel::Warn => LevelFilter::Warn,
            CoreCryptoLogLevel::Error => LevelFilter::Error,
        }
    }
}

impl From<&Level> for CoreCryptoLogLevel {
    fn from(value: &Level) -> Self {
        match *value {
            Level::Warn => CoreCryptoLogLevel::Warn,
            Level::Error => CoreCryptoLogLevel::Error,
            Level::Info => CoreCryptoLogLevel::Info,
            Level::Debug => CoreCryptoLogLevel::Debug,
            Level::Trace => CoreCryptoLogLevel::Trace,
        }
    }
}

#[derive(Debug, uniffi::Object)]
pub struct CoreCrypto {
    central: core_crypto::CoreCrypto,
}

#[uniffi::export]
/// See [core_crypto::mls::MlsCentral::try_new]
pub async fn core_crypto_new(
    path: String,
    key: String,
    client_id: ClientId,
    ciphersuites: Ciphersuites,
    nb_key_package: Option<u32>,
) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::new(path, key, Some(client_id), Some(ciphersuites), nb_key_package).await
}

#[uniffi::export]
/// Similar to [core_crypto_new] but defers MLS initialization. It can be initialized later
/// with [CoreCryptoContext::mls_init].
pub async fn core_crypto_deferred_init(path: String, key: String) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::new(path, key, None, None, None).await
}

#[allow(dead_code, unused_variables)]
#[uniffi::export]
impl CoreCrypto {
    #[uniffi::constructor]
    pub async fn new(
        path: String,
        key: String,
        client_id: Option<ClientId>,
        ciphersuites: Option<Ciphersuites>,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<Self> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CoreCryptoError::generic())?;
        let configuration = MlsCentralConfiguration::try_new(
            path,
            key,
            client_id.map(|cid| cid.0.clone()),
            (&ciphersuites.unwrap_or_default()).into(),
            None,
            nb_key_package,
        )?;

        let central = MlsCentral::try_new(configuration).await?;
        let central = core_crypto::CoreCrypto::from(central);

        Ok(CoreCrypto { central })
    }

    /// See [core_crypto::mls::MlsCentral::provide_transport]
    pub async fn provide_transport(&self, callbacks: Arc<dyn MlsTransport>) -> CoreCryptoResult<()> {
        self.central
            .provide_transport(Arc::new(MlsTransportWrapper(callbacks)))
            .await;
        Ok(())
    }

    /// See [core_crypto::mls::MlsCentral::client_public_key]
    pub async fn client_public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .client_public_key(ciphersuite.into(), credential_type.into())
            .await?)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::epoch]
    pub async fn conversation_epoch(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<u64> {
        Ok(self.central.get_raw_conversation(&conversation_id).await?.epoch())
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::ciphersuite]
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let cs = self.central.get_raw_conversation(conversation_id).await?.ciphersuite();
        Ok(Ciphersuite::from(core_crypto::prelude::CiphersuiteName::from(cs)))
    }

    /// See [core_crypto::mls::MlsCentral::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<bool> {
        Ok(self.central.conversation_exists(&conversation_id).await?)
    }

    /// See [core_crypto::mls::MlsCentral::random_bytes]
    pub async fn random_bytes(&self, len: u32) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .random_bytes(len.try_into().map_err(CoreCryptoError::generic())?)?)
    }

    /// see [core_crypto::prelude::MlsCryptoProvider::reseed]
    pub async fn reseed_rng(&self, seed: Vec<u8>) -> CoreCryptoResult<()> {
        let seed = EntropySeed::try_from_slice(&seed).map_err(CoreCryptoError::generic())?;
        self.central.reseed(Some(seed)).await?;

        Ok(())
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<ClientId>> {
        Ok(self
            .central
            .get_raw_conversation(&conversation_id)
            .await?
            .get_client_ids()
            .await
            .into_iter()
            .map(ClientId)
            .collect())
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::export_secret_key]
    pub async fn export_secret_key(&self, conversation_id: Vec<u8>, key_length: u32) -> CoreCryptoResult<Vec<u8>> {
        self.central
            .get_raw_conversation(&conversation_id)
            .await?
            .export_secret_key(key_length as usize)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .get_raw_conversation(&conversation_id)
            .await?
            .get_external_sender()
            .await?)
    }
}

#[derive(Debug, Copy, Clone, uniffi::Enum)]
#[repr(u8)]
pub enum E2eiConversationState {
    /// All clients have a valid E2EI certificate
    Verified = 1,
    /// Some clients are either still Basic or their certificate is expired
    NotVerified,
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is returned.
    NotEnabled,
}

impl From<core_crypto::prelude::E2eiConversationState> for E2eiConversationState {
    fn from(value: core_crypto::prelude::E2eiConversationState) -> Self {
        match value {
            core_crypto::prelude::E2eiConversationState::Verified => Self::Verified,
            core_crypto::prelude::E2eiConversationState::NotVerified => Self::NotVerified,
            core_crypto::prelude::E2eiConversationState::NotEnabled => Self::NotEnabled,
        }
    }
}

#[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
#[uniffi::export]
impl CoreCrypto {
    /// See [core_crypto::proteus::ProteusCentral::session_exists]
    pub async fn proteus_session_exists(&self, session_id: String) -> CoreCryptoResult<bool> {
        proteus_impl!({ Ok(self.central.proteus_session_exists(&session_id).await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id(&self) -> CoreCryptoResult<u16> {
        proteus_impl!({ Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id()) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint]
    pub async fn proteus_fingerprint(&self) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.central.proteus_fingerprint().await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_local]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.central.proteus_fingerprint_local(&session_id).await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.central.proteus_fingerprint_remote(&session_id).await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    /// NOTE: uniffi doesn't support associated functions, so we have to have the self here
    pub fn proteus_fingerprint_prekeybundle(&self, prekey: Vec<u8>) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey)?) })
    }
}

// End-to-end identity methods
#[allow(dead_code, unused_variables)]
#[uniffi::export]
impl CoreCrypto {
    pub async fn e2ei_dump_pki_env(&self) -> CoreCryptoResult<Option<E2eiDumpedPkiEnv>> {
        Ok(self.central.e2ei_dump_pki_env().await?.map(Into::into))
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.central.e2ei_is_pki_env_setup().await
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let sc = core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
            .signature_algorithm();
        Ok(self.central.e2ei_is_enabled(sc).await?)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::get_device_identities]
    pub async fn get_device_identities(
        &self,
        conversation_id: Vec<u8>,
        device_ids: Vec<ClientId>,
    ) -> CoreCryptoResult<Vec<WireIdentity>> {
        let device_ids = device_ids.into_iter().map(|cid| cid.0).collect::<Vec<_>>();
        Ok(self
            .central
            .get_raw_conversation(&conversation_id)
            .await?
            .get_device_identities(&device_ids[..])
            .await?
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>())
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::get_user_identities]
    pub async fn get_user_identities(
        &self,
        conversation_id: Vec<u8>,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<HashMap<String, Vec<WireIdentity>>> {
        Ok(self
            .central
            .get_raw_conversation(&conversation_id)
            .await?
            .get_user_identities(&user_ids[..])
            .await?
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
            .collect::<HashMap<String, Vec<WireIdentity>>>())
    }

    /// See [core_crypto::mls::MlsCentral::get_credential_in_use]
    pub async fn get_credential_in_use(
        &self,
        group_info: Vec<u8>,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<E2eiConversationState> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                "verifiable group info",
            ))
            .map_err(RecursiveError::mls_conversation("deserializing veriable group info"))?;
        Ok(self
            .central
            .get_credential_in_use(group_info, credential_type.into())
            .await?
            .into())
    }
}

#[derive(Debug, uniffi::Object)]
/// See [core_crypto::e2e_identity::E2eiEnrollment]
pub struct E2eiEnrollment(std::sync::Arc<async_lock::RwLock<core_crypto::prelude::E2eiEnrollment>>);

#[uniffi::export]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::E2eiEnrollment::directory_response]
    pub async fn directory_response(&self, directory: Vec<u8>) -> CoreCryptoResult<AcmeDirectory> {
        Ok(self
            .0
            .write()
            .await
            .directory_response(directory)
            .map(AcmeDirectory::from)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_request]
    pub async fn new_account_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_account_request(previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_response]
    pub async fn new_account_response(&self, account: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.0.write().await.new_account_response(account)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_request]
    #[allow(clippy::too_many_arguments)]
    pub async fn new_order_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_order_request(previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_response]
    pub async fn new_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<NewAcmeOrder> {
        Ok(self.0.read().await.new_order_response(order)?.into())
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_request]
    pub async fn new_authz_request(&self, url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_authz_request(url, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_response]
    pub async fn new_authz_response(&self, authz: Vec<u8>) -> CoreCryptoResult<NewAcmeAuthz> {
        Ok(self.0.write().await.new_authz_response(authz)?.into())
    }

    #[allow(clippy::too_many_arguments)]
    /// See [core_crypto::e2e_identity::E2eiEnrollment::create_dpop_token]
    pub async fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> CoreCryptoResult<String> {
        Ok(self.0.read().await.create_dpop_token(expiry_secs, backend_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_request]
    pub async fn new_dpop_challenge_request(
        &self,
        access_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .0
            .read()
            .await
            .new_dpop_challenge_request(access_token, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_response]
    pub async fn new_dpop_challenge_response(&self, challenge: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.0.read().await.new_dpop_challenge_response(challenge)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_request]
    pub async fn new_oidc_challenge_request(
        &self,
        id_token: String,
        refresh_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .0
            .write()
            .await
            .new_oidc_challenge_request(id_token, refresh_token, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_response]
    pub async fn context_new_oidc_challenge_response(
        &self,
        cc: std::sync::Arc<CoreCryptoContext>,
        challenge: Vec<u8>,
    ) -> CoreCryptoResult<()> {
        self.0
            .write()
            .await
            .new_oidc_challenge_response(&cc.context.mls_provider().await?, challenge)
            .await?;
        Ok(())
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_request]
    pub async fn check_order_request(&self, order_url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.check_order_request(order_url, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_response]
    pub async fn check_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<String> {
        Ok(self.0.write().await.check_order_response(order)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::finalize_request]
    pub async fn finalize_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.write().await.finalize_request(previous_nonce)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::finalize_response]
    pub async fn finalize_response(&self, finalize: Vec<u8>) -> CoreCryptoResult<String> {
        Ok(self.0.write().await.finalize_response(finalize)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::certificate_request]
    pub async fn certificate_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.write().await.certificate_request(previous_nonce)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::get_refresh_token]
    pub async fn get_refresh_token(&self) -> CoreCryptoResult<String> {
        Ok(self.0.read().await.get_refresh_token().map(Into::into)?)
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeDirectory]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
}

impl From<core_crypto::prelude::E2eiAcmeDirectory> for AcmeDirectory {
    fn from(directory: core_crypto::prelude::E2eiAcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

impl From<AcmeDirectory> for core_crypto::prelude::E2eiAcmeDirectory {
    fn from(directory: AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeOrder]
pub struct NewAcmeOrder {
    pub delegate: Vec<u8>,
    pub authorizations: Vec<String>,
}

impl From<core_crypto::prelude::E2eiNewAcmeOrder> for NewAcmeOrder {
    fn from(new_order: core_crypto::prelude::E2eiNewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}

impl From<NewAcmeOrder> for core_crypto::prelude::E2eiNewAcmeOrder {
    fn from(new_order: NewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeAuthz]
pub struct NewAcmeAuthz {
    pub identifier: String,
    pub keyauth: Option<String>,
    pub challenge: AcmeChallenge,
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(new_authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(new_authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeChallenge]
pub struct AcmeChallenge {
    pub delegate: Vec<u8>,
    pub url: String,
    pub target: String,
}

impl From<core_crypto::prelude::E2eiAcmeChallenge> for AcmeChallenge {
    fn from(chall: core_crypto::prelude::E2eiAcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}

impl From<AcmeChallenge> for core_crypto::prelude::E2eiAcmeChallenge {
    fn from(chall: AcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::LeafError;
    #[test]
    fn test_error_mapping() {
        let duplicate_message_error = RecursiveError::mls_conversation("test duplicate message error")(
            core_crypto::mls::conversation::Error::DuplicateMessage,
        );
        let mapped_error = CoreCryptoError::from(duplicate_message_error);
        assert!(matches!(mapped_error, CoreCryptoError::Mls(MlsError::DuplicateMessage)));

        let conversation_exists_error = RecursiveError::mls_conversation("test conversation exists error")(
            core_crypto::mls::conversation::Error::Leaf(LeafError::ConversationAlreadyExists(
                "test conversation id".into(),
            )),
        );
        let mapped_error = CoreCryptoError::from(conversation_exists_error);
        assert!(matches!(
            mapped_error,
            CoreCryptoError::Mls(MlsError::ConversationAlreadyExists(_))
        ));
    }

    #[tokio::test]
    async fn test_error_is_logged() {
        testing_logger::setup();
        // we shouldn't be able to create a SQLite DB in `/root` unless we are running this test as root
        // Don't do that!
        let result = CoreCrypto::new("/root/asdf".into(), "key".into(), None, None, None).await;
        assert!(
            result.is_err(),
            "result must be an error in order to verify that something was logged"
        );
        testing_logger::validate(|captured_logs| {
            assert!(
                captured_logs.iter().any(|log| log.level == Level::Warn
                    && log.target == "core-crypto"
                    && log.body.contains("returning this error across ffi")),
                "log message did not appear within the captured logs"
            )
        });
    }
}
