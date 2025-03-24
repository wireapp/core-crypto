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
#![allow(unused_variables)]
pub mod context;
mod epoch_observer;
mod utils;

use std::{
    collections::{BTreeMap, HashMap},
    ops::Deref,
    sync::{Arc, LazyLock, Once},
};

use crate::proteus_impl;
use core_crypto::mls::conversation::Conversation as _;
use core_crypto::{InnermostErrorMessage, MlsTransportResponse, prelude::*};
use futures_util::future::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use log::{
    Level, LevelFilter, Metadata, Record,
    kv::{self, Key, Value, VisitSource},
};
use log_reload::ReloadLog;
use tls_codec::Deserialize;
use utils::*;
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::future_to_promise;

#[allow(dead_code)]
pub(super) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Metadata describing the conditions of the build of this software.
#[wasm_bindgen(inspectable)]
pub struct BuildMetadata {
    /// Build Timestamp
    #[wasm_bindgen(readonly)]
    pub timestamp: &'static str,
    /// Whether this build was in Debug mode (true) or Release mode (false)
    #[wasm_bindgen(readonly, js_name = "cargoDebug")]
    pub cargo_debug: &'static str,
    /// Features enabled for this build
    #[wasm_bindgen(readonly, js_name = "cargoFeatures")]
    pub cargo_features: &'static str,
    /// Optimization level
    #[wasm_bindgen(readonly, js_name = "optLevel")]
    pub opt_level: &'static str,
    /// Build target triple
    #[wasm_bindgen(readonly, js_name = "targetTriple")]
    pub target_triple: &'static str,
    /// Git branch
    #[wasm_bindgen(readonly, js_name = "gitBranch")]
    pub git_branch: &'static str,
    /// Output of `git describe`
    #[wasm_bindgen(readonly, js_name = "gitDescribe")]
    pub git_describe: &'static str,
    /// Hash of current git commit
    #[wasm_bindgen(readonly, js_name = "gitSha")]
    pub git_sha: &'static str,
    /// `true` when the source code differed from the commit at the most recent git hash
    #[wasm_bindgen(readonly, js_name = "gitDirty")]
    pub git_dirty: &'static str,
}

#[derive(Debug, thiserror::Error, strum::AsRefStr)]
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
#[derive(Debug, thiserror::Error, strum::AsRefStr)]
pub enum ProteusError {
    #[error("Proteus was not initialized")]
    NotInitialized,
    #[error("The requested session was not found")]
    SessionNotFound,
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    #[error("The remote identity has changed")]
    RemoteIdentityChanged,
    #[error("Another Proteus error occurred but the details are probably irrelevant to clients ({})", .0.unwrap_or_default())]
    Other(Option<u16>),
}

impl ProteusError {
    pub fn from_error_code(code: impl Into<Option<u16>>) -> Option<Self> {
        let code = code.into()?;
        if code == 0 {
            return None;
        }

        match code {
            5 => Self::NotInitialized,
            102 => Self::SessionNotFound,
            204 => Self::RemoteIdentityChanged,
            209 => Self::DuplicateMessage,
            _ => Self::Other(Some(code)),
        }
        .into()
    }

    pub fn error_code(&self) -> Option<u16> {
        match self {
            ProteusError::NotInitialized => Some(5),
            ProteusError::SessionNotFound => Some(102),
            ProteusError::RemoteIdentityChanged => Some(204),
            ProteusError::DuplicateMessage => Some(209),
            ProteusError::Other(code) => *code,
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
            _ => Self::Other(value.source.error_code()),
        }
    }
}

#[derive(Debug, thiserror::Error, strum::AsRefStr)]
pub(crate) enum InternalError {
    #[error(transparent)]
    MlsError(#[from] MlsError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    ProteusError(#[from] ProteusError),
    #[error("End to end identity error: {0}")]
    E2eiError(String),
    #[error(transparent)]
    SerializationError(#[from] serde_wasm_bindgen::Error),
    #[error("Unknown ciphersuite identifier")]
    UnknownCiphersuite,
    #[error("Transaction rolled back. Uncaught JsError: {uncaught_error:?}")]
    TransactionFailed { uncaught_error: JsValue },
    #[error("{0}")]
    Other(String),
}

/// Prepare and dispatch a log message reporting this error.
///
/// We want to ensure consistent logging every time we pass a log message across the FFI boundary,
/// as we cannot guarantee the method, format, or existence of error logging once the result crosses.
/// In this case there is a single point at which we convert internal errors to trans-ffi
/// errors, but it was still convenient to extract the logging procedure, because that point is
/// within a macro-generated `From` impl.
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

impl From<RecursiveError> for InternalError {
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
            return InternalError::E2eiError(err.to_string());
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
            // The internal name is what we want, but renaming the external variant is a breaking change.
            // Since we're re-designing the `BufferedMessage` errors soon, it's not worth producing
            // an additional breaking change until then, so the names are inconsistent.
            core_crypto::mls::conversation::Error::BufferedForPendingConversation => MlsError::UnmergedPendingGroup.into(),
            ||=> MlsError::Other(error.innermost_error_message()).into(),
        })
    }
}

// This implementation is intended to be temporary; we're going to be completely restructuring the way we handle
// errors in `core-crypto` soon. We can replace this with better error patterns when we do.
//
// Certain error mappings could apply to both MLS and Proteus. In all such cases, we map them to the MLS variant.
// When we redesign the errors in `core-crypto`, these ambiguities should disappear anyway.
impl From<core_crypto::Error> for InternalError {
    fn from(error: core_crypto::Error) -> Self {
        log_error(&error);

        // we can take care of the _simple_ error-mapping up here.
        #[cfg(feature = "proteus")]
        if let core_crypto::Error::Proteus(proteus) = &error {
            if let Some(code) = proteus.source.error_code() {
                if code != 0 {
                    if let Some(proteus_error) = ProteusError::from_error_code(code) {
                        return Self::ProteusError(proteus_error);
                    }
                }
            }
        }
        match error {
            #[cfg(feature = "proteus")]
            core_crypto::Error::ProteusNotInitialized => Self::ProteusError(ProteusError::NotInitialized),
            core_crypto::Error::Proteus(proteus) => Self::Other(proteus.innermost_error_message()),
            core_crypto::Error::Mls(mls) => Self::MlsError(MlsError::from(mls)),
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

/// We can't do a generic `impl<E: ToRecursiveError> From<E> for InternalError`
/// because that has the potential to cause breaking conflicts later on: what if
/// core-crypto later did `impl ToRecursiveError for core_crypto::Error`? That would
/// cause a duplicate `From` impl.
///
/// Instead, we explicitly specify every variant which can be converted to a
/// `InternalError`, and implement its `From` block directly.
macro_rules! impl_from_via_recursive_error {
    ($($t:ty),+ $(,)?) => {
        $(
            impl From<$t> for InternalError {
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

impl InternalError {
    fn generic<E>() -> impl FnOnce(E) -> Self
    where
        E: ToString,
    {
        |err| Self::Other(err.to_string())
    }

    fn variant_name(&self) -> String {
        let mut out = self.as_ref().to_string();
        match self {
            Self::MlsError(mls) => out += mls.as_ref(),
            Self::ProteusError(proteus) => out += proteus.as_ref(),
            _ => {}
        }
        out
    }

    fn stack(&self) -> Vec<String> {
        let mut stack = Vec::new();
        let mut err: &dyn std::error::Error = self;
        stack.push(err.to_string());

        while let Some(source) = err.source() {
            stack.push(source.to_string());
            err = source;
        }

        stack
    }
}

#[derive(Debug, thiserror::Error)]
pub struct CoreCryptoError(#[source] InternalError);

impl std::fmt::Display for CoreCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let proteus_error_code = match &self.0 {
            InternalError::ProteusError(ProteusError::Other(code)) => *code,
            _ => None,
        };

        let json = serde_json::to_string(&serde_json::json!({
            "message": self.0.to_string(),
            "error_name": self.0.variant_name(),
            "error_stack": self.0.stack(),
            "proteus_error_code": proteus_error_code,
        }))
        .map_err(|_| std::fmt::Error)?;

        write!(f, "{json}")
    }
}

impl<T> From<T> for CoreCryptoError
where
    T: Into<InternalError>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl From<CoreCryptoError> for wasm_bindgen::JsValue {
    fn from(val: CoreCryptoError) -> Self {
        fn construct_error_stack(err: &dyn std::error::Error) -> js_sys::Error {
            let out = js_sys::Error::new(&err.to_string());
            if let Some(source) = err.source() {
                let source_value = construct_error_stack(source);
                out.set_cause(&source_value);
            }
            out
        }

        let stacked_error = construct_error_stack(&val);
        stacked_error.set_name(&val.0.variant_name());

        stacked_error.into()
    }
}

pub type CoreCryptoResult<T> = Result<T, CoreCryptoError>;
pub type WasmCryptoResult<T> = CoreCryptoResult<T>;

#[allow(non_camel_case_types)]
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, strum::FromRepr)]
#[repr(u16)]
// see [core_crypto::prelude::CiphersuiteName]
pub enum Ciphersuite {
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

impl From<MlsCiphersuite> for Ciphersuite {
    fn from(c: MlsCiphersuite) -> Self {
        Self::from(CiphersuiteName::from(c))
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    fn from(c: Ciphersuite) -> Self {
        let c: CiphersuiteName = c.into();
        Self::from(c)
    }
}

impl From<CiphersuiteName> for Ciphersuite {
    fn from(c: CiphersuiteName) -> Self {
        match c {
            CiphersuiteName::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            }
            CiphersuiteName::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            CiphersuiteName::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            }
            CiphersuiteName::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            CiphersuiteName::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            CiphersuiteName::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            }
            CiphersuiteName::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<CiphersuiteName> for Ciphersuite {
    fn into(self) -> CiphersuiteName {
        match self {
            Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                CiphersuiteName::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            }
            Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => CiphersuiteName::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                CiphersuiteName::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            }
            Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => CiphersuiteName::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => CiphersuiteName::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                CiphersuiteName::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            }
            Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => CiphersuiteName::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        }
    }
}

/// Helper to lower arrays of Ciphersuites (js -> rust)
fn lower_ciphersuites(ciphersuites: &[u16]) -> WasmCryptoResult<Vec<MlsCiphersuite>> {
    ciphersuites.iter().try_fold(
        Vec::with_capacity(ciphersuites.len()),
        |mut acc, &cs| -> WasmCryptoResult<_> {
            let cs = Ciphersuite::from_repr(cs).ok_or(InternalError::UnknownCiphersuite)?;
            let cs: MlsCiphersuite = cs.into();
            acc.push(cs);
            Ok(acc)
        },
    )
}

#[allow(non_camel_case_types)]
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
/// see [core_crypto::prelude::MlsCredentialType]
pub enum CredentialType {
    /// Just a KeyPair
    Basic = 0x0001,
    /// A certificate obtained through e2e identity enrollment process
    X509 = 0x0002,
}

impl From<CredentialType> for core_crypto::prelude::MlsCredentialType {
    fn from(from: CredentialType) -> Self {
        match from {
            CredentialType::Basic => core_crypto::prelude::MlsCredentialType::Basic,
            CredentialType::X509 => core_crypto::prelude::MlsCredentialType::X509,
        }
    }
}

impl From<core_crypto::prelude::MlsCredentialType> for CredentialType {
    fn from(from: core_crypto::prelude::MlsCredentialType) -> Self {
        match from {
            core_crypto::prelude::MlsCredentialType::Basic => CredentialType::Basic,
            core_crypto::prelude::MlsCredentialType::X509 => CredentialType::X509,
        }
    }
}

pub type FfiClientId = Box<[u8]>;

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProteusAutoPrekeyBundle {
    pub id: u16,
    #[wasm_bindgen(getter_with_clone)]
    pub pkb: Vec<u8>,
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitBundle {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    group_info: GroupInfoBundle,
}

#[wasm_bindgen]
impl CommitBundle {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        Uint8Array::from(&*self.commit)
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Option<Uint8Array> {
        self.welcome.as_ref().map(|buf| Uint8Array::from(buf.as_slice()))
    }

    #[wasm_bindgen(getter)]
    pub fn group_info(&self) -> GroupInfoBundle {
        self.group_info.clone()
    }
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let (welcome, commit, pgs) = msg.to_bytes_triple()?;

        Ok(Self {
            welcome,
            commit,
            group_info: pgs.into(),
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupInfoBundle {
    encryption_type: u8,
    ratchet_tree_type: u8,
    payload: Vec<u8>,
}

#[wasm_bindgen]
impl GroupInfoBundle {
    #[wasm_bindgen(getter)]
    pub fn encryption_type(&self) -> u8 {
        self.encryption_type
    }

    #[wasm_bindgen(getter)]
    pub fn ratchet_tree_type(&self) -> u8 {
        self.ratchet_tree_type
    }

    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Uint8Array {
        Uint8Array::from(&*self.payload)
    }
}

impl From<MlsGroupInfoBundle> for GroupInfoBundle {
    fn from(gi: MlsGroupInfoBundle) -> Self {
        Self {
            encryption_type: gi.encryption_type as u8,
            ratchet_tree_type: gi.ratchet_tree_type as u8,
            payload: gi.payload.bytes(),
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProposalBundle {
    /// TLS-serialized MLS proposal that needs to be fanned out to other (existing) members of the conversation
    proposal: Vec<u8>,
    /// Unique identifier of a proposal.
    proposal_ref: Vec<u8>,
    /// New CRL Distribution of members of this group
    crl_new_distribution_points: Option<Vec<String>>,
}

#[wasm_bindgen]
impl ProposalBundle {
    #[wasm_bindgen(getter)]
    pub fn proposal(&self) -> Uint8Array {
        Uint8Array::from(&*self.proposal)
    }

    #[wasm_bindgen(getter)]
    pub fn proposal_ref(&self) -> Uint8Array {
        Uint8Array::from(&*self.proposal_ref)
    }

    #[wasm_bindgen(getter)]
    pub fn crl_new_distribution_points(&self) -> Option<js_sys::Array> {
        self.crl_new_distribution_points
            .clone()
            .map(|crl_dp| crl_dp.iter().cloned().map(JsValue::from).collect::<js_sys::Array>())
    }
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

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WelcomeBundle {
    /// Identifier of the joined conversation
    id: ConversationId,
    /// New CRL Distribution of members of this group
    crl_new_distribution_points: Option<Vec<String>>,
}

#[wasm_bindgen]
impl WelcomeBundle {
    /// Identifier of the joined conversation
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Uint8Array {
        Uint8Array::from(&*self.id)
    }

    /// New CRL Distribution of members of this group
    #[wasm_bindgen(getter)]
    #[wasm_bindgen(js_name = "crlNewDistributionPoints")]
    pub fn crl_new_distribution_points(&self) -> Option<js_sys::Array> {
        self.crl_new_distribution_points
            .clone()
            .map(|crl_dp| crl_dp.iter().cloned().map(JsValue::from).collect::<js_sys::Array>())
    }
}

impl From<core_crypto::prelude::WelcomeBundle> for WelcomeBundle {
    fn from(w: core_crypto::prelude::WelcomeBundle) -> Self {
        Self {
            id: w.id,
            crl_new_distribution_points: w.crl_new_distribution_points.into(),
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::decrypt::MlsConversationDecryptMessage]
pub struct DecryptedMessage {
    message: Option<Vec<u8>>,
    proposals: Vec<ProposalBundle>,
    /// It is set to false if ingesting this MLS message has resulted in the client being removed from the group (i.e. a Remove commit)
    is_active: bool,
    /// Commit delay hint (in milliseconds) to prevent clients from hammering the server with epoch changes
    commit_delay: Option<u32>,
    sender_client_id: Option<Vec<u8>>,
    /// true when the decrypted message resulted in an epoch change i.e. it was a commit
    has_epoch_changed: bool,
    identity: WireIdentity,
    buffered_messages: Option<Vec<BufferedDecryptedMessage>>,
    /// New CRL Distribution of members of this group
    crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsConversationDecryptMessage> for DecryptedMessage {
    type Error = CoreCryptoError;

    fn try_from(from: MlsConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(ProposalBundle::try_from)
            .collect::<WasmCryptoResult<Vec<_>>>()?;

        let buffered_messages = if let Some(bm) = from.buffered_messages {
            let bm = bm
                .into_iter()
                .map(TryInto::try_into)
                .collect::<WasmCryptoResult<Vec<_>>>()?;
            Some(bm)
        } else {
            None
        };

        let commit_delay = from
            .delay
            .map(TryInto::try_into)
            .transpose()
            .map_err(InternalError::generic())?;

        #[expect(deprecated)]
        Ok(Self {
            message: from.app_msg,
            proposals,
            is_active: from.is_active,
            commit_delay,
            sender_client_id: from.sender_client_id.map(ClientId::into),
            has_epoch_changed: from.has_epoch_changed,
            identity: from.identity.into(),
            buffered_messages,
            crl_new_distribution_points: from.crl_new_distribution_points.into(),
        })
    }
}

#[wasm_bindgen]
impl DecryptedMessage {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> JsValue {
        if let Some(message) = &self.message {
            Uint8Array::from(message.as_slice()).into()
        } else {
            JsValue::NULL
        }
    }

    #[wasm_bindgen(getter)]
    pub fn proposals(&self) -> js_sys::Array {
        self.proposals
            .iter()
            .cloned()
            .map(JsValue::from)
            .collect::<js_sys::Array>()
    }

    #[wasm_bindgen(getter)]
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    #[wasm_bindgen(getter)]
    pub fn commit_delay(&self) -> Option<u32> {
        self.commit_delay
    }

    #[wasm_bindgen(getter)]
    pub fn sender_client_id(&self) -> JsValue {
        if let Some(cid) = &self.sender_client_id {
            Uint8Array::from(cid.as_slice()).into()
        } else {
            JsValue::NULL
        }
    }

    #[wasm_bindgen(getter)]
    pub fn has_epoch_changed(&self) -> bool {
        self.has_epoch_changed
    }

    #[wasm_bindgen(getter)]
    pub fn identity(&self) -> WireIdentity {
        self.identity.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn buffered_messages(&self) -> Option<js_sys::Array> {
        self.buffered_messages
            .clone()
            .map(|bm| bm.iter().cloned().map(JsValue::from).collect::<js_sys::Array>())
    }

    #[wasm_bindgen(getter)]
    pub fn crl_new_distribution_points(&self) -> Option<js_sys::Array> {
        self.crl_new_distribution_points
            .clone()
            .map(|crl_dp| crl_dp.iter().cloned().map(JsValue::from).collect::<js_sys::Array>())
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// to avoid recursion
pub struct BufferedDecryptedMessage {
    message: Option<Vec<u8>>,
    proposals: Vec<ProposalBundle>,
    is_active: bool,
    commit_delay: Option<u32>,
    sender_client_id: Option<Vec<u8>>,
    has_epoch_changed: bool,
    identity: WireIdentity,
    /// New CRL Distribution of members of this group
    crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsBufferedConversationDecryptMessage> for BufferedDecryptedMessage {
    type Error = CoreCryptoError;

    fn try_from(from: MlsBufferedConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(TryInto::try_into)
            .collect::<WasmCryptoResult<Vec<_>>>()?;

        let commit_delay = from
            .delay
            .map(TryInto::try_into)
            .transpose()
            .map_err(InternalError::generic())?;

        #[expect(deprecated)]
        Ok(Self {
            message: from.app_msg,
            proposals,
            is_active: from.is_active,
            commit_delay,
            sender_client_id: from.sender_client_id.map(ClientId::into),
            has_epoch_changed: from.has_epoch_changed,
            identity: from.identity.into(),
            crl_new_distribution_points: from.crl_new_distribution_points.into(),
        })
    }
}

#[wasm_bindgen]
impl BufferedDecryptedMessage {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> JsValue {
        if let Some(message) = &self.message {
            Uint8Array::from(message.as_slice()).into()
        } else {
            JsValue::NULL
        }
    }

    #[wasm_bindgen(getter)]
    pub fn proposals(&self) -> js_sys::Array {
        self.proposals
            .iter()
            .cloned()
            .map(JsValue::from)
            .collect::<js_sys::Array>()
    }

    #[wasm_bindgen(getter)]
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    #[wasm_bindgen(getter)]
    pub fn commit_delay(&self) -> Option<u32> {
        self.commit_delay
    }

    #[wasm_bindgen(getter)]
    pub fn sender_client_id(&self) -> JsValue {
        if let Some(cid) = &self.sender_client_id {
            Uint8Array::from(cid.as_slice()).into()
        } else {
            JsValue::NULL
        }
    }

    #[wasm_bindgen(getter)]
    pub fn has_epoch_changed(&self) -> bool {
        self.has_epoch_changed
    }

    #[wasm_bindgen(getter)]
    pub fn identity(&self) -> WireIdentity {
        self.identity.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn crl_new_distribution_points(&self) -> Option<js_sys::Array> {
        self.crl_new_distribution_points
            .clone()
            .map(|crl_dp| crl_dp.iter().cloned().map(JsValue::from).collect::<js_sys::Array>())
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    #[wasm_bindgen(readonly, js_name = clientId)]
    pub client_id: String,
    /// Status of the Credential at the moment this object is created
    #[wasm_bindgen(readonly)]
    pub status: u8,
    /// MLS thumbprint
    #[wasm_bindgen(readonly)]
    pub thumbprint: String,
    #[wasm_bindgen(readonly, js_name = credentialType)]
    pub credential_type: u8,
    #[wasm_bindgen(readonly, js_name = x509Identity)]
    pub x509_identity: Option<X509Identity>,
}

impl From<core_crypto::prelude::WireIdentity> for WireIdentity {
    fn from(i: core_crypto::prelude::WireIdentity) -> Self {
        Self {
            client_id: i.client_id,
            status: i.status as u8,
            thumbprint: i.thumbprint,
            credential_type: i.credential_type as u8,
            x509_identity: i.x509_identity.map(Into::into),
        }
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
pub struct X509Identity {
    /// user handle e.g. `john_wire`
    #[wasm_bindgen(readonly)]
    pub handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    #[wasm_bindgen(readonly, js_name = displayName)]
    pub display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    #[wasm_bindgen(readonly)]
    pub domain: String,
    /// X509 certificate identifying this client in the MLS group ; PEM encoded
    #[wasm_bindgen(readonly)]
    pub certificate: String,
    /// X509 certificate serial number
    #[wasm_bindgen(readonly, js_name = serialNumber)]
    pub serial_number: String,
    /// X509 certificate not before as Unix timestamp
    #[wasm_bindgen(readonly, js_name = notBefore)]
    pub not_before: u64,
    /// X509 certificate not after as Unix timestamp
    #[wasm_bindgen(readonly, js_name = notAfter)]
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

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Dump of the PKI environemnt as PEM
pub struct E2eiDumpedPkiEnv {
    #[wasm_bindgen(readonly)]
    /// Root CA in use (i.e. Trust Anchor)
    pub root_ca: String,
    #[wasm_bindgen(readonly)]
    /// Intermediate CAs that are loaded
    pub intermediates: Vec<String>,
    #[wasm_bindgen(readonly)]
    /// CRLs registered in the PKI env
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

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Configuration object for new conversations
/// see [core_crypto::prelude::MlsConversationConfiguration]
pub struct ConversationConfiguration {
    #[wasm_bindgen(readonly)]
    /// Conversation ciphersuite
    pub ciphersuite: Option<Ciphersuite>,
    external_senders: Vec<Vec<u8>>,
    #[wasm_bindgen(readonly)]
    /// Additional configuration
    pub custom: CustomConfiguration,
}

#[wasm_bindgen]
impl ConversationConfiguration {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ciphersuite: Option<Ciphersuite>,
        external_senders: Option<Vec<Uint8Array>>,
        key_rotation_span: Option<u32>,
        wire_policy: Option<WirePolicy>,
    ) -> WasmCryptoResult<ConversationConfiguration> {
        let external_senders = external_senders
            .map(|exs| exs.iter().cloned().map(|jsv| jsv.to_vec()).collect())
            .unwrap_or_default();
        Ok(Self {
            ciphersuite,
            external_senders,
            custom: CustomConfiguration::new(key_rotation_span, wire_policy),
        })
    }

    /// List of client IDs that are allowed to be external senders
    #[wasm_bindgen(getter, js_name = externalSenders)]
    pub fn external_senders(&self) -> js_sys::Array {
        self.external_senders
            .iter()
            .cloned()
            .map(JsValue::from)
            .collect::<js_sys::Array>()
    }
}

#[wasm_bindgen]
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::MlsCustomConfiguration]
pub struct CustomConfiguration {
    ///  Duration in seconds after which we will automatically force a self-update commit
    ///  Note: This isn't currently implemented
    #[wasm_bindgen(js_name = keyRotationSpan)]
    pub key_rotation_span: Option<u32>,
    /// Defines if handshake messages are encrypted or not
    /// Note: encrypted handshake messages are not supported by wire-server
    #[wasm_bindgen(js_name = wirePolicy)]
    pub wire_policy: Option<WirePolicy>,
}

#[wasm_bindgen]
impl CustomConfiguration {
    #[wasm_bindgen(constructor)]
    pub fn new(key_rotation_span: Option<u32>, wire_policy: Option<WirePolicy>) -> Self {
        Self {
            key_rotation_span,
            wire_policy,
        }
    }
}

impl From<CustomConfiguration> for MlsCustomConfiguration {
    fn from(cfg: CustomConfiguration) -> Self {
        let key_rotation_span = cfg
            .key_rotation_span
            .map(|span| std::time::Duration::from_secs(span as u64));
        let wire_policy = cfg.wire_policy.map(WirePolicy::into).unwrap_or_default();
        Self {
            key_rotation_span,
            wire_policy,
            ..Default::default()
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
/// see [core_crypto::prelude::MlsWirePolicy]
pub enum WirePolicy {
    /// Handshake messages are never encrypted
    Plaintext = 0x0001,
    /// Handshake messages are always encrypted
    Ciphertext = 0x0002,
}

impl From<WirePolicy> for MlsWirePolicy {
    fn from(policy: WirePolicy) -> Self {
        match policy {
            WirePolicy::Plaintext => Self::Plaintext,
            WirePolicy::Ciphertext => Self::Ciphertext,
        }
    }
}

static INIT_LOGGER: Once = Once::new();
static LOGGER: LazyLock<ReloadLog<CoreCryptoWasmLogger>> = LazyLock::new(|| {
    ReloadLog::new(CoreCryptoWasmLogger {
        logger: Default::default(),
        ctx: Default::default(),
    })
});

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct CoreCryptoWasmLogger {
    logger: js_sys::Function,
    ctx: JsValue,
}

// SAFETY: WASM only ever runs in a single-threaded context, so this is intrinsically thread-safe.
// If that invariant ever varies, we may need to rethink this (but more likely that would be addressed
// upstream where the types are defined).
unsafe impl Send for CoreCryptoWasmLogger {}
// SAFETY: WASM only ever runs in a single-threaded context, so this is intrinsically thread-safe.
unsafe impl Sync for CoreCryptoWasmLogger {}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum CoreCryptoLogLevel {
    Off = 1,
    Trace = 2,
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
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

impl From<Level> for CoreCryptoLogLevel {
    fn from(value: Level) -> CoreCryptoLogLevel {
        match value {
            Level::Warn => CoreCryptoLogLevel::Warn,
            Level::Error => CoreCryptoLogLevel::Error,
            Level::Info => CoreCryptoLogLevel::Info,
            Level::Debug => CoreCryptoLogLevel::Debug,
            Level::Trace => CoreCryptoLogLevel::Trace,
        }
    }
}

struct KeyValueVisitor<'kvs>(BTreeMap<Key<'kvs>, Value<'kvs>>);

impl<'kvs> VisitSource<'kvs> for KeyValueVisitor<'kvs> {
    #[inline]
    fn visit_pair(&mut self, key: Key<'kvs>, value: Value<'kvs>) -> Result<(), kv::Error> {
        self.0.insert(key, value);
        Ok(())
    }
}

#[wasm_bindgen]
impl CoreCryptoWasmLogger {
    #[wasm_bindgen(constructor)]
    pub fn new(logger: js_sys::Function, ctx: JsValue) -> Self {
        Self { logger, ctx }
    }
}

impl log::Log for CoreCryptoWasmLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let kvs = record.key_values();
        let mut visitor = KeyValueVisitor(BTreeMap::new());
        let _ = kvs.visit(&mut visitor);

        let message = format!("{}", record.args());
        let level: CoreCryptoLogLevel = CoreCryptoLogLevel::from(record.level());
        let context = serde_json::to_string(&visitor.0).ok();

        if let Err(e) = self.logger.call3(
            &self.ctx,
            &JsValue::from(level),
            &JsValue::from(message),
            &JsValue::from(context),
        ) {
            web_sys::console::error_1(&e);
        }
    }

    fn flush(&self) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, strum::FromRepr)]
#[repr(u8)]
#[serde(from = "u8")]
#[wasm_bindgen]
pub enum MlsTransportResponseVariant {
    Success = 1,
    Retry = 2,
    Abort = 3,
}

impl From<u8> for MlsTransportResponseVariant {
    fn from(value: u8) -> Self {
        match Self::from_repr(value) {
            Some(variant) => variant,
            // This is unreachable because deserialization is only done on a value that was
            // serialized directly from our type (this happens in js_sys::Function::call1, where the
            // constructed and returned MlsTransportResponse is serialized to a JsValue).
            // In drive_js_func_call(), we deserialize it without any transformations.
            // Hence, we can never have a u8 value other than the ones assigned to a variant.
            None => unreachable!("{} is not member of enum MlsTransportResponseVariant", value),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmMlsTransportResponse {
    #[wasm_bindgen(readonly)]
    pub variant: MlsTransportResponseVariant,
    #[wasm_bindgen(readonly)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<String>,
}

#[wasm_bindgen]
impl WasmMlsTransportResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(variant: MlsTransportResponseVariant, abort_reason: Option<String>) -> WasmMlsTransportResponse {
        WasmMlsTransportResponse { variant, abort_reason }
    }
}

impl From<WasmMlsTransportResponse> for MlsTransportResponse {
    fn from(response: WasmMlsTransportResponse) -> Self {
        match response.variant {
            MlsTransportResponseVariant::Success => MlsTransportResponse::Success,
            MlsTransportResponseVariant::Retry => MlsTransportResponse::Retry,
            MlsTransportResponseVariant::Abort => MlsTransportResponse::Abort {
                reason: response.abort_reason.unwrap_or_default(),
            },
        }
    }
}

impl From<MlsTransportResponse> for WasmMlsTransportResponse {
    fn from(response: MlsTransportResponse) -> Self {
        match response {
            MlsTransportResponse::Success => WasmMlsTransportResponse {
                variant: MlsTransportResponseVariant::Success,
                abort_reason: None,
            },
            MlsTransportResponse::Retry => WasmMlsTransportResponse {
                variant: MlsTransportResponseVariant::Retry,
                abort_reason: None,
            },
            MlsTransportResponse::Abort { reason } => WasmMlsTransportResponse {
                variant: MlsTransportResponseVariant::Abort,
                abort_reason: (!reason.is_empty()).then_some(reason),
            },
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
/// see [core_crypto::prelude::MlsTransport]
pub struct MlsTransportProvider {
    send_commit_bundle: Arc<async_lock::RwLock<js_sys::Function>>,
    send_message: Arc<async_lock::RwLock<js_sys::Function>>,
    ctx: Arc<async_lock::RwLock<JsValue>>,
}

#[wasm_bindgen]
impl MlsTransportProvider {
    #[wasm_bindgen(constructor)]
    pub fn new(send_commit_bundle: js_sys::Function, send_message: js_sys::Function, ctx: JsValue) -> Self {
        #[allow(clippy::arc_with_non_send_sync)] // see https://github.com/rustwasm/wasm-bindgen/pull/955
        Self {
            send_commit_bundle: Arc::new(send_commit_bundle.into()),
            send_message: Arc::new(send_message.into()),
            ctx: Arc::new(ctx.into()),
        }
    }
}

impl MlsTransportProvider {
    async fn drive_js_func_call(
        function_return_value: Result<JsValue, JsValue>,
    ) -> Result<WasmMlsTransportResponse, JsValue> {
        let promise: Promise = match function_return_value?.dyn_into() {
            Ok(promise) => promise,
            Err(e) => {
                web_sys::console::error_1(&js_sys::JsString::from(
                    r#"
[CoreCrypto] One or more transport functions are not returning a `Promise`
Please make all callbacks `async` or manually return a `Promise` via `Promise.resolve()`"#,
                ));
                return Err(e);
            }
        };
        let js_future = wasm_bindgen_futures::JsFuture::from(promise);
        let serialized_response = js_future.await?;
        let response = serde_wasm_bindgen::from_value(serialized_response)?;
        Ok(response)
    }
}

// SAFETY: All callback instances are wrapped into Arc<RwLock> so this is safe to mark
unsafe impl Send for MlsTransportProvider {}
// SAFETY: All callback instances are wrapped into Arc<RwLock> so this is safe to mark
unsafe impl Sync for MlsTransportProvider {}

#[async_trait::async_trait(?Send)]
impl MlsTransport for MlsTransportProvider {
    async fn send_commit_bundle(
        &self,
        commit_bundle: MlsCommitBundle,
    ) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        let send_commit_bundle = self.send_commit_bundle.read().await;
        let this = self.ctx.read().await;
        let commit_bundle = CommitBundle::try_from(commit_bundle)
            .map_err(|e| core_crypto::Error::ErrorDuringMlsTransport(e.to_string()))?;
        Ok(
            Self::drive_js_func_call(send_commit_bundle.call1(&this, &commit_bundle.into()))
                .await
                .map_err(|e| core_crypto::Error::ErrorDuringMlsTransport(format!("JsError: {e:?}")))?
                .into(),
        )
    }

    async fn send_message(&self, mls_message: Vec<u8>) -> core_crypto::Result<MlsTransportResponse> {
        let send_message = self.send_message.read().await;
        let this = self.ctx.read().await;
        let mls_message = js_sys::Uint8Array::from(mls_message.as_slice());
        Ok(Self::drive_js_func_call(send_message.call1(&this, &mls_message))
            .await
            .map_err(|e| Error::ErrorDuringMlsTransport(format!("JsError: {e:?}")))?
            .into())
    }
}

#[derive(Debug)]
#[wasm_bindgen]
pub struct CoreCrypto {
    inner: Arc<core_crypto::CoreCrypto>,
}

#[wasm_bindgen]
impl CoreCrypto {
    /// Returns the current version of CoreCrypto
    pub fn version() -> String {
        crate::VERSION.into()
    }

    /// Returs build data for CoreCrypto
    pub fn build_metadata() -> BuildMetadata {
        BuildMetadata {
            timestamp: core_crypto::BUILD_METADATA.timestamp,
            cargo_debug: core_crypto::BUILD_METADATA.cargo_debug,
            cargo_features: core_crypto::BUILD_METADATA.cargo_features,
            opt_level: core_crypto::BUILD_METADATA.opt_level,
            target_triple: core_crypto::BUILD_METADATA.target_triple,
            git_branch: core_crypto::BUILD_METADATA.git_branch,
            git_describe: core_crypto::BUILD_METADATA.git_describe,
            git_sha: core_crypto::BUILD_METADATA.git_sha,
            git_dirty: core_crypto::BUILD_METADATA.git_dirty,
        }
    }

    /// see [core_crypto::mls::Client::try_new]
    pub async fn _internal_new(
        path: String,
        key: String,
        client_id: FfiClientId,
        ciphersuites: Box<[u16]>,
        entropy_seed: Option<Box<[u8]>>,
        nb_key_package: Option<u32>,
    ) -> WasmCryptoResult<CoreCrypto> {
        console_error_panic_hook::set_once();
        let ciphersuites = lower_ciphersuites(&ciphersuites)?;
        let entropy_seed = entropy_seed.map(|s| s.to_vec());
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .expect("we never run corecrypto on systems with architectures narrower than 32 bits");
        let configuration = MlsClientConfiguration::try_new(
            path,
            key,
            Some(client_id.into()),
            ciphersuites,
            entropy_seed,
            nb_key_package,
        )
        .map_err(CoreCryptoError::from)?;

        let client = Client::try_new(configuration).await.map_err(CoreCryptoError::from)?;
        Ok(CoreCrypto {
            inner: Arc::new(client.into()),
        })
    }

    /// see [core_crypto::mls::Client::try_new]
    pub async fn deferred_init(
        path: String,
        key: String,
        entropy_seed: Option<Box<[u8]>>,
    ) -> WasmCryptoResult<CoreCrypto> {
        let entropy_seed = entropy_seed.map(|s| s.to_vec());
        let configuration = MlsClientConfiguration::try_new(path, key, None, vec![], entropy_seed, None)
            .map_err(CoreCryptoError::from)?;

        let client = Client::try_new(configuration).await.map_err(CoreCryptoError::from)?;

        Ok(CoreCrypto {
            inner: Arc::new(client.into()),
        })
    }

    /// Returns the Arc strong ref count
    pub fn has_outstanding_refs(&self) -> bool {
        Arc::strong_count(&self.inner) > 1
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::Client::close]
    pub fn close(self) -> Promise {
        let error_message: &JsValue = &format!(
            "There are other outstanding references to this CoreCrypto instance [strong refs = {}]",
            Arc::strong_count(&self.inner),
        )
        .into();
        match Arc::into_inner(self.inner) {
            Some(central) => future_to_promise(
                async move {
                    central.take().close().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                }
                .err_into(),
            ),
            None => Promise::reject(error_message),
        }
    }

    pub fn set_logger(logger: CoreCryptoWasmLogger) {
        // unwrapping poisoned lock error which shouldn't happen since we don't panic while replacing the logger
        LOGGER.handle().replace(logger).unwrap();

        INIT_LOGGER.call_once(|| {
            log::set_logger(LOGGER.deref()).unwrap();
            log::set_max_level(LevelFilter::Warn);
        });
    }

    pub fn set_max_log_level(level: CoreCryptoLogLevel) {
        log::set_max_level(level.into());
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::Client::provide_transport]
    pub fn provide_transport(&self, callbacks: MlsTransportProvider) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                central.provide_transport(Arc::new(callbacks)).await;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns:: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::Client::client_public_key]
    pub fn client_public_key(&self, ciphersuite: Ciphersuite, credential_type: CredentialType) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let pk = central
                    .public_key(ciphersuite.into(), credential_type.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(pk.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<u64>`]
    ///
    /// see [core_crypto::mls::conversation::ImmutableConversation::epoch]
    pub fn conversation_epoch(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let epoch = central
                    .get_raw_conversation(&conversation_id)
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .epoch()
                    .await
                    .into();
                WasmCryptoResult::Ok(epoch)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Ciphersuite>`]
    ///
    /// see [core_crypto::mls::conversation::ImmutableConversation::ciphersuite]
    pub fn conversation_ciphersuite(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let ciphersuite: Ciphersuite = central
                    .get_raw_conversation(&conversation_id)
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .ciphersuite()
                    .await
                    .into();
                WasmCryptoResult::Ok(ciphersuite.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`bool`]
    ///
    /// see [core_crypto::mls::Client::conversation_exists]
    pub fn conversation_exists(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(
                    if central
                        .conversation_exists(&conversation_id)
                        .await
                        .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    {
                        JsValue::TRUE
                    } else {
                        JsValue::FALSE
                    },
                )
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::Client::random_bytes]
    pub fn random_bytes(&self, len: usize) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let bytes = central.random_bytes(len).map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(bytes.as_slice()).into())
            }
            .err_into(),
        )
    }

    #[allow(rustdoc::broken_intra_doc_links)]
    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [mls_crypto_provider::MlsCryptoProvider::reseed]
    pub fn reseed_rng(&self, seed: Box<[u8]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let seed = EntropySeed::try_from_slice(&seed)
                    .map_err(core_crypto::MlsError::wrap(
                        "trying to construct entropy seed from slice",
                    ))
                    .map_err(core_crypto::Error::Mls)?;

                central.reseed(Some(seed)).await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<bool>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_exists]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_exists(&self, session_id: String) -> Promise {
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! {{
                    let exists = central.proteus_session_exists(&session_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::from_bool(exists))
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<u16>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_last_resort_prekey_id() -> WasmCryptoResult<u16> {
        proteus_impl! {{
            Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id())
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint(&self) -> WasmCryptoResult<String> {
        let central = self.inner.clone();

        proteus_impl! {{
            central.proteus_fingerprint().await.map_err(CoreCryptoError::from)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_local]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> WasmCryptoResult<String> {
        let central = self.inner.clone();

        proteus_impl! {{
            central
                .proteus_fingerprint_local(&session_id)
                .await
                .map_err(CoreCryptoError::from)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> WasmCryptoResult<String> {
        let central = self.inner.clone();

        proteus_impl! {{
            central.proteus_fingerprint_remote(&session_id).await
                .map_err(CoreCryptoError::from)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCproteus_fingerprint_prekeybundle]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_fingerprint_prekeybundle(prekey: Box<[u8]>) -> WasmCryptoResult<String> {
        proteus_impl!({
            core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey)
                .map_err(Into::into)
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// See [crate::mls::conversation::ImmutableConversation::export_secret_key]
    pub fn export_secret_key(&self, conversation_id: ConversationId, key_length: usize) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let key = central
                    .get_raw_conversation(&conversation_id.to_vec())
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .export_secret_key(key_length)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(key.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// See [crate::mls::conversation::ImmutableConversation::get_external_sender]
    pub fn get_external_sender(&self, id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let ext_sender = central
                    .get_raw_conversation(&id.to_vec())
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .get_external_sender()
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(ext_sender.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Box<[js_sys::Uint8Array]>`]
    ///
    /// See [core_crypto::mls::conversation::ImmutableConversation::get_client_ids]
    pub fn get_client_ids(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let clients = central
                    .get_raw_conversation(&conversation_id.to_vec())
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .get_client_ids()
                    .await;
                let clients = js_sys::Array::from_iter(
                    clients
                        .into_iter()
                        .map(|client| Uint8Array::from(client.as_slice()))
                        .map(JsValue::from),
                );
                WasmCryptoResult::Ok(clients.into())
            }
            .err_into(),
        )
    }
}

// End-to-end identity methods
#[wasm_bindgen]
impl CoreCrypto {
    /// See [core_crypto::mls::context::CentralContext::e2ei_dump_pki_env]
    pub async fn e2ei_dump_pki_env(&self) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let dump: Option<E2eiDumpedPkiEnv> = central
                    .e2ei_dump_pki_env()
                    .await
                    .map_err(RecursiveError::mls_client("dumping pki env"))?
                    .map(Into::into);
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&dump)?)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::context::CentralContext::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> Promise {
        let central = self.inner.clone();
        future_to_promise(async move { WasmCryptoResult::Ok(central.e2ei_is_pki_env_setup().await.into()) }.err_into())
    }

    /// Returns [`WasmCryptoResult<bool>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::e2ei_is_enabled]
    pub fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> Promise {
        let sc = MlsCiphersuite::from(ciphersuite).signature_algorithm();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let is_enabled = central
                    .e2ei_is_enabled(sc)
                    .await
                    .map_err(RecursiveError::mls_client("is e2ei enabled for client"))?
                    .into();
                WasmCryptoResult::Ok(is_enabled)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Vec<WireIdentity>>`]
    ///
    /// see [core_crypto::mls::conversation::ConversationGuard::get_device_identities]
    pub fn get_device_identities(&self, conversation_id: ConversationId, device_ids: Box<[Uint8Array]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let device_ids = device_ids.iter().map(|c| c.to_vec().into()).collect::<Vec<ClientId>>();
                let identities = central
                    .get_raw_conversation(&conversation_id)
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .get_device_identities(&device_ids[..])
                    .await
                    .map_err(CoreCryptoError::from)?
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<WireIdentity>>();
                WasmCryptoResult::Ok(identities.into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<HashMap<String, Vec<WireIdentity>>>`]
    ///
    /// see [core_crypto::mls::conversation::ConversationGuard::get_user_identities]
    pub fn get_user_identities(&self, conversation_id: ConversationId, user_ids: Box<[String]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let identities = central
                    .get_raw_conversation(&conversation_id)
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .get_user_identities(user_ids.deref())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .into_iter()
                    .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
                    .collect::<HashMap<String, Vec<WireIdentity>>>();
                let js_obj = js_sys::Map::new();
                for (uid, identities) in identities.into_iter() {
                    let uid = js_sys::JsString::from(uid).into();
                    let identities = JsValue::from(identities);
                    js_obj.set(&uid, &identities);
                }
                WasmCryptoResult::Ok(js_obj.into())
            }
            .err_into(),
        )
    }

    #[allow(clippy::boxed_local)]
    /// Returns: [`WasmCryptoResult<u8>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::get_credential_in_use]
    pub fn get_credential_in_use(&self, group_info: Box<[u8]>, credential_type: CredentialType) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_ref())
                    .map_err(|e| MlsError::Other(e.to_string()))
                    .map_err(CoreCryptoError::from)?;

                let state: E2eiConversationState = central
                    .get_credential_in_use(group_info, credential_type.into())
                    .await
                    .map(Into::into)
                    .map_err(RecursiveError::mls_client("getting credential in use"))?;

                WasmCryptoResult::Ok((state as u8).into())
            }
            .err_into(),
        )
    }
}

#[derive(Debug)]
#[wasm_bindgen(js_name = FfiWireE2EIdentity)]
#[repr(transparent)]
pub struct E2eiEnrollment(pub(super) Arc<async_lock::RwLock<core_crypto::prelude::E2eiEnrollment>>);

#[wasm_bindgen(js_class = FfiWireE2EIdentity)]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::WireE2eIdentity::directory_response]
    pub fn directory_response(&mut self, directory: Vec<u8>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let directory: AcmeDirectory = this.directory_response(directory)?.into();
                WasmCryptoResult::Ok(directory.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_account_request]
    pub fn new_account_request(&self, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let new_account: Vec<u8> = this.new_account_request(previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(new_account.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_account_response]
    pub fn new_account_response(&mut self, account: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                this.new_account_response(account.to_vec())?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_order_request]
    pub fn new_order_request(&self, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let new_order = this.new_order_request(previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(new_order.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_order_response]
    pub fn new_order_response(&self, order: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let order: NewAcmeOrder = this.new_order_response(order.to_vec())?.into();
                WasmCryptoResult::Ok(order.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_authz_request]
    pub fn new_authz_request(&self, url: String, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let new_authz = this.new_authz_request(url, previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(new_authz.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_authz_response]
    pub fn new_authz_response(&mut self, authz: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let authz: NewAcmeAuthz = this.new_authz_response(authz.to_vec())?.into();
                WasmCryptoResult::Ok(authz.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::create_dpop_token]
    pub fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let dpop_token = this.create_dpop_token(expiry_secs, backend_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(dpop_token.as_bytes()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_dpop_challenge_request]
    pub fn new_dpop_challenge_request(&self, access_token: String, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let chall = this.new_dpop_challenge_request(access_token, previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(chall.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_dpop_challenge_response]
    pub fn new_dpop_challenge_response(&self, challenge: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                this.new_dpop_challenge_response(challenge.to_vec())?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_oidc_challenge_request]
    pub fn new_oidc_challenge_request(&mut self, id_token: String, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let chall = this.new_oidc_challenge_request(id_token, previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(chall.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_oidc_challenge_response]
    pub fn new_oidc_challenge_response(&mut self, challenge: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                this.new_oidc_challenge_response(challenge.to_vec()).await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::check_order_request]
    pub fn check_order_request(&self, order_url: String, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let new_order = this.check_order_request(order_url, previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(new_order.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::check_order_response]
    pub fn check_order_response(&mut self, order: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                WasmCryptoResult::Ok(this.check_order_response(order.to_vec())?.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::finalize_request]
    pub fn finalize_request(&mut self, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let finalize = this.finalize_request(previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(finalize.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::finalize_response]
    pub fn finalize_response(&mut self, finalize: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                WasmCryptoResult::Ok(this.finalize_response(finalize.to_vec())?.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::certificate_request]
    pub fn certificate_request(&mut self, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let certificate_req = this.certificate_request(previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(certificate_req.as_slice()).into())
            }
            .err_into(),
        )
    }
}

/// Holds URLs of all the standard ACME endpoint supported on an ACME server.
/// @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
#[wasm_bindgen(skip_jsdoc, getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcmeDirectory {
    /// URL for fetching a new nonce. Use this only for creating a new account.
    #[wasm_bindgen(readonly)]
    pub new_nonce: String,
    /// URL for creating a new account.
    #[wasm_bindgen(readonly)]
    pub new_account: String,
    /// URL for creating a new order.
    #[wasm_bindgen(readonly)]
    pub new_order: String,
    /// Revocation URL
    #[wasm_bindgen(readonly)]
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

/// Result of an order creation.
/// @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
#[wasm_bindgen(skip_jsdoc)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewAcmeOrder {
    /// Contains raw JSON data of this order. This is parsed by the underlying Rust library hence should not be accessed
    #[wasm_bindgen(readonly, getter_with_clone)]
    pub delegate: Vec<u8>,
    authorizations: ArrayOfByteArray,
}

#[wasm_bindgen]
impl NewAcmeOrder {
    #[wasm_bindgen(getter)]
    pub fn authorizations(&self) -> Vec<Uint8Array> {
        self.authorizations.clone().into()
    }
}

impl From<core_crypto::prelude::E2eiNewAcmeOrder> for NewAcmeOrder {
    fn from(new_order: core_crypto::prelude::E2eiNewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order
                .authorizations
                .into_iter()
                .map(String::into_bytes)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl TryFrom<NewAcmeOrder> for core_crypto::prelude::E2eiNewAcmeOrder {
    type Error = CoreCryptoError;

    fn try_from(new_order: NewAcmeOrder) -> WasmCryptoResult<Self> {
        let authorizations = new_order
            .authorizations
            .0
            .into_iter()
            .map(String::from_utf8)
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| InternalError::Other("invalid authorization string: not utf8".into()))?;
        Ok(Self {
            delegate: new_order.delegate,
            authorizations,
        })
    }
}

/// Result of an authorization creation.
/// @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
#[wasm_bindgen(skip_jsdoc, getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewAcmeAuthz {
    /// DNS entry associated with those challenge
    #[wasm_bindgen(readonly)]
    pub identifier: String,
    /// ACME challenge + ACME key thumbprint
    #[wasm_bindgen(readonly)]
    pub keyauth: Option<String>,
    /// Associated ACME Challenge
    #[wasm_bindgen(readonly)]
    pub challenge: AcmeChallenge,
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: authz.identifier,
            keyauth: authz.keyauth,
            challenge: authz.challenge.into(),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: authz.identifier,
            keyauth: authz.keyauth,
            challenge: authz.challenge.into(),
        }
    }
}

/// For creating a challenge.
/// @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
#[wasm_bindgen(skip_jsdoc, getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcmeChallenge {
    /// Contains raw JSON data of this challenge. This is parsed by the underlying Rust library hence should not be accessed
    #[wasm_bindgen(readonly)]
    pub delegate: Vec<u8>,
    /// URL of this challenge
    #[wasm_bindgen(readonly)]
    pub url: String,
    /// Non-standard, Wire specific claim. Indicates the consumer from where it should get the challenge proof.
    /// Either from wire-server "/access-token" endpoint in case of a DPoP challenge, or from an OAuth token endpoint for an OIDC challenge
    #[wasm_bindgen(readonly)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
/// see [core_crypto::prelude::E2eiConversationState]
enum E2eiConversationState {
    Verified = 1,
    /// Some clients are either still Basic or their certificate is expired
    NotVerified = 2,
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is returned.
    NotEnabled = 3,
}

impl From<core_crypto::prelude::E2eiConversationState> for E2eiConversationState {
    fn from(state: core_crypto::prelude::E2eiConversationState) -> Self {
        match state {
            core_crypto::prelude::E2eiConversationState::Verified => Self::Verified,
            core_crypto::prelude::E2eiConversationState::NotVerified => Self::NotVerified,
            core_crypto::prelude::E2eiConversationState::NotEnabled => Self::NotEnabled,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
/// see [core_crypto::prelude::DeviceStatus]
pub enum DeviceStatus {
    /// All is fine
    Valid = 1,
    /// The Credential's certificate is expired
    Expired = 2,
    /// The Credential's certificate is revoked (not implemented yet)
    Revoked = 3,
}

impl From<core_crypto::prelude::DeviceStatus> for DeviceStatus {
    fn from(state: core_crypto::prelude::DeviceStatus) -> Self {
        match state {
            core_crypto::prelude::DeviceStatus::Valid => Self::Valid,
            core_crypto::prelude::DeviceStatus::Expired => Self::Expired,
            core_crypto::prelude::DeviceStatus::Revoked => Self::Revoked,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
