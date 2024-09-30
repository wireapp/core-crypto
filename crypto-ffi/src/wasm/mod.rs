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
mod utils;

use std::collections::HashMap;
use std::ops::Deref;

use core_crypto::prelude::*;
use core_crypto::CryptoError;
use futures_util::future::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use std::ops::DerefMut;
use std::sync::Arc;
use tls_codec::{Deserialize, Serialize};
use tracing::{level_filters::LevelFilter, Level};
use tracing_subscriber::fmt::{self, MakeWriter};
use utils::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;

#[allow(dead_code)]
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

// This is intended to hotfix this import:
// ❯ wasmer inspect bindings/js/wasm/core-crypto-ffi_bg.wasm | grep env
//    "env"."__stack_chk_fail": [] -> []
#[no_mangle]
pub extern "C" fn __stack_chk_fail() {
    panic!("Stack overflow detected");
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
enum WasmError {
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    #[error(transparent)]
    E2eError(#[from] E2eIdentityError),
    #[error(transparent)]
    SerializationError(#[from] serde_wasm_bindgen::Error),
    #[error("Failed lifting an enum")]
    EnumError,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreCryptoJsRichError {
    error_name: String,
    message: String,
    rust_stack_trace: String,
    proteus_error_code: u32,
}

impl<'a> From<&'a CoreCryptoError> for CoreCryptoJsRichError {
    fn from(e: &'a CoreCryptoError) -> Self {
        Self {
            error_name: match e.0 {
                WasmError::CryptoError(_) => "CryptoError",
                WasmError::E2eError(_) => "E2eError",
                WasmError::SerializationError(_) => "SerializationError",
                WasmError::EnumError => "EnumError",
            }
            .to_string(),
            message: e.0.to_string(),
            rust_stack_trace: format!("{:?}", e.0),
            proteus_error_code: e.proteus_error_code(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub struct CoreCryptoError(#[from] WasmError);

impl CoreCryptoError {
    fn proteus_error_code(&self) -> u32 {
        let WasmError::CryptoError(e) = &self.0 else {
            return 0;
        };

        e.proteus_error_code()
    }
}

impl std::fmt::Display for CoreCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let rich_error = CoreCryptoJsRichError::from(self);
        let rich_error_json = serde_json::to_string(&rich_error).map_err(|_| std::fmt::Error)?;
        write!(f, "{}\n\n{rich_error_json}", self.0)
    }
}

impl From<CryptoError> for CoreCryptoError {
    fn from(e: CryptoError) -> Self {
        Self(e.into())
    }
}

impl From<E2eIdentityError> for CoreCryptoError {
    fn from(e: E2eIdentityError) -> Self {
        Self(e.into())
    }
}

impl From<serde_wasm_bindgen::Error> for CoreCryptoError {
    fn from(e: serde_wasm_bindgen::Error) -> Self {
        Self(e.into())
    }
}

impl From<CoreCryptoError> for wasm_bindgen::JsValue {
    fn from(val: CoreCryptoError) -> Self {
        js_sys::Error::new(&val.to_string()).into()
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
            let cs = Ciphersuite::from_repr(cs).ok_or(WasmError::EnumError)?;
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
#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::MlsConversationCreationMessage]
pub struct MemberAddedMessages {
    welcome: Vec<u8>,
    commit: Vec<u8>,
    group_info: GroupInfoBundle,
    crl_new_distribution_points: Option<Vec<String>>,
}

#[wasm_bindgen]
impl MemberAddedMessages {
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Uint8Array {
        Uint8Array::from(&*self.welcome)
    }

    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        Uint8Array::from(&*self.commit)
    }

    #[wasm_bindgen(getter)]
    pub fn group_info(&self) -> GroupInfoBundle {
        self.group_info.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn crl_new_distribution_points(&self) -> Option<js_sys::Array> {
        self.crl_new_distribution_points
            .clone()
            .map(|crl_dp| crl_dp.iter().cloned().map(JsValue::from).collect::<js_sys::Array>())
    }
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, commit, pgs, crl_new_distribution_points) =
            msg.to_bytes().map_err(CryptoError::from).map_err(Self::Error::from)?;

        Ok(Self {
            welcome,
            commit,
            group_info: pgs.into(),
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

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
        let (welcome, commit, pgs) = msg
            .to_bytes_triple()
            .map_err(CryptoError::from)
            .map_err(Self::Error::from)?;

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
pub struct RotateBundle {
    commits: HashMap<String, CommitBundle>,
    new_key_packages: Vec<Vec<u8>>,
    key_package_refs_to_remove: Vec<Vec<u8>>,
    /// New CRL Distribution of members of this group
    crl_new_distribution_points: Option<Vec<String>>,
}

#[wasm_bindgen]
impl RotateBundle {
    #[wasm_bindgen(getter)]
    pub fn commits(&self) -> js_sys::Map {
        let commits = js_sys::Map::new();
        for (id, c) in &self.commits {
            commits.set(&JsValue::from(id), &JsValue::from(c.clone()));
        }
        commits
    }

    #[wasm_bindgen(getter)]
    pub fn new_key_packages(&self) -> Vec<Uint8Array> {
        self.new_key_packages
            .iter()
            .cloned()
            .map(|jsv| jsv.as_slice().into())
            .collect()
    }

    #[wasm_bindgen(getter)]
    pub fn key_package_refs_to_remove(&self) -> Vec<Uint8Array> {
        self.key_package_refs_to_remove
            .iter()
            .cloned()
            .map(|jsv| jsv.as_slice().into())
            .collect()
    }

    #[wasm_bindgen(getter)]
    pub fn crl_new_distribution_points(&self) -> Option<js_sys::Array> {
        self.crl_new_distribution_points
            .clone()
            .map(|crl_dp| crl_dp.iter().cloned().map(JsValue::from).collect::<js_sys::Array>())
    }
}

impl TryFrom<MlsRotateBundle> for RotateBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsRotateBundle) -> Result<Self, Self::Error> {
        let (commits, new_key_packages, key_package_refs_to_remove, crl_new_distribution_points) =
            msg.to_bytes().map_err(CryptoError::from).map_err(Self::Error::from)?;

        let commits_size = commits.len();
        let commits = commits
            .into_iter()
            .try_fold(HashMap::with_capacity(commits_size), |mut acc, (id, c)| {
                let _ = acc.insert(id, c.try_into()?);
                WasmCryptoResult::Ok(acc)
            })?;

        Ok(Self {
            commits,
            new_key_packages,
            key_package_refs_to_remove,
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProposalBundle {
    /// TLS-serialized MLS proposal that needs to be fanned out to other (existing) members of the conversation
    proposal: Vec<u8>,
    /// Unique identifier of a proposal. Use this in {@link CoreCrypto.clearPendingProposal} to roll back (delete) the proposal
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
        let (proposal, proposal_ref, crl_new_distribution_points) =
            msg.to_bytes().map_err(CryptoError::from).map_err(Self::Error::from)?;

        Ok(Self {
            proposal,
            proposal_ref,
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

#[wasm_bindgen(skip_jsdoc, getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConversationInitBundle {
    conversation_id: ConversationId,
    commit: Vec<u8>,
    group_info: GroupInfoBundle,
    /// New CRL Distribution of members of this group
    crl_new_distribution_points: Option<Vec<String>>,
}

#[wasm_bindgen]
impl ConversationInitBundle {
    #[wasm_bindgen(getter)]
    pub fn conversation_id(&self) -> Uint8Array {
        Uint8Array::from(&*self.conversation_id)
    }

    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        Uint8Array::from(&*self.commit)
    }

    #[wasm_bindgen(getter)]
    pub fn group_info(&self) -> GroupInfoBundle {
        self.group_info.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn crl_new_distribution_points(&self) -> Option<js_sys::Array> {
        self.crl_new_distribution_points
            .clone()
            .map(|crl_dp| crl_dp.iter().cloned().map(JsValue::from).collect::<js_sys::Array>())
    }
}

impl TryFrom<MlsConversationInitBundle> for ConversationInitBundle {
    type Error = CoreCryptoError;

    fn try_from(mut from: MlsConversationInitBundle) -> Result<Self, Self::Error> {
        let conversation_id = std::mem::take(&mut from.conversation_id);
        let (commit, pgs, crl_new_distribution_points) =
            from.to_bytes().map_err(CryptoError::from).map_err(Self::Error::from)?;

        Ok(Self {
            conversation_id,
            commit,
            group_info: pgs.into(),
            crl_new_distribution_points: crl_new_distribution_points.into(),
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::WelcomeBundle]
pub struct WelcomeBundle {
    /// Identifier of the joined conversation
    id: ConversationId,
    /// New CRL Distribution of members of this group
    crl_new_distribution_points: Option<Vec<String>>,
}

#[wasm_bindgen]
impl WelcomeBundle {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Uint8Array {
        Uint8Array::from(&*self.id)
    }

    #[wasm_bindgen(getter)]
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

        let commit_delay = if let Some(delay) = from.delay {
            Some(delay.try_into().map_err(CryptoError::from)?)
        } else {
            None
        };

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

        let commit_delay = if let Some(delay) = from.delay {
            Some(delay.try_into().map_err(CryptoError::from)?)
        } else {
            None
        };

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

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    client_id: String,
    /// Status of the Credential at the moment T when this object is created
    status: u8,
    /// MLS thumbprint
    thumbprint: String,
    credential_type: u8,
    x509_identity: Option<X509Identity>,
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

#[wasm_bindgen]
impl WireIdentity {
    #[wasm_bindgen(getter)]
    pub fn client_id(&self) -> String {
        self.client_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn status(&self) -> u8 {
        self.status
    }

    #[wasm_bindgen(getter)]
    pub fn thumbprint(&self) -> String {
        self.thumbprint.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn credential_type(&self) -> u8 {
        self.credential_type
    }

    #[wasm_bindgen(getter)]
    pub fn x509_identity(&self) -> Option<X509Identity> {
        self.x509_identity.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
pub struct X509Identity {
    /// user handle e.g. `john_wire`
    handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    domain: String,
    /// X509 certificate identifying this client in the MLS group ; PEM encoded
    certificate: String,
    /// X509 certificate serial number
    serial_number: String,
    /// X509 certificate not before as Unix timestamp
    not_before: u64,
    /// X509 certificate not after as Unix timestamp
    not_after: u64,
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

#[wasm_bindgen]
impl X509Identity {
    #[wasm_bindgen(getter)]
    pub fn handle(&self) -> String {
        self.handle.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn display_name(&self) -> String {
        self.display_name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn domain(&self) -> String {
        self.domain.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn certificate(&self) -> String {
        self.certificate.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn serial_number(&self) -> String {
        self.serial_number.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    #[wasm_bindgen(getter)]
    pub fn not_after(&self) -> u64 {
        self.not_after
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
/// see [core_crypto::prelude::MlsConversationConfiguration]
pub struct ConversationConfiguration {
    ciphersuite: Option<Ciphersuite>,
    external_senders: Vec<Vec<u8>>,
    custom: CustomConfiguration,
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
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::MlsCustomConfiguration]
pub struct CustomConfiguration {
    key_rotation_span: Option<u32>,
    wire_policy: Option<WirePolicy>,
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

impl Drop for CustomConfiguration {
    fn drop(&mut self) {
        let _ = self.key_rotation_span.take();
        let _ = self.wire_policy.take();
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

#[wasm_bindgen]
pub fn set_logger(logger: CoreCryptoWasmLogger, level: CoreCryptoLogLevel) {
    fmt::fmt()
        .json()
        .with_writer(logger)
        .with_max_level(LevelFilter::from(level))
        .init()
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct CoreCryptoWasmLogger {
    logger: js_sys::Function,
    level: CoreCryptoLogLevel,
    ctx: JsValue,
}

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
            CoreCryptoLogLevel::Off => LevelFilter::OFF,
            CoreCryptoLogLevel::Trace => LevelFilter::TRACE,
            CoreCryptoLogLevel::Debug => LevelFilter::DEBUG,
            CoreCryptoLogLevel::Info => LevelFilter::INFO,
            CoreCryptoLogLevel::Warn => LevelFilter::WARN,
            CoreCryptoLogLevel::Error => LevelFilter::ERROR,
        }
    }
}

impl From<&Level> for CoreCryptoLogLevel {
    fn from(value: &Level) -> CoreCryptoLogLevel {
        match *value {
            Level::WARN => CoreCryptoLogLevel::Warn,
            Level::ERROR => CoreCryptoLogLevel::Error,
            Level::INFO => CoreCryptoLogLevel::Info,
            Level::DEBUG => CoreCryptoLogLevel::Debug,
            Level::TRACE => CoreCryptoLogLevel::Trace,
        }
    }
}

#[wasm_bindgen]
impl CoreCryptoWasmLogger {
    #[wasm_bindgen(constructor)]
    pub fn new(logger: js_sys::Function, ctx: JsValue) -> Self {
        Self {
            logger,
            level: CoreCryptoLogLevel::Info,
            ctx,
        }
    }

    fn clone_with_level(&self, level: &Level) -> Self {
        Self {
            logger: self.logger.clone(),
            level: level.into(),
            ctx: self.ctx.clone(),
        }
    }
}

impl std::io::Write for CoreCryptoWasmLogger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let message = String::from_utf8_lossy(buf);
        let _ = self
            .logger
            .call2(&self.ctx, &JsValue::from(self.level), &JsValue::from(message.as_ref()));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for CoreCryptoWasmLogger {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }

    fn make_writer_for(&'_ self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        self.clone_with_level(meta.level())
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
/// see [core_crypto::prelude::CoreCryptoCallbacks]
pub struct CoreCryptoWasmCallbacks {
    authorize: std::sync::Arc<async_lock::RwLock<js_sys::Function>>,
    user_authorize: std::sync::Arc<async_lock::RwLock<js_sys::Function>>,
    client_is_existing_group_user: std::sync::Arc<async_lock::RwLock<js_sys::Function>>,
    ctx: std::sync::Arc<async_lock::RwLock<JsValue>>,
}

#[wasm_bindgen]
impl CoreCryptoWasmCallbacks {
    #[wasm_bindgen(constructor)]
    pub fn new(
        authorize: js_sys::Function,
        user_authorize: js_sys::Function,
        client_is_existing_group_user: js_sys::Function,
        ctx: JsValue,
    ) -> Self {
        #[allow(clippy::arc_with_non_send_sync)] // see https://github.com/rustwasm/wasm-bindgen/pull/955
        Self {
            authorize: std::sync::Arc::new(authorize.into()),
            user_authorize: std::sync::Arc::new(user_authorize.into()),
            client_is_existing_group_user: std::sync::Arc::new(client_is_existing_group_user.into()),
            ctx: std::sync::Arc::new(ctx.into()),
        }
    }
}

impl CoreCryptoWasmCallbacks {
    async fn drive_js_func_call(result: Result<JsValue, JsValue>) -> Result<bool, JsValue> {
        let value = result?;
        let promise: js_sys::Promise = match value.dyn_into() {
            Ok(promise) => promise,
            Err(e) => {
                web_sys::console::warn_1(&js_sys::JsString::from(
                    r#"
[CoreCrypto] One or more callbacks are not returning a `Promise`

They will thus be automatically coerced into returning `false`.
Please make all callbacks `async` or manually return a `Promise` via `Promise.resolve(boolean)`"#,
                ));
                return Err(e);
            }
        };
        let fut = wasm_bindgen_futures::JsFuture::from(promise);

        fut.await.map(|jsval| jsval.as_bool().unwrap_or_default())
    }
}

// SAFETY: All callback instances are wrapped into Arc<RwLock> so this is safe to mark
unsafe impl Send for CoreCryptoWasmCallbacks {}
unsafe impl Sync for CoreCryptoWasmCallbacks {}
unsafe impl Send for CoreCryptoWasmLogger {}
unsafe impl Sync for CoreCryptoWasmLogger {}

#[async_trait::async_trait(?Send)]
impl CoreCryptoCallbacks for CoreCryptoWasmCallbacks {
    async fn authorize(&self, conversation_id: ConversationId, client_id: ClientId) -> bool {
        let authorize = self.authorize.read().await;
        let this = self.ctx.read().await;

        Self::drive_js_func_call(authorize.call2(
            &this,
            &js_sys::Uint8Array::from(conversation_id.as_slice()),
            &js_sys::Uint8Array::from(client_id.as_slice()),
        ))
        .await
        .unwrap_or_default()
    }

    async fn user_authorize(
        &self,
        conversation_id: ConversationId,
        external_client_id: ClientId,
        existing_clients: Vec<ClientId>,
    ) -> bool {
        let user_authorize = self.user_authorize.read().await;
        let this = self.ctx.read().await;
        let clients = existing_clients
            .into_iter()
            .map(|client| js_sys::Uint8Array::from(client.as_slice()))
            .collect::<js_sys::Array>();

        Self::drive_js_func_call(user_authorize.call3(
            &this,
            &js_sys::Uint8Array::from(conversation_id.as_slice()),
            &js_sys::Uint8Array::from(external_client_id.as_slice()),
            &clients,
        ))
        .await
        .unwrap_or_default()
    }

    async fn client_is_existing_group_user(
        &self,
        conversation_id: ConversationId,
        client_id: ClientId,
        existing_clients: Vec<ClientId>,
        parent_conversation_clients: Option<Vec<ClientId>>,
    ) -> bool {
        let client_is_existing_group_user = self.client_is_existing_group_user.read().await;
        let this = self.ctx.read().await;
        let clients = existing_clients
            .into_iter()
            .map(|client| js_sys::Uint8Array::from(client.as_slice()))
            .collect::<js_sys::Array>();

        let parent_clients = parent_conversation_clients.map(|clients| {
            clients
                .into_iter()
                .map(|client_id| js_sys::Uint8Array::from(client_id.as_slice()))
                .collect::<js_sys::Array>()
        });

        Self::drive_js_func_call(client_is_existing_group_user.apply(
            &this,
            &js_sys::Array::of4(
                &js_sys::Uint8Array::from(conversation_id.as_slice()).into(),
                &js_sys::Uint8Array::from(client_id.as_slice()).into(),
                &clients.into(),
                &parent_clients.into(),
            ),
        ))
        .await
        .unwrap_or_default()
    }
}

#[derive(Debug)]
#[wasm_bindgen]
pub struct CoreCrypto {
    inner: Arc<core_crypto::CoreCrypto>,
    proteus_last_error_code: std::sync::Arc<async_lock::RwLock<u32>>,
}

#[wasm_bindgen]
impl CoreCrypto {
    /// Returns the current version of CoreCrypto
    pub fn version() -> String {
        crate::VERSION.into()
    }

    /// see [core_crypto::mls::MlsCentral::try_new]
    pub async fn _internal_new(
        path: String,
        key: String,
        client_id: FfiClientId,
        ciphersuites: Box<[u16]>,
        entropy_seed: Option<Box<[u8]>>,
        nb_key_package: Option<u32>,
    ) -> WasmCryptoResult<CoreCrypto> {
        let ciphersuites = lower_ciphersuites(&ciphersuites)?;
        let entropy_seed = entropy_seed.map(|s| s.to_vec());
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CryptoError::from)?;
        let configuration = MlsCentralConfiguration::try_new(
            path,
            key,
            Some(client_id.into()),
            ciphersuites,
            entropy_seed,
            nb_key_package,
        )
        .map_err(CoreCryptoError::from)?;

        let central = MlsCentral::try_new(configuration)
            .await
            .map_err(CoreCryptoError::from)?;
        Ok(CoreCrypto {
            inner: Arc::new(central.into()),
            proteus_last_error_code: async_lock::RwLock::new(0).into(),
        })
    }

    /// see [core_crypto::mls::MlsCentral::try_new]
    pub async fn deferred_init(
        path: String,
        key: String,
        entropy_seed: Option<Box<[u8]>>,
    ) -> WasmCryptoResult<CoreCrypto> {
        let entropy_seed = entropy_seed.map(|s| s.to_vec());
        let configuration = MlsCentralConfiguration::try_new(path, key, None, vec![], entropy_seed, None)
            .map_err(CoreCryptoError::from)?;

        let central = MlsCentral::try_new(configuration)
            .await
            .map_err(CoreCryptoError::from)?;

        Ok(CoreCrypto {
            inner: Arc::new(central.into()),
            proteus_last_error_code: async_lock::RwLock::new(0).into(),
        })
    }

    /// see [core_crypto::mls::MlsCentral::mls_init]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn mls_init(&self, client_id: FfiClientId, ciphersuites: Box<[u16]>, nb_key_package: Option<u32>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let ciphersuites = lower_ciphersuites(&ciphersuites)?;
                let nb_key_package = nb_key_package
                    .map(usize::try_from)
                    .transpose()
                    .map_err(CryptoError::from)?;
                context
                    .mls_init(
                        ClientIdentifier::Basic(client_id.clone().into()),
                        ciphersuites,
                        nb_key_package,
                    )
                    .await
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// See [core_crypto::mls::MlsCentral::mls_generate_keypair]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn mls_generate_keypair(&self, ciphersuites: Box<[u16]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let ciphersuites = lower_ciphersuites(&ciphersuites)?;
                let context = central.new_transaction().await;
                let pks = context
                    .mls_generate_keypairs(ciphersuites)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let js_pks = js_sys::Array::from_iter(
                    pks.into_iter()
                        .map(|kp| js_sys::Uint8Array::from(kp.as_slice()))
                        .map(JsValue::from),
                );
                context.finish().await?;
                WasmCryptoResult::Ok(js_pks.into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<()>`]
    ///
    /// See [core_crypto::mls::MlsCentral::mls_init_with_client_id]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn mls_init_with_client_id(
        &self,
        client_id: FfiClientId,
        signature_public_keys: Box<[Uint8Array]>,
        ciphersuites: Box<[u16]>,
    ) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let ciphersuites = lower_ciphersuites(&ciphersuites)?;
                let signature_public_keys = signature_public_keys
                    .iter()
                    .map(|c| ClientId::from(c.to_vec()))
                    .collect();

                let context = central.new_transaction().await;
                context
                    .mls_init_with_client_id(client_id.into(), signature_public_keys, ciphersuites)
                    .await
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns the Arc strong ref count
    pub fn has_outstanding_refs(&self) -> bool {
        Arc::strong_count(&self.inner) > 1
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::MlsCentral::close]
    pub fn close(self) -> Promise {
        let error_message = &js_sys::JsString::from(
            format!(
                "There are other outstanding references to this CoreCrypto instance [refs = {}]",
                Arc::strong_count(&self.inner)
            )
                .as_str(),
        );
        if self.has_outstanding_refs() {
            return Promise::reject(error_message);
        }
        let central = self.inner.clone();
        match Arc::try_unwrap(self.inner) {
            Ok(central) => future_to_promise(
                async move {
                    central.take().close().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                }
                .err_into(),
            ),
            Err(_) => Promise::reject(error_message),
        }
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::MlsCentral::wipe]
    pub fn wipe(self) -> Promise {
        let error_message = &js_sys::JsString::from(
            format!(
                "There are other outstanding references to this CoreCrypto instance [refs = {}]",
                Arc::strong_count(&self.inner)
            )
                .as_str(),
        );
        if self.has_outstanding_refs() {
            return Promise::reject(error_message);
        }
        let central = self.inner.clone();
        match Arc::try_unwrap(self.inner) {
            Ok(central) => future_to_promise(
                async move {
                    central.take().wipe().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                }
                    .err_into(),
            ),
            Err(_) => Promise::reject(error_message),
        }
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::MlsCentral::callbacks]
    pub fn set_callbacks(&self, callbacks: CoreCryptoWasmCallbacks) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                central.callbacks(std::sync::Arc::new(callbacks)).await;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns:: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::MlsCentral::client_public_key]
    pub fn client_public_key(&self, ciphersuite: Ciphersuite, credential_type: CredentialType) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let pk = central
                    .client_public_key(ciphersuite.into(), credential_type.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(pk.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Array<js_sys::Uint8Array>>`]
    ///
    /// see [core_crypto::mls::MlsCentral::client_keypackages]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn client_keypackages(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
        amount_requested: u32,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let kps = context
                    .get_or_create_client_keypackages(
                        ciphersuite.into(),
                        credential_type.into(),
                        amount_requested as usize,
                    )
                    .await?
                    .into_iter()
                    .map(|kpb| {
                        kpb.tls_serialize_detached()
                            .map_err(MlsError::from)
                            .map_err(CryptoError::from)
                            .map(Into::into)
                    })
                    .collect::<CryptoResult<Vec<Vec<u8>>>>()
                    .map_err(CoreCryptoError::from)?;

                let js_kps = js_sys::Array::from_iter(
                    kps.into_iter()
                        .map(|kp| js_sys::Uint8Array::from(kp.as_slice()))
                        .map(JsValue::from),
                );
                context.finish().await?;

                WasmCryptoResult::Ok(js_kps.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<usize>`]
    ///
    /// see [core_crypto::mls::MlsCentral::client_valid_keypackages_count]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn client_valid_keypackages_count(&self, ciphersuite: Ciphersuite, credential_type: CredentialType) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let count = context
                    .client_valid_key_packages_count(ciphersuite.into(), credential_type.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(count.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<usize>`]
    ///
    /// see [core_crypto::mls::MlsCentral::delete_keypackages]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    #[allow(clippy::boxed_local)]
    pub fn delete_keypackages(&self, refs: Box<[Uint8Array]>) -> Promise {
        let refs = refs
            .iter()
            .map(|r| r.to_vec())
            .map(|r| KeyPackageRef::from(r.as_slice()))
            .collect::<Vec<_>>();

        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                context
                    .delete_keypackages(&refs[..])
                    .await
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::MlsCentral::new_conversation]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn create_conversation(
        &self,
        conversation_id: ConversationId,
        creator_credential_type: CredentialType,
        mut config: ConversationConfiguration,
    ) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let mut lower_cfg = MlsConversationConfiguration {
                    custom: config.custom.into(),
                    ..Default::default()
                };

                if let Some(ciphersuite) = config.ciphersuite.take() {
                    let mls_ciphersuite: CiphersuiteName = ciphersuite.into();
                    lower_cfg.ciphersuite = mls_ciphersuite.into();
                }

                central.set_raw_external_senders(&mut lower_cfg, config.external_senders)?;

                let context = central.new_transaction().await;
                context
                    .new_conversation(&conversation_id.to_vec(), creator_credential_type.into(), lower_cfg)
                    .await
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<u64>`]
    ///
    /// see [core_crypto::mls::MlsCentral::conversation_epoch]
    pub fn conversation_epoch(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(
                    central
                        .conversation_epoch(&conversation_id)
                        .await
                        .map_err(CoreCryptoError::from)?
                        .into(),
                )
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Ciphersuite>`]
    ///
    /// see [core_crypto::mls::MlsCentral::conversation_ciphersuite]
    pub fn conversation_ciphersuite(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(
                    Ciphersuite::from(
                        central
                            .conversation_ciphersuite(&conversation_id)
                            .await
                            .map_err(CoreCryptoError::from)?,
                    )
                    .into(),
                )
            }
            .err_into(),
        )
    }

    /// Returns: [`bool`]
    ///
    /// see [core_crypto::mls::MlsCentral::conversation_exists]
    pub fn conversation_exists(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(if central.conversation_exists(&conversation_id).await? {
                    JsValue::TRUE
                } else {
                    JsValue::FALSE
                })
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::mls::MlsCentral::process_raw_welcome_message]
    pub fn process_welcome_message(
        &self,
        welcome_message: Box<[u8]>,
        custom_configuration: CustomConfiguration,
    ) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let bundle = context
                    .process_raw_welcome_message(welcome_message.into(), custom_configuration.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                let bundle: WelcomeBundle = bundle.into();
                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&bundle)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Option<MemberAddedMessages>>`]
    ///
    /// see [core_crypto::mls::MlsCentral::add_members_to_conversation]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn add_clients_to_conversation(
        &self,
        conversation_id: ConversationId,
        key_packages: Box<[Uint8Array]>,
    ) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let key_packages = key_packages
                    .iter()
                    .map(|kp| {
                        KeyPackageIn::tls_deserialize(&mut kp.to_vec().as_slice())
                            .map_err(|e| CoreCryptoError(WasmError::CryptoError(CryptoError::MlsError(e.into()))))
                    })
                    .collect::<CoreCryptoResult<Vec<_>>>()?;

                let context = central.new_transaction().await;
                let commit = context
                    .add_members_to_conversation(&conversation_id, key_packages)
                    .await?;
                let commit: MemberAddedMessages = commit.try_into()?;
                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Option<js_sys::Uint8Array>>`]
    ///
    /// see [core_crypto::mls::MlsCentral::remove_members_from_conversation]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn remove_clients_from_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Box<[Uint8Array]>,
    ) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let clients = clients
                    .iter()
                    .cloned()
                    .map(|c| c.to_vec().into())
                    .collect::<Vec<ClientId>>();

                let context = central.new_transaction().await;
                let commit = context
                    .remove_members_from_conversation(&conversation_id, &clients)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let commit: CommitBundle = commit.try_into()?;
                context.finish().await?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::MlsCentral::mark_conversation_as_child_of]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn mark_conversation_as_child_of(&self, child_id: Box<[u8]>, parent_id: Box<[u8]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                context
                    .mark_conversation_as_child_of(&child_id.into(), &parent_id.into())
                    .await
                    .map_err(CoreCryptoError::from)?;

                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<CommitBundle>`]
    ///
    /// see [core_crypto::mls::MlsCentral::update_keying_material]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn update_keying_material(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let commit = context
                    .update_keying_material(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let commit: CommitBundle = commit.try_into()?;
                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::MlsCentral::commit_pending_proposals]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn commit_pending_proposals(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let commit: Option<CommitBundle> = context
                    .commit_pending_proposals(&conversation_id)
                    .await?
                    .map(|c| c.try_into())
                    .transpose()?;

                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::MlsCentral::wipe_conversation]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn wipe_conversation(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                context
                    .wipe_conversation(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<DecryptedMessage>`]
    ///
    /// see [core_crypto::mls::MlsCentral::decrypt_message]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: Box<[u8]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let raw_decrypted_message = context
                    .decrypt_message(&conversation_id.to_vec(), payload)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let decrypted_message = DecryptedMessage::try_from(raw_decrypted_message)?;
                context.finish().await?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&decrypted_message)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::mls::MlsCentral::encrypt_message]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn encrypt_message(&self, conversation_id: ConversationId, message: Box<[u8]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let ciphertext = context
                    .encrypt_message(&conversation_id.to_vec(), message)
                    .await
                    .map(|ciphertext| Uint8Array::from(ciphertext.as_slice()))
                    .map_err(CoreCryptoError::from)?;

                context.finish().await?;
                WasmCryptoResult::Ok(ciphertext.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::MlsCentral::new_add_proposal]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn new_add_proposal(&self, conversation_id: ConversationId, keypackage: Box<[u8]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let kp = KeyPackageIn::tls_deserialize(&mut keypackage.as_ref())
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                let context = central.new_transaction().await;

                let proposal: ProposalBundle = context
                    .new_add_proposal(&conversation_id.to_vec(), kp.into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;

                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::MlsCentral::new_update_proposal]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn new_update_proposal(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let proposal: ProposalBundle = context
                    .new_update_proposal(&conversation_id.to_vec())
                    .await?
                    .try_into()?;

                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::MlsCentral::new_remove_proposal]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn new_remove_proposal(&self, conversation_id: ConversationId, client_id: FfiClientId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let proposal: ProposalBundle = context
                    .new_remove_proposal(&conversation_id.to_vec(), client_id.into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;

                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::MlsCentral::new_external_add_proposal]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn new_external_add_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: u32,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let proposal_bytes = context
                    .new_external_add_proposal(
                        conversation_id.to_vec(),
                        u64::from(epoch).into(),
                        ciphersuite.into(),
                        credential_type.into(),
                    )
                    .await
                    .map_err(CoreCryptoError::from)?
                    .to_bytes()
                    .map(|bytes| Uint8Array::from(bytes.as_slice()))
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                context.finish().await?;
                WasmCryptoResult::Ok(proposal_bytes.into())
            }
            .err_into(),
        )
    }

    #[allow(clippy::boxed_local)]
    /// Returns: [`WasmCryptoResult<ConversationInitBundle>`]
    ///
    /// see [core_crypto::mls::MlsCentral::join_by_external_commit]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn join_by_external_commit(
        &self,
        group_info: Box<[u8]>,
        custom_configuration: CustomConfiguration,
        credential_type: CredentialType,
    ) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_ref())
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                let context = central.new_transaction().await;
                let result: ConversationInitBundle = context
                    .join_by_external_commit(group_info, custom_configuration.into(), credential_type.into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;

                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&result)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::MlsCentral::merge_pending_group_from_external_commit]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn merge_pending_group_from_external_commit(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                if let Some(decrypted_messages) = context
                    .merge_pending_group_from_external_commit(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?
                {
                    let messages = decrypted_messages
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<WasmCryptoResult<Vec<BufferedDecryptedMessage>>>()?;

                    return WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&messages)?);
                }

                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::MlsCentral::clear_pending_group_from_external_commit]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn clear_pending_group_from_external_commit(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                context
                    .clear_pending_group_from_external_commit(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;

                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::MlsCentral::commit_accepted]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn commit_accepted(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                if let Some(decrypted_messages) = context
                    .commit_accepted(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?
                {
                    let messages = decrypted_messages
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<WasmCryptoResult<Vec<BufferedDecryptedMessage>>>()?;

                    return WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&messages)?);
                }

                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::MlsCentral::clear_pending_proposal]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn clear_pending_proposal(&self, conversation_id: ConversationId, proposal_ref: Box<[u8]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                context
                    .clear_pending_proposal(&conversation_id.to_vec(), proposal_ref.to_vec().into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::MlsCentral::clear_pending_commit]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn clear_pending_commit(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                context
                    .clear_pending_commit(&conversation_id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::MlsCentral::random_bytes]
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
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                central.reseed(Some(seed)).await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::try_new]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_init(&self) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    central.proteus_init().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_from_prekey]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_from_prekey(&self, session_id: String, prekey: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    central.proteus_session_from_prekey(&session_id, &prekey).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_from_message]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_from_message(&self, session_id: String, envelope: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let (_, payload) = central.proteus_session_from_message(&session_id, &envelope).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(payload.as_slice()).into())
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_save]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_save(&self, session_id: String) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    central.proteus_session_save(&session_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_delete]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_delete(&self, session_id: String) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    central.proteus_session_delete(&session_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<bool>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_exists]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_exists(&self, session_id: String) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let exists = central.proteus_session_exists(&session_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::from_bool(exists))
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::decrypt]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_decrypt(&self, session_id: String, ciphertext: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let cleartext = central.proteus_decrypt(&session_id, &ciphertext).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(cleartext.as_slice()).into())
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::encrypt]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_encrypt(&self, session_id: String, plaintext: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let encrypted = central.proteus_encrypt(&session_id, &plaintext).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(encrypted.as_slice()).into())
                } or throw WasmCryptoResult<_> }
            }.err_into()
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Map<string, Uint8Array>>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::encrypt_batched]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_encrypt_batched(&self, sessions: Box<[js_sys::JsString]>, plaintext: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let session_ids: Vec<String> = sessions.iter().map(String::from).collect();
                    let batch = central.proteus_encrypt_batched(session_ids.as_slice(), &plaintext).await.map_err(CoreCryptoError::from)?;
                    let js_obj = js_sys::Map::new();
                    for (key, payload) in batch.into_iter() {
                        js_obj.set(&js_sys::JsString::from(key).into(), &Uint8Array::from(payload.as_slice()));
                    }
                    WasmCryptoResult::Ok(js_obj.into())
                } or throw WasmCryptoResult<_> }
            }.err_into()
        )
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::new_prekey]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_new_prekey(&self, prekey_id: u16) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();

        let central = self.inner.clone();
        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let prekey_raw = central.proteus_new_prekey(prekey_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(prekey_raw.as_slice()).into())
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<ProteusAutoPrekeyBundle>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::new_prekey]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_new_prekey_auto(&self) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let (id, pkb) = central.proteus_new_prekey_auto().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(ProteusAutoPrekeyBundle { id, pkb }.into())
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::last_resort_prekey]
    pub fn proteus_last_resort_prekey(&self) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        future_to_promise(async move {
            proteus_impl! { errcode_dest => {
                let last_resort_pkbundle = central.proteus_last_resort_prekey().await.map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(last_resort_pkbundle.as_slice()).into())
            } or throw WasmCryptoResult<_> }
        }.err_into())
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
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        proteus_impl! { errcode_dest => {
            central.proteus_fingerprint().await.map_err(CoreCryptoError::from).map(Into::into)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_local]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> WasmCryptoResult<String> {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        proteus_impl! { errcode_dest => {
            central
                .proteus_fingerprint_local(&session_id)
                .await
                .map_err(CoreCryptoError::from)
                .map(Into::into)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> WasmCryptoResult<String> {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();

        proteus_impl! { errcode_dest => {
            central.proteus_fingerprint_remote(&session_id).await
                .map_err(CoreCryptoError::from).map(Into::into)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCproteus_fingerprint_prekeybundle]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_fingerprint_prekeybundle(prekey: Box<[u8]>) -> WasmCryptoResult<String> {
        proteus_impl!({
            core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey)
                .map_err(Into::into).map(Into::into)
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::cryptobox_migrate]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_cryptobox_migrate(&self, path: String) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    central.proteus_cryptobox_migrate(&path).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<u32>`]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_last_error_code(&self) -> Promise {
        let errcode = self.proteus_last_error_code.clone();
        future_to_promise(
            async move {
                proteus_impl! {{
                    let prev_value: u32 = *(errcode.read().await);
                    let mut errcode_val = errcode.write().await;
                    *errcode_val = 0;

                    WasmCryptoResult::Ok(prev_value.into())
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// see [core_crypto::mls::MlsCentral::export_secret_key]
    pub fn export_secret_key(&self, conversation_id: ConversationId, key_length: usize) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let key = central
                    .export_secret_key(&conversation_id.to_vec(), key_length)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(key.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// see [core_crypto::mls::MlsCentral::get_external_sender]
    pub fn get_external_sender(&self, id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let ext_sender = central
                    .get_external_sender(&id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(ext_sender.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Box<[js_sys::Uint8Array]>`]
    ///
    /// see [core_crypto::mls::MlsCentral::get_client_ids]
    pub fn get_client_ids(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let clients = central
                    .get_client_ids(&conversation_id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;
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
    /// Returns: [`WasmCryptoResult<E2eiEnrollment>`]
    ///
    /// see [core_crypto::mls::MlsCentral::e2ei_new_enrollment]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn e2ei_new_enrollment(
        &self,
        client_id: String,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let enrollment = context
                    .e2ei_new_enrollment(
                        client_id.into_bytes().into(),
                        display_name,
                        handle,
                        team,
                        expiry_sec,
                        ciphersuite.into(),
                    )
                    .await
                    .map(async_lock::RwLock::new)
                    .map(std::sync::Arc::new)
                    .map(E2eiEnrollment)
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;

                WasmCryptoResult::Ok(enrollment.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<E2eiEnrollment>`]
    ///
    /// see [core_crypto::mls::MlsCentral::e2ei_new_activation_enrollment]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn e2ei_new_activation_enrollment(
        &self,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let enrollment = context
                    .e2ei_new_activation_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
                    .await
                    .map(async_lock::RwLock::new)
                    .map(std::sync::Arc::new)
                    .map(E2eiEnrollment)
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(enrollment.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<E2eiEnrollment>`]
    ///
    /// see [core_crypto::mls::MlsCentral::e2ei_new_rotate_enrollment]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let enrollment = context
                    .e2ei_new_rotate_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
                    .await
                    .map(async_lock::RwLock::new)
                    .map(std::sync::Arc::new)
                    .map(E2eiEnrollment)
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(enrollment.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_dump_pki_env]
    pub async fn e2ei_dump_pki_env(&self) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let dump: Option<E2eiDumpedPkiEnv> = central.e2ei_dump_pki_env().await?.map(Into::into);
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&dump)?)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> Promise {
        let central = self.inner.clone();
        future_to_promise(async move { WasmCryptoResult::Ok(central.e2ei_is_pki_env_setup().await.into()) }.err_into())
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_register_acme_ca]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                context.e2ei_register_acme_ca(trust_anchor_pem).await?;
                context.finish().await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_register_intermediate_ca]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub async fn e2ei_register_intermediate_ca(&self, cert_pem: String) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let crls = context.e2ei_register_intermediate_ca_pem(cert_pem).await?;

                let crls = if let Some(crls) = &*crls {
                    js_sys::Array::from_iter(crls.iter().map(JsValue::from))
                } else {
                    js_sys::Array::new()
                };
                context.finish().await?;
                WasmCryptoResult::Ok(crls.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_register_crl]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub async fn e2ei_register_crl(&self, crl_dp: String, crl_der: Box<[u8]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let cc_registration = context.e2ei_register_crl(crl_dp, crl_der.to_vec()).await?;
                let registration: CrlRegistration = cc_registration.into();
                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&registration)?)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::MlsCentral::e2ei_mls_init_only]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn e2ei_mls_init_only(
        &self,
        enrollment: E2eiEnrollment,
        certificate_chain: String,
        nb_key_package: Option<u32>,
    ) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let nb_key_package = nb_key_package
                    .map(usize::try_from)
                    .transpose()
                    .map_err(CryptoError::from)?;

                let context = central.new_transaction().await;
                let crls = context
                    .e2ei_mls_init_only(
                        enrollment.0.write().await.deref_mut(),
                        certificate_chain,
                        nb_key_package,
                    )
                    .await?;

                let crls = if let Some(crls) = &*crls {
                    js_sys::Array::from_iter(crls.iter().map(JsValue::from))
                } else {
                    js_sys::Array::new()
                };
                context.finish().await?;
                WasmCryptoResult::Ok(crls.into())
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::MlsCentral::e2ei_rotate_all]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn e2ei_rotate_all(
        &self,
        enrollment: E2eiEnrollment,
        certificate_chain: String,
        new_key_packages_count: u32,
    ) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let rotate_bundle: RotateBundle = context
                    .e2ei_rotate_all(
                        enrollment.0.write().await.deref_mut(),
                        certificate_chain,
                        new_key_packages_count as usize,
                    )
                    .await?
                    .try_into()?;
                context.finish().await?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&rotate_bundle)?)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::MlsCentral::e2ei_enrollment_stash]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn e2ei_enrollment_stash(&self, enrollment: E2eiEnrollment) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let enrollment = std::sync::Arc::try_unwrap(enrollment.0)
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .into_inner();
                let context = central.new_transaction().await;
                let handle = context.e2ei_enrollment_stash(enrollment).await?;
                context.finish().await?;
                WasmCryptoResult::Ok(Uint8Array::from(handle.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::MlsCentral::e2ei_enrollment_stash_pop]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn e2ei_enrollment_stash_pop(&self, handle: Box<[u8]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let enrollment = context
                    .e2ei_enrollment_stash_pop(handle.to_vec())
                    .await
                    .map(async_lock::RwLock::new)
                    .map(std::sync::Arc::new)
                    .map(E2eiEnrollment)
                    .map_err(CoreCryptoError::from)?;
                context.finish().await?;
                WasmCryptoResult::Ok(enrollment.into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<u8>`]
    ///
    /// see [core_crypto::mls::MlsCentral::e2ei_conversation_state]
    #[deprecated = "Please create a transaction in Core Crypto and call this method from it."]
    pub fn e2ei_conversation_state(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let context = central.new_transaction().await;
                let state: E2eiConversationState = context
                    .e2ei_conversation_state(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?
                    .into();
                context.finish().await?;
                WasmCryptoResult::Ok((state as u8).into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<bool>`]
    ///
    /// see [core_crypto::mls::MlsCentral::e2ei_is_enabled]
    pub fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> Promise {
        let sc = MlsCiphersuite::from(ciphersuite).signature_algorithm();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let is_enabled = central.e2ei_is_enabled(sc).await.map_err(CoreCryptoError::from)?.into();
                WasmCryptoResult::Ok(is_enabled)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Vec<WireIdentity>>`]
    ///
    /// see [core_crypto::mls::MlsCentral::get_device_identities]
    pub fn get_device_identities(&self, conversation_id: ConversationId, device_ids: Box<[Uint8Array]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let device_ids = device_ids.iter().map(|c| c.to_vec().into()).collect::<Vec<ClientId>>();
                let identities = central
                    .get_device_identities(&conversation_id, &device_ids[..])
                    .await
                    .map_err(CoreCryptoError::from)?
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<WireIdentity>>();
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&identities)?)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<HashMap<String, Vec<WireIdentity>>>`]
    ///
    /// see [core_crypto::mls::MlsCentral::get_user_identities]
    pub fn get_user_identities(&self, conversation_id: ConversationId, user_ids: Box<[String]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let identities = central
                    .get_user_identities(&conversation_id, user_ids.deref())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .into_iter()
                    .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
                    .collect::<HashMap<String, Vec<WireIdentity>>>();
                let js_obj = js_sys::Map::new();
                for (uid, identities) in identities.into_iter() {
                    let uid = js_sys::JsString::from(uid).into();
                    let identities = serde_wasm_bindgen::to_value(&identities)?;
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
    /// see [core_crypto::mls::MlsCentral::get_credential_in_use]
    pub fn get_credential_in_use(&self, group_info: Box<[u8]>, credential_type: CredentialType) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_ref())
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                let state: E2eiConversationState = central
                    .get_credential_in_use(group_info, credential_type.into())
                    .await
                    .map(Into::into)
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok((state as u8).into())
            }
            .err_into(),
        )
    }
}

#[derive(Debug)]
#[wasm_bindgen(js_name = FfiWireE2EIdentity)]
#[repr(transparent)]
pub struct E2eiEnrollment(std::sync::Arc<async_lock::RwLock<core_crypto::prelude::E2eiEnrollment>>);

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
        Ok(Self {
            delegate: new_order.delegate,
            authorizations: new_order
                .authorizations
                .0
                .into_iter()
                .map(|a| String::from_utf8(a).map_err(CryptoError::from))
                .collect::<CryptoResult<Vec<String>>>()?,
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
