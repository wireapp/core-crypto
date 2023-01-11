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

use std::collections::HashMap;

use futures_util::future::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use core_crypto::prelude::*;
pub use core_crypto::CryptoError;

#[allow(dead_code)]
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

#[wasm_bindgen(inline_js = r#"
    export class CoreCryptoError extends Error {
        constructor(message, rustStackTrace, ...params) {
            super(...params);

            if (Error.captureStackTrace) {
                Error.captureStackTrace(this, CoreCryptoError);
            }

            this.name = "CoreCryptoError";
            this.rustStackTrace = rustStackTrace;
            this.proteusErrorCode = 0;
        }

        setProteusErrorCode(code) {
            this.proteusErrorCode = code;
        }

        proteusError() {
            return this.proteusErrorCode;
        }
    }
"#)]
extern "C" {
    pub type CoreCryptoError;

    #[wasm_bindgen(constructor)]
    pub fn new(message: String, rust_stack_trace: String) -> CoreCryptoError;

    #[wasm_bindgen(method)]
    pub fn set_proteus_error_code(this: &CoreCryptoError, code: u32);

    #[wasm_bindgen(method)]
    pub fn proteus_error(this: &CoreCryptoError) -> u32;
}

impl From<CryptoError> for CoreCryptoError {
    fn from(e: CryptoError) -> Self {
        // use std::error::Error as _;
        let js_err = CoreCryptoError::new(e.to_string(), std::backtrace::Backtrace::capture().to_string());
        js_err.set_proteus_error_code(e.proteus_error_code());

        js_err
    }
}

impl From<E2eIdentityError> for CoreCryptoError {
    fn from(e: E2eIdentityError) -> Self {
        let js_err = CoreCryptoError::new(e.to_string(), std::backtrace::Backtrace::capture().to_string());
        js_err
    }
}

impl From<serde_wasm_bindgen::Error> for CoreCryptoError {
    fn from(e: serde_wasm_bindgen::Error) -> Self {
        let e_js: wasm_bindgen::JsValue = e.into();
        e_js.into()
    }
}

pub type WasmCryptoResult<T> = Result<T, CoreCryptoError>;

#[allow(non_camel_case_types)]
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
/// see [core_crypto::prelude::CiphersuiteName]
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

pub type FfiClientId = Box<[u8]>;

#[wasm_bindgen]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::MlsConversationCreationMessage]
pub struct MemberAddedMessages {
    welcome: Vec<u8>,
    commit: Vec<u8>,
    public_group_state: PublicGroupStateBundle,
}

#[wasm_bindgen]
impl MemberAddedMessages {
    #[wasm_bindgen(constructor)]
    pub fn new(welcome: Uint8Array, commit: Uint8Array, public_group_state: PublicGroupStateBundle) -> Self {
        Self {
            welcome: welcome.to_vec(),
            commit: commit.to_vec(),
            public_group_state,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Uint8Array {
        Uint8Array::from(&*self.welcome)
    }

    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        Uint8Array::from(&*self.commit)
    }

    #[wasm_bindgen(getter)]
    pub fn public_group_state(&self) -> PublicGroupStateBundle {
        self.public_group_state.clone()
    }
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, commit, pgs) = msg
            .to_bytes_triple()
            .map_err(CryptoError::from)
            .map_err(Self::Error::from)?;

        Ok(Self {
            welcome,
            commit,
            public_group_state: pgs.into(),
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitBundle {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    public_group_state: PublicGroupStateBundle,
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
    pub fn public_group_state(&self) -> PublicGroupStateBundle {
        self.public_group_state.clone()
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
            public_group_state: pgs.into(),
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicGroupStateBundle {
    encryption_type: u8,
    ratchet_tree_type: u8,
    payload: Vec<u8>,
}

#[wasm_bindgen]
impl PublicGroupStateBundle {
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

impl From<MlsPublicGroupStateBundle> for PublicGroupStateBundle {
    fn from(pgs: MlsPublicGroupStateBundle) -> Self {
        Self {
            encryption_type: pgs.encryption_type as u8,
            ratchet_tree_type: pgs.ratchet_tree_type as u8,
            payload: pgs.payload.bytes(),
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProposalBundle {
    proposal: Vec<u8>,
    proposal_ref: Vec<u8>,
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
}

impl TryFrom<MlsProposalBundle> for ProposalBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsProposalBundle) -> Result<Self, Self::Error> {
        let (proposal, proposal_ref) = msg
            .to_bytes_pair()
            .map_err(CryptoError::from)
            .map_err(Self::Error::from)?;

        Ok(Self { proposal, proposal_ref })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConversationInitBundle {
    conversation_id: ConversationId,
    commit: Vec<u8>,
    public_group_state: PublicGroupStateBundle,
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
    pub fn public_group_state(&self) -> PublicGroupStateBundle {
        self.public_group_state.clone()
    }
}

impl TryFrom<MlsConversationInitBundle> for ConversationInitBundle {
    type Error = CoreCryptoError;

    fn try_from(mut from: MlsConversationInitBundle) -> Result<Self, Self::Error> {
        let conversation_id = std::mem::take(&mut from.conversation_id);
        let (commit, pgs) = from
            .to_bytes_pair()
            .map_err(CryptoError::from)
            .map_err(Self::Error::from)?;

        Ok(Self {
            conversation_id,
            commit,
            public_group_state: pgs.into(),
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::decrypt::MlsConversationDecryptMessage]
pub struct DecryptedMessage {
    message: Option<Vec<u8>>,
    proposals: Vec<ProposalBundle>,
    is_active: bool,
    commit_delay: Option<u32>,
    sender_client_id: Option<Vec<u8>>,
    has_epoch_changed: bool,
}

impl TryFrom<MlsConversationDecryptMessage> for DecryptedMessage {
    type Error = CoreCryptoError;

    fn try_from(from: MlsConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(ProposalBundle::try_from)
            .collect::<WasmCryptoResult<Vec<ProposalBundle>>>()?;

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
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::ConversationMember]
pub struct Invitee {
    id: Vec<u8>,
    kp: Vec<u8>,
}

#[wasm_bindgen]
impl Invitee {
    #[wasm_bindgen(constructor)]
    pub fn new(id: Uint8Array, kp: Uint8Array) -> Self {
        Self {
            id: id.to_vec(),
            kp: kp.to_vec(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Uint8Array {
        Uint8Array::from(&*self.id)
    }

    #[wasm_bindgen(getter)]
    pub fn kp(&self) -> Uint8Array {
        Uint8Array::from(&*self.kp)
    }
}

impl Invitee {
    #[inline(always)]
    fn group_to_conversation_member(clients: Vec<Self>) -> WasmCryptoResult<Vec<ConversationMember>> {
        Ok(clients
            .into_iter()
            .try_fold(
                HashMap::new(),
                |mut acc, c| -> WasmCryptoResult<HashMap<ClientId, ConversationMember>> {
                    let client_id: ClientId = c.id.into();
                    if let Some(member) = acc.get_mut(&client_id) {
                        member.add_keypackage(c.kp.to_vec()).map_err(CoreCryptoError::from)?;
                    } else {
                        acc.insert(
                            client_id.clone(),
                            ConversationMember::new_raw(client_id, c.kp.to_vec()).map_err(CoreCryptoError::from)?,
                        );
                    }
                    Ok(acc)
                },
            )?
            .into_values()
            .collect::<Vec<ConversationMember>>())
    }
}

impl TryInto<ConversationMember> for Invitee {
    type Error = CoreCryptoError;

    fn try_into(self) -> Result<ConversationMember, Self::Error> {
        Ok(ConversationMember::new_raw(self.id.into(), self.kp.to_vec())?)
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
    ) -> Self {
        let external_senders = external_senders
            .map(|exs| exs.iter().cloned().map(|jsv| jsv.to_vec()).collect())
            .unwrap_or_default();
        Self {
            ciphersuite,
            external_senders,
            custom: CustomConfiguration::new(key_rotation_span, wire_policy),
        }
    }
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = CoreCryptoError;
    fn try_into(mut self) -> WasmCryptoResult<MlsConversationConfiguration> {
        let mut cfg = MlsConversationConfiguration {
            custom: self.custom.into(),
            ..Default::default()
        };

        cfg.set_raw_external_senders(self.external_senders);

        if let Some(ciphersuite) = self.ciphersuite.take() {
            let mls_ciphersuite: CiphersuiteName = ciphersuite.into();
            cfg.ciphersuite = mls_ciphersuite.into();
        }

        Ok(cfg)
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
#[derive(Debug, Clone)]
/// see [core_crypto::prelude::CoreCryptoCallbacks]
pub struct CoreCryptoWasmCallbacks {
    authorize: std::sync::Arc<std::sync::Mutex<js_sys::Function>>,
    user_authorize: std::sync::Arc<std::sync::Mutex<js_sys::Function>>,
    client_is_existing_group_user: std::sync::Arc<std::sync::Mutex<js_sys::Function>>,
}

#[wasm_bindgen]
impl CoreCryptoWasmCallbacks {
    #[wasm_bindgen(constructor)]
    pub fn new(
        authorize: js_sys::Function,
        user_authorize: js_sys::Function,
        client_is_existing_group_user: js_sys::Function,
    ) -> Self {
        Self {
            authorize: std::sync::Arc::new(authorize.into()),
            user_authorize: std::sync::Arc::new(user_authorize.into()),
            client_is_existing_group_user: std::sync::Arc::new(client_is_existing_group_user.into()),
        }
    }
}

// SAFETY: All callback instances are wrapped into Arc<Mutex> so this is safe to mark
unsafe impl Send for CoreCryptoWasmCallbacks {}
unsafe impl Sync for CoreCryptoWasmCallbacks {}

impl CoreCryptoCallbacks for CoreCryptoWasmCallbacks {
    fn authorize(&self, conversation_id: ConversationId, client_id: ClientId) -> bool {
        if let Ok(authorize) = self.authorize.try_lock() {
            let this = JsValue::null();
            if let Ok(Some(result)) = authorize
                .call2(
                    &this,
                    &js_sys::Uint8Array::from(conversation_id.as_slice()),
                    &js_sys::Uint8Array::from(client_id.as_slice()),
                )
                .map(|jsval| jsval.as_bool())
            {
                result
            } else {
                false
            }
        } else {
            false
        }
    }

    fn user_authorize(
        &self,
        conversation_id: ConversationId,
        external_client_id: ClientId,
        existing_clients: Vec<ClientId>,
    ) -> bool {
        if let Ok(user_authorize) = self.user_authorize.try_lock() {
            let this = JsValue::null();
            if let Ok(Some(result)) = user_authorize
                .call3(
                    &this,
                    &js_sys::Uint8Array::from(conversation_id.as_slice()),
                    &js_sys::Uint8Array::from(external_client_id.as_slice()),
                    &existing_clients
                        .into_iter()
                        .map(|client| js_sys::Uint8Array::from(client.as_slice()))
                        .collect::<js_sys::Array>(),
                )
                .map(|jsval| jsval.as_bool())
            {
                result
            } else {
                false
            }
        } else {
            false
        }
    }

    fn client_is_existing_group_user(&self, client_id: ClientId, existing_clients: Vec<ClientId>) -> bool {
        if let Ok(client_is_existing_group_user) = self.client_is_existing_group_user.try_lock() {
            let this = JsValue::null();
            if let Ok(Some(result)) = client_is_existing_group_user
                .call2(
                    &this,
                    &js_sys::Uint8Array::from(client_id.as_slice()),
                    &existing_clients
                        .into_iter()
                        .map(|client| js_sys::Uint8Array::from(client.as_slice()))
                        .collect::<js_sys::Array>(),
                )
                .map(|jsval| jsval.as_bool())
            {
                result
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[derive(Debug)]
#[wasm_bindgen]
#[repr(transparent)]
pub struct CoreCrypto(std::sync::Arc<async_lock::RwLock<core_crypto::CoreCrypto>>);

#[wasm_bindgen]
impl CoreCrypto {
    /// see [core_crypto::MlsCentral::try_new]
    pub async fn _internal_new(
        path: String,
        key: String,
        client_id: FfiClientId,
        entropy_seed: Option<Box<[u8]>>,
    ) -> WasmCryptoResult<CoreCrypto> {
        let ciphersuites = vec![MlsCiphersuite::default()];
        let mut configuration = MlsCentralConfiguration::try_new(path, key, Some(client_id.into()), ciphersuites)
            .map_err(CoreCryptoError::from)?;

        if let Some(seed) = entropy_seed {
            let owned_seed = EntropySeed::try_from_slice(&seed[..EntropySeed::EXPECTED_LEN])
                .map_err(CryptoError::from)
                .map_err(CoreCryptoError::from)?;
            configuration.set_entropy(owned_seed);
        }

        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let certificate_bundle = None;
        let central = MlsCentral::try_new(configuration, certificate_bundle)
            .await
            .map_err(CoreCryptoError::from)?;
        Ok(CoreCrypto(async_lock::RwLock::new(central.into()).into()))
    }

    /// see [core_crypto::MlsCentral::try_new]
    pub async fn deferred_init(
        path: String,
        key: String,
        entropy_seed: Option<Box<[u8]>>,
    ) -> WasmCryptoResult<CoreCrypto> {
        let ciphersuites = vec![MlsCiphersuite::default()];
        let mut configuration =
            MlsCentralConfiguration::try_new(path, key, None, ciphersuites).map_err(CoreCryptoError::from)?;

        if let Some(seed) = entropy_seed {
            let owned_seed = EntropySeed::try_from_slice(&seed[..EntropySeed::EXPECTED_LEN])
                .map_err(CryptoError::from)
                .map_err(CoreCryptoError::from)?;
            configuration.set_entropy(owned_seed);
        }

        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let certificate_bundle = None;
        let central = MlsCentral::try_new(configuration, certificate_bundle)
            .await
            .map_err(CoreCryptoError::from)?;
        Ok(CoreCrypto(async_lock::RwLock::new(central.into()).into()))
    }

    /// see [core_crypto::MlsCentral::mls_init]
    pub async fn mls_init(&self, client_id: FfiClientId) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let ciphersuites = vec![MlsCiphersuite::default()];
                // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
                let certificate_bundle = None;
                let mut central = this.write().await;
                central
                    .mls_init(client_id.into(), ciphersuites, certificate_bundle)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::close]
    pub fn close(self) -> Promise {
        if let Ok(cc) = std::sync::Arc::try_unwrap(self.0).map(async_lock::RwLock::into_inner) {
            future_to_promise(
                async move {
                    cc.take().close().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                }
                .err_into(),
            )
        } else {
            js_sys::Promise::reject(
                &js_sys::JsString::from("There are other outstanding references to this CoreCrypto instance").into(),
            )
        }
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::wipe]
    pub fn wipe(self) -> Promise {
        if let Ok(cc) = std::sync::Arc::try_unwrap(self.0).map(async_lock::RwLock::into_inner) {
            future_to_promise(
                async move {
                    cc.take().wipe().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                }
                .err_into(),
            )
        } else {
            js_sys::Promise::reject(
                &js_sys::JsString::from("There are other outstanding references to this CoreCrypto instance").into(),
            )
        }
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::callbacks]
    pub fn set_callbacks(&self, callbacks: CoreCryptoWasmCallbacks) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.write().await.callbacks(Box::new(callbacks));

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns:: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::client_public_key]
    pub fn client_public_key(&self) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let cc = this.read().await;
                let pk = cc.client_public_key().map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(pk.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Array<js_sys::Uint8Array>>`]
    ///
    /// see [core_crypto::MlsCentral::client_keypackages]
    pub fn client_keypackages(&self, amount_requested: u32) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                use core_crypto::prelude::tls_codec::Serialize as _;
                let kps = this
                    .write()
                    .await
                    .client_keypackages(amount_requested as usize)
                    .await?
                    .into_iter()
                    .map(|kpb| {
                        kpb.key_package()
                            .tls_serialize_detached()
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

                WasmCryptoResult::Ok(js_kps.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<usize>`]
    ///
    /// see [core_crypto::MlsCentral::client_valid_keypackages_count]
    pub fn client_valid_keypackages_count(&self) -> Promise {
        let this = self.0.clone();

        future_to_promise(
            async move {
                let count = this
                    .read()
                    .await
                    .client_valid_keypackages_count()
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(count.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::new_conversation]
    pub fn create_conversation(&self, conversation_id: Box<[u8]>, config: ConversationConfiguration) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.write()
                    .await
                    .new_conversation(conversation_id.to_vec(), config.try_into()?)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<u64>`]
    ///
    /// see [core_crypto::MlsCentral::conversation_epoch]
    pub fn conversation_epoch(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(
                    this.read()
                        .await
                        .conversation_epoch(&conversation_id.into())
                        .map_err(CoreCryptoError::from)?
                        .into(),
                )
            }
            .err_into(),
        )
    }

    /// Returns: [`bool`]
    ///
    /// see [core_crypto::MlsCentral::conversation_exists]
    pub fn conversation_exists(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(if this.read().await.conversation_exists(&conversation_id.into()) {
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
    /// see [core_crypto::MlsCentral::process_raw_welcome_message]
    pub fn process_welcome_message(
        &self,
        welcome_message: Box<[u8]>,
        custom_configuration: CustomConfiguration,
    ) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let conversation_id = this
                    .write()
                    .await
                    .process_raw_welcome_message(welcome_message.into(), custom_configuration.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(conversation_id.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Option<MemberAddedMessages>>`]
    ///
    /// see [core_crypto::MlsCentral::add_members_to_conversation]
    pub fn add_clients_to_conversation(&self, conversation_id: Box<[u8]>, clients: Box<[JsValue]>) -> Promise {
        let this = self.0.clone();

        future_to_promise(
            async move {
                let invitees = clients
                    .iter()
                    .cloned()
                    .map(|js_client| Ok(serde_wasm_bindgen::from_value(js_client)?))
                    .collect::<WasmCryptoResult<Vec<Invitee>>>()?;

                let mut members = Invitee::group_to_conversation_member(invitees)?;
                let mut central = this.write().await;
                let conversation_id = conversation_id.into();
                let commit = central
                    .add_members_to_conversation(&conversation_id, &mut members)
                    .await?;
                let commit: MemberAddedMessages = commit.try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Option<js_sys::Uint8Array>>`]
    ///
    /// see [core_crypto::MlsCentral::remove_members_from_conversation]
    pub fn remove_clients_from_conversation(
        &self,
        conversation_id: Box<[u8]>,
        clients: Box<[js_sys::Uint8Array]>,
    ) -> Promise {
        let this = self.0.clone();

        future_to_promise(
            async move {
                let clients = clients
                    .iter()
                    .cloned()
                    .map(|c| c.to_vec().into())
                    .collect::<Vec<ClientId>>();

                let conversation_id = conversation_id.into();
                let mut central = this.write().await;
                let commit = central
                    .remove_members_from_conversation(&conversation_id, &clients)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let commit: CommitBundle = commit.try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<CommitBundle>`]
    ///
    /// see [core_crypto::MlsCentral::update_keying_material]
    pub fn update_keying_material(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();

        future_to_promise(
            async move {
                let mut central = this.write().await;
                let conversation_id = conversation_id.into();
                let commit = central
                    .update_keying_material(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let commit: CommitBundle = commit.try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::MlsCentral::commit_pending_proposals]
    pub fn commit_pending_proposals(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();

        future_to_promise(
            async move {
                let mut central = this.write().await;
                let conversation_id = conversation_id.into();
                let commit: Option<CommitBundle> = central
                    .commit_pending_proposals(&conversation_id)
                    .await?
                    .map(|c| c.try_into())
                    .transpose()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::wipe_conversation]
    pub fn wipe_conversation(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let conversation_id = conversation_id.into();
                let mut central = this.write().await;
                central
                    .wipe_conversation(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<DecryptedMessage>`]
    ///
    /// see [core_crypto::MlsCentral::decrypt_message]
    pub fn decrypt_message(&self, conversation_id: Box<[u8]>, payload: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let raw_decrypted_message = this
                    .write()
                    .await
                    .decrypt_message(&conversation_id.to_vec(), payload)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let decrypted_message = DecryptedMessage::try_from(raw_decrypted_message)?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&decrypted_message)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::encrypt_message]
    pub fn encrypt_message(&self, conversation_id: Box<[u8]>, message: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let ciphertext = this
                    .write()
                    .await
                    .encrypt_message(&conversation_id.to_vec(), message)
                    .await
                    .map(|ciphertext| Uint8Array::from(ciphertext.as_slice()))
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(ciphertext.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::new_proposal]
    pub fn new_add_proposal(&self, conversation_id: Box<[u8]>, keypackage: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let kp = KeyPackage::try_from(&keypackage[..])
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                let proposal: ProposalBundle = this
                    .write()
                    .await
                    .new_proposal(&conversation_id.to_vec(), MlsProposal::Add(kp))
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::new_proposal]
    pub fn new_update_proposal(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let proposal: ProposalBundle = this
                    .write()
                    .await
                    .new_proposal(&conversation_id.to_vec(), MlsProposal::Update)
                    .await?
                    .try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::new_proposal]
    pub fn new_remove_proposal(&self, conversation_id: Box<[u8]>, client_id: FfiClientId) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let proposal: ProposalBundle = this
                    .write()
                    .await
                    .new_proposal(&conversation_id.to_vec(), MlsProposal::Remove(client_id.into()))
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::new_external_add_proposal]
    pub fn new_external_add_proposal(&self, conversation_id: Box<[u8]>, epoch: u32) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let proposal_bytes = this
                    .write()
                    .await
                    .new_external_add_proposal(conversation_id.to_vec(), u64::from(epoch).into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .to_bytes()
                    .map(|bytes| Uint8Array::from(bytes.as_slice()))
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(proposal_bytes.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::new_external_remove_proposal]
    pub fn new_external_remove_proposal(
        &self,
        conversation_id: Box<[u8]>,
        epoch: u32,
        keypackage_ref: Box<[u8]>,
    ) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let kpr: Box<[u8; 16]> = keypackage_ref
                    .try_into()
                    .map_err(|_| CryptoError::InvalidByteArrayError(16))
                    .map_err(CoreCryptoError::from)?;
                let kpr = KeyPackageRef::from(*kpr);
                let proposal_bytes = this
                    .write()
                    .await
                    .new_external_remove_proposal(conversation_id.to_vec(), u64::from(epoch).into(), kpr)
                    .await
                    .map_err(CoreCryptoError::from)?
                    .to_bytes()
                    .map(|bytes| Uint8Array::from(bytes.as_slice()))
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(proposal_bytes.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::export_public_group_state]
    pub fn export_group_state(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let state = this
                    .read()
                    .await
                    .export_public_group_state(&conversation_id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(state.as_slice()).into())
            }
            .err_into(),
        )
    }

    #[allow(clippy::boxed_local)]
    /// Returns: [`WasmCryptoResult<ConversationInitBundle>`]
    ///
    /// see [core_crypto::MlsCentral::join_by_external_commit]
    pub fn join_by_external_commit(
        &self,
        public_group_state: Box<[u8]>,
        custom_configuration: CustomConfiguration,
    ) -> Promise {
        use core_crypto::prelude::tls_codec::Deserialize as _;

        let this = self.0.clone();
        let state = public_group_state.to_vec();

        future_to_promise(
            async move {
                let group_state = VerifiablePublicGroupState::tls_deserialize(&mut &state[..])
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                let result: ConversationInitBundle = this
                    .read()
                    .await
                    .join_by_external_commit(group_state, custom_configuration.into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&result)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::merge_pending_group_from_external_commit]
    pub fn merge_pending_group_from_external_commit(&self, conversation_id: ConversationId) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.write()
                    .await
                    .merge_pending_group_from_external_commit(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::clear_pending_group_from_external_commit]
    pub fn clear_pending_group_from_external_commit(&self, conversation_id: ConversationId) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.write()
                    .await
                    .clear_pending_group_from_external_commit(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::MlsCentral::commit_accepted]
    pub fn commit_accepted(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.write()
                    .await
                    .commit_accepted(&conversation_id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::MlsCentral::clear_pending_proposal]
    pub fn clear_pending_proposal(&self, conversation_id: Box<[u8]>, proposal_ref: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.write()
                    .await
                    .clear_pending_proposal(&conversation_id.to_vec(), proposal_ref.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::MlsCentral::clear_pending_commit]
    pub fn clear_pending_commit(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.write()
                    .await
                    .clear_pending_commit(&conversation_id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::MlsCentral::random_bytes]
    pub fn random_bytes(&self, len: usize) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let bytes = this.read().await.random_bytes(len).map_err(CoreCryptoError::from)?;
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
        let this = self.0.clone();
        future_to_promise(
            async move {
                let seed = EntropySeed::try_from_slice(&seed)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                this.write().await.provider_mut().reseed(Some(seed));
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
        let this = self.0.clone();
        future_to_promise(
            async move {
                proteus_impl!({
                    this.write().await.proteus_init().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_>)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_from_prekey]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_from_prekey(&self, session_id: String, prekey: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                proteus_impl!({
                    this.write().await.proteus_session_from_prekey(&session_id, &prekey).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_>)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_from_message]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_from_message(&self, session_id: String, envelope: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                proteus_impl!({
                    let (_, payload) = this.write().await.proteus_session_from_message(&session_id, &envelope).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(payload.as_slice()).into())
                } or throw WasmCryptoResult<_>)
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
        let this = self.0.clone();
        future_to_promise(
            async move {
                proteus_impl!({
                    this.write().await.proteus_session_save(&session_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_>)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_delete]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_delete(&self, session_id: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                proteus_impl!({
                    this.write().await.proteus_session_delete(&session_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_>)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<bool>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_exists]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_exists(&self, session_id: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                proteus_impl!({
                    let exists = this.write().await.proteus_session_exists(&session_id).map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::from_bool(exists))
                } or throw WasmCryptoResult<_>)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::decrypt]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_decrypt(&self, session_id: String, ciphertext: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                proteus_impl!({
                    let cleartext = this.write().await.proteus_decrypt(&session_id, &ciphertext).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(cleartext.as_slice()).into())
                } or throw WasmCryptoResult<_>)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::encrypt]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_encrypt(&self, session_id: String, plaintext: Box<[u8]>) -> WasmCryptoResult<Uint8Array> {
        proteus_impl!({
            let encrypted = self.0.write().await.proteus_encrypt(&session_id, &plaintext).await.map_err(CoreCryptoError::from)?;
            WasmCryptoResult::Ok(Uint8Array::from(encrypted.as_slice()))
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<js_sys::Map<string, Uint8Array>>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::encrypt_batched]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_encrypt_batched(
        &self,
        sessions: Box<[js_sys::JsString]>,
        plaintext: Box<[u8]>,
    ) -> WasmCryptoResult<js_sys::Map> {
        proteus_impl!({
            let session_ids: Vec<String> = sessions.iter().map(String::from).collect();
            let batch = self.0.write().await.proteus_encrypt_batched(session_ids.as_slice(), &plaintext).await.map_err(CoreCryptoError::from)?;
            let js_obj = js_sys::Map::new();
            for (key, payload) in batch.into_iter() {
                js_obj.set(&js_sys::JsString::from(key).into(), &Uint8Array::from(payload.as_slice()));
            }
            WasmCryptoResult::Ok(js_obj)
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::new_prekey]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> WasmCryptoResult<Uint8Array> {
        proteus_impl!({
            let prekey_raw = self.0.read().await.proteus_new_prekey(prekey_id).await.map_err(CoreCryptoError::from)?;
            WasmCryptoResult::Ok(Uint8Array::from(prekey_raw.as_slice()))
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::new_prekey]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_new_prekey_auto(&self) -> WasmCryptoResult<Uint8Array> {
        proteus_impl!({
            let prekey_raw = self.0.read().await.proteus_new_prekey_auto().await.map_err(CoreCryptoError::from)?;
            WasmCryptoResult::Ok(Uint8Array::from(prekey_raw.as_slice()))
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint(&self) -> WasmCryptoResult<String> {
        proteus_impl!({
            self.0.read().await.proteus_fingerprint().map_err(Into::into).map(Into::into)
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_local]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> WasmCryptoResult<String> {
        proteus_impl!({
            self.0.read().await.proteus_fingerprint_local(&session_id)
                .map_err(Into::into).map(Into::into)
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> WasmCryptoResult<String> {
        proteus_impl!({
            self.0.read().await.proteus_fingerprint_remote(&session_id)
                .map_err(Into::into).map(Into::into)
        } or throw WasmCryptoResult<_>)
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
        let this = self.0.clone();
        future_to_promise(
            async move {
                proteus_impl!({
                    this.read().await.proteus_cryptobox_migrate(&path).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_>)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// see [core_crypto::MlsCentral::export_secret_key]
    pub fn export_secret_key(&self, conversation_id: Box<[u8]>, key_length: usize) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let key = this
                    .read()
                    .await
                    .export_secret_key(&conversation_id.to_vec(), key_length)
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(key.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Box<[js_sys::Uint8Array]>`]
    ///
    /// see [core_crypto::MlsCentral::get_client_ids]
    pub fn get_client_ids(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let clients = this
                    .read()
                    .await
                    .get_client_ids(&conversation_id.to_vec())
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

    /// see [core_crypto::MlsCentral::new_acme_enrollment]
    pub async fn new_acme_enrollment(&self, ciphersuite: Ciphersuite) -> WasmCryptoResult<WireE2eIdentity> {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let enrollment = self
            .0
            .read()
            .await
            .new_acme_enrollment(ciphersuite.into())
            .map(WireE2eIdentity)
            .map_err(|_| CryptoError::ImplementationError)
            .map_err(CoreCryptoError::from)?;

        WasmCryptoResult::Ok(enrollment)
    }
}

#[wasm_bindgen]
/// Returns the current version of CoreCrypto
pub fn version() -> String {
    crate::VERSION.into()
}

#[derive(Debug)]
#[wasm_bindgen]
#[repr(transparent)]
pub struct WireE2eIdentity(core_crypto::prelude::WireE2eIdentity);

#[wasm_bindgen]
impl WireE2eIdentity {
    /// See [core_crypto::e2e_identity::WireE2eIdentity::directory_response]
    pub fn directory_response(&self, directory: Vec<u8>) -> WasmCryptoResult<JsValue> {
        let directory: AcmeDirectory = self
            .0
            .directory_response(directory)
            .map_err(CoreCryptoError::from)?
            .into();
        WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&directory)?)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_account_request]
    pub fn new_account_request(&self, directory: JsValue, previous_nonce: String) -> WasmCryptoResult<Uint8Array> {
        let directory = serde_wasm_bindgen::from_value::<AcmeDirectory>(directory)?;
        let new_account = self.0.new_account_request(directory.into(), previous_nonce)?;
        WasmCryptoResult::Ok(new_account.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_account_response]
    pub fn new_account_response(&self, account: Uint8Array) -> WasmCryptoResult<Uint8Array> {
        let account: Vec<u8> = self.0.new_account_response(account.to_vec())?.into();
        WasmCryptoResult::Ok(account.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_order_request]
    pub fn new_order_request(
        &self,
        handle: String,
        client_id: String,
        expiry_days: u32,
        directory: JsValue,
        account: Uint8Array,
        previous_nonce: String,
    ) -> WasmCryptoResult<Uint8Array> {
        let directory = serde_wasm_bindgen::from_value::<AcmeDirectory>(directory)?;
        let new_order = self.0.new_order_request(
            handle,
            client_id,
            expiry_days,
            directory.into(),
            account.to_vec().into(),
            previous_nonce,
        )?;
        WasmCryptoResult::Ok(new_order.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_order_response]
    pub fn new_order_response(&self, order: Uint8Array) -> WasmCryptoResult<JsValue> {
        let order: NewAcmeOrder = self.0.new_order_response(order.to_vec())?.into();
        WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&order)?)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_authz_request]
    pub fn new_authz_request(
        &self,
        url: String,
        account: Uint8Array,
        previous_nonce: String,
    ) -> WasmCryptoResult<Uint8Array> {
        let new_authz = self.0.new_authz_request(url, account.to_vec().into(), previous_nonce)?;
        WasmCryptoResult::Ok(new_authz.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_authz_response]
    pub fn new_authz_response(&self, authz: Uint8Array) -> WasmCryptoResult<JsValue> {
        let authz: NewAcmeAuthz = self.0.new_authz_response(authz.to_vec())?.into();
        WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&authz)?)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::create_dpop_token]
    pub fn create_dpop_token(
        &self,
        access_token_url: String,
        user_id: String,
        client_id: u64,
        domain: String,
        client_id_challenge: JsValue,
        backend_nonce: String,
        expiry_days: u32,
    ) -> WasmCryptoResult<String> {
        let client_id_challenge = serde_wasm_bindgen::from_value::<AcmeChallenge>(client_id_challenge)?;
        let dpop_token = self.0.create_dpop_token(
            access_token_url,
            user_id,
            client_id,
            domain,
            client_id_challenge.into(),
            backend_nonce,
            expiry_days,
        )?;
        WasmCryptoResult::Ok(dpop_token)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_challenge_request]
    pub fn new_challenge_request(
        &self,
        handle_challenge: JsValue,
        account: Uint8Array,
        previous_nonce: String,
    ) -> WasmCryptoResult<Uint8Array> {
        let handle_chall = serde_wasm_bindgen::from_value::<AcmeChallenge>(handle_challenge)?;
        let chall = self
            .0
            .new_challenge_request(handle_chall.into(), account.to_vec().into(), previous_nonce)?;
        WasmCryptoResult::Ok(chall.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_challenge_response]
    pub fn new_challenge_response(&self, challenge: Uint8Array) -> WasmCryptoResult<()> {
        self.0.new_challenge_response(challenge.to_vec())?;
        WasmCryptoResult::Ok(())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::check_order_request]
    pub fn check_order_request(
        &self,
        order_url: String,
        account: Uint8Array,
        previous_nonce: String,
    ) -> WasmCryptoResult<Uint8Array> {
        let new_order = self
            .0
            .check_order_request(order_url, account.to_vec().into(), previous_nonce)?;
        WasmCryptoResult::Ok(new_order.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::check_order_response]
    pub fn check_order_response(&self, order: Uint8Array) -> WasmCryptoResult<Uint8Array> {
        let order: Vec<u8> = self.0.check_order_response(order.to_vec())?.into();
        WasmCryptoResult::Ok(order.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::finalize_request]
    pub fn finalize_request(
        &self,
        domains: Vec<Uint8Array>,
        order: Uint8Array,
        account: Uint8Array,
        previous_nonce: String,
    ) -> WasmCryptoResult<Uint8Array> {
        let domains = domains
            .into_iter()
            .try_fold(vec![], |mut acc, a| -> WasmCryptoResult<Vec<String>> {
                acc.push(String::from_utf8(a.to_vec()).map_err(CryptoError::from)?);
                Ok(acc)
            })?;
        let finalize =
            self.0
                .finalize_request(domains, order.to_vec().into(), account.to_vec().into(), previous_nonce)?;
        WasmCryptoResult::Ok(finalize.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::finalize_response]
    pub fn finalize_response(&self, finalize: Uint8Array) -> WasmCryptoResult<JsValue> {
        let finalize: AcmeFinalize = self.0.finalize_response(finalize.to_vec())?.into();
        WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&finalize)?)
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::certificate_request]
    pub fn certificate_request(
        &self,
        finalize: JsValue,
        account: Uint8Array,
        previous_nonce: String,
    ) -> WasmCryptoResult<Uint8Array> {
        let finalize = serde_wasm_bindgen::from_value::<AcmeFinalize>(finalize)?;
        let certificate_req = self
            .0
            .certificate_request(finalize.into(), account.to_vec().into(), previous_nonce)?;
        WasmCryptoResult::Ok(certificate_req.as_slice().into())
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::certificate_response]
    pub fn certificate_response(&self, certificate_chain: String) -> WasmCryptoResult<Vec<Uint8Array>> {
        let certificate_chain = self.0.certificate_response(certificate_chain)?;
        let certificate_chain = certificate_chain
            .into_iter()
            .map(|c| Uint8Array::from(c.as_bytes()))
            .collect();
        WasmCryptoResult::Ok(certificate_chain)
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// See [core_crypto::e2e_identity::types::E2eiAcmeDirectory]
pub struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[wasm_bindgen]
impl AcmeDirectory {
    #[wasm_bindgen(constructor)]
    pub fn new(new_nonce: String, new_account: String, new_order: String) -> Self {
        Self {
            new_nonce,
            new_account,
            new_order,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn new_nonce(&self) -> String {
        self.new_nonce.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn new_account(&self) -> String {
        self.new_account.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn new_order(&self) -> String {
        self.new_order.to_string()
    }
}

impl From<core_crypto::prelude::E2eiAcmeDirectory> for AcmeDirectory {
    fn from(directory: core_crypto::prelude::E2eiAcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
        }
    }
}

impl From<AcmeDirectory> for core_crypto::prelude::E2eiAcmeDirectory {
    fn from(directory: AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeOrder]
pub struct NewAcmeOrder {
    delegate: Vec<u8>,
    authorizations: Vec<Vec<u8>>,
}

#[wasm_bindgen]
impl NewAcmeOrder {
    #[wasm_bindgen(constructor)]
    pub fn new(delegate: Uint8Array, authorizations: Vec<Uint8Array>) -> Self {
        Self {
            delegate: delegate.to_vec(),
            authorizations: authorizations.iter().map(Uint8Array::to_vec).collect(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn delegate(&self) -> Uint8Array {
        self.delegate.as_slice().into()
    }

    #[wasm_bindgen(getter)]
    pub fn authorizations(&self) -> js_sys::Array {
        self.authorizations
            .iter()
            .map(|a| Uint8Array::from(a.as_slice()))
            .collect::<js_sys::Array>()
    }
}

impl From<core_crypto::prelude::E2eiNewAcmeOrder> for NewAcmeOrder {
    fn from(new_order: core_crypto::prelude::E2eiNewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations.into_iter().map(String::into_bytes).collect(),
        }
    }
}

impl TryFrom<NewAcmeOrder> for core_crypto::prelude::E2eiNewAcmeOrder {
    type Error = CoreCryptoError;

    fn try_from(new_order: NewAcmeOrder) -> WasmCryptoResult<Self> {
        Ok(Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations.into_iter().try_fold(
                vec![],
                |mut acc, a| -> WasmCryptoResult<Vec<String>> {
                    acc.push(String::from_utf8(a).map_err(CryptoError::from)?);
                    Ok(acc)
                },
            )?,
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeAuthz]
pub struct NewAcmeAuthz {
    identifier: String,
    wire_http_challenge: Option<AcmeChallenge>,
    wire_oidc_challenge: Option<AcmeChallenge>,
}

#[wasm_bindgen]
impl NewAcmeAuthz {
    #[wasm_bindgen(constructor)]
    pub fn new(
        identifier: String,
        wire_http_challenge: Option<AcmeChallenge>,
        wire_oidc_challenge: Option<AcmeChallenge>,
    ) -> Self {
        Self {
            identifier,
            wire_http_challenge,
            wire_oidc_challenge,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> String {
        self.identifier.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wire_http_challenge(&self) -> Option<AcmeChallenge> {
        self.wire_http_challenge.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wire_oidc_challenge(&self) -> Option<AcmeChallenge> {
        self.wire_oidc_challenge.clone()
    }
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: authz.identifier,
            wire_http_challenge: authz.wire_http_challenge.map(Into::into),
            wire_oidc_challenge: authz.wire_oidc_challenge.map(Into::into),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: authz.identifier,
            wire_http_challenge: authz.wire_http_challenge.map(Into::into),
            wire_oidc_challenge: authz.wire_oidc_challenge.map(Into::into),
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// See [core_crypto::e2e_identity::types::E2eiAcmeChallenge]
pub struct AcmeChallenge {
    delegate: Vec<u8>,
    url: String,
}

#[wasm_bindgen]
impl AcmeChallenge {
    #[wasm_bindgen(constructor)]
    pub fn new(delegate: Uint8Array, url: String) -> Self {
        Self {
            delegate: delegate.to_vec(),
            url,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn delegate(&self) -> Uint8Array {
        self.delegate.as_slice().into()
    }

    #[wasm_bindgen(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }
}

impl From<core_crypto::prelude::E2eiAcmeChallenge> for AcmeChallenge {
    fn from(chall: core_crypto::prelude::E2eiAcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
        }
    }
}

impl From<AcmeChallenge> for core_crypto::prelude::E2eiAcmeChallenge {
    fn from(chall: AcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// See [core_crypto::e2e_identity::types::E2eiAcmeFinalize]
pub struct AcmeFinalize {
    delegate: Vec<u8>,
    certificate_url: String,
}

#[wasm_bindgen]
impl AcmeFinalize {
    #[wasm_bindgen(constructor)]
    pub fn new(delegate: Uint8Array, certificate_url: String) -> Self {
        Self {
            delegate: delegate.to_vec(),
            certificate_url,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn delegate(&self) -> Uint8Array {
        self.delegate.as_slice().into()
    }

    #[wasm_bindgen(getter)]
    pub fn certificate_url(&self) -> String {
        self.certificate_url.clone()
    }
}

impl From<core_crypto::prelude::E2eiAcmeFinalize> for AcmeFinalize {
    fn from(finalize: core_crypto::prelude::E2eiAcmeFinalize) -> Self {
        Self {
            delegate: finalize.delegate,
            certificate_url: finalize.certificate_url,
        }
    }
}

impl From<AcmeFinalize> for core_crypto::prelude::E2eiAcmeFinalize {
    fn from(finalize: AcmeFinalize) -> Self {
        Self {
            delegate: finalize.delegate,
            certificate_url: finalize.certificate_url,
        }
    }
}
