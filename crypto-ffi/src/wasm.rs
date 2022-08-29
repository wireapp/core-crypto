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

use core_crypto::prelude::decrypt::MlsConversationDecryptMessage;
use core_crypto::prelude::handshake::MlsCommitBundle;
use core_crypto::prelude::*;
pub use core_crypto::CryptoError;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[allow(dead_code)]
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type WasmCryptoError = JsError;
pub type WasmCryptoResult<T> = Result<T, WasmCryptoError>;

#[allow(non_camel_case_types)]
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    public_group_state: Vec<u8>,
}

#[wasm_bindgen]
impl MemberAddedMessages {
    #[wasm_bindgen(constructor)]
    pub fn new(welcome: Uint8Array, commit: Uint8Array, public_group_state: Uint8Array) -> Self {
        Self {
            welcome: welcome.to_vec(),
            commit: commit.to_vec(),
            public_group_state: public_group_state.to_vec(),
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
    pub fn public_group_state(&self) -> Uint8Array {
        Uint8Array::from(&*self.public_group_state)
    }
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = WasmCryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, commit, public_group_state) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            public_group_state,
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitBundle {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    public_group_state: Vec<u8>,
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
    pub fn public_group_state(&self) -> Uint8Array {
        Uint8Array::from(&*self.public_group_state)
    }
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = WasmCryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let (welcome, commit, public_group_state) = msg.to_bytes_triple()?;
        Ok(Self {
            welcome,
            commit,
            public_group_state,
        })
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
    type Error = WasmCryptoError;

    fn try_from(msg: MlsProposalBundle) -> Result<Self, Self::Error> {
        let (proposal, proposal_ref) = msg.to_bytes_pair()?;
        Ok(Self { proposal, proposal_ref })
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MlsConversationInitMessage {
    group: Vec<u8>,
    commit: Vec<u8>,
}

#[wasm_bindgen]
impl MlsConversationInitMessage {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        Uint8Array::from(&*self.commit)
    }

    #[wasm_bindgen(getter)]
    pub fn group(&self) -> Uint8Array {
        Uint8Array::from(&*self.group)
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
    sender_client_id: Option<FfiClientId>,
}

impl TryFrom<MlsConversationDecryptMessage> for DecryptedMessage {
    type Error = WasmCryptoError;

    fn try_from(from: MlsConversationDecryptMessage) -> Result<Self, Self::Error> {
        let proposals = from
            .proposals
            .into_iter()
            .map(ProposalBundle::try_from)
            .collect::<WasmCryptoResult<Vec<ProposalBundle>>>()?;

        let commit_delay = if let Some(delay) = from.delay {
            Some(delay.try_into()?)
        } else {
            None
        };

        Ok(Self {
            message: from.app_msg,
            proposals,
            is_active: from.is_active,
            commit_delay,
            sender_client_id: from.sender_client_id.map(ClientId::into),
        })
    }
}

#[wasm_bindgen]
impl DecryptedMessage {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Option<Uint8Array> {
        self.message.clone().map(|m| Uint8Array::from(m.as_slice()))
    }

    #[wasm_bindgen(getter)]
    pub fn proposals(&self) -> js_sys::Array {
        self.proposals
            .iter()
            .map(|p| JsValue::from(p.clone()))
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
                        member.add_keypackage(c.kp.to_vec())?;
                    } else {
                        acc.insert(
                            client_id.clone(),
                            ConversationMember::new_raw(client_id, c.kp.to_vec())?,
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
    type Error = WasmCryptoError;

    fn try_into(self) -> Result<ConversationMember, Self::Error> {
        Ok(ConversationMember::new_raw(self.id.into(), self.kp.to_vec())?)
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// see [core_crypto::prelude::MlsConversationConfiguration]
pub struct ConversationConfiguration {
    admins: Vec<Vec<u8>>,
    ciphersuite: Option<Ciphersuite>,
    key_rotation_span: Option<u32>,
    external_senders: Vec<Vec<u8>>,
}

#[wasm_bindgen]
impl ConversationConfiguration {
    #[wasm_bindgen(constructor)]
    pub fn new(
        admins: Option<Vec<Uint8Array>>,
        ciphersuite: Option<Ciphersuite>,
        key_rotation_span: Option<u32>,
        external_senders: Option<Vec<Uint8Array>>,
    ) -> Self {
        let admins = admins
            .map(|a| {
                a.to_vec()
                    .into_iter()
                    .map(|jsv| Uint8Array::from(jsv).to_vec())
                    .collect()
            })
            .unwrap_or_default();
        let external_senders = external_senders
            .map(|exs| {
                exs.to_vec()
                    .into_iter()
                    .map(|jsv| Uint8Array::from(jsv).to_vec())
                    .collect()
            })
            .unwrap_or_default();

        Self {
            admins,
            ciphersuite,
            key_rotation_span,
            external_senders,
        }
    }
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = WasmCryptoError;
    fn try_into(mut self) -> WasmCryptoResult<MlsConversationConfiguration> {
        let key_rotation_span = self
            .key_rotation_span
            .map(|span| std::time::Duration::from_secs(span as u64));

        let mut cfg = MlsConversationConfiguration {
            admins: self.admins,
            key_rotation_span,
            external_senders: self.external_senders,
            ..Default::default()
        };

        if let Some(ciphersuite) = self.ciphersuite.take() {
            let mls_ciphersuite: CiphersuiteName = ciphersuite.into();
            cfg.ciphersuite = mls_ciphersuite.into();
        }

        Ok(cfg)
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
/// see [core_crypto::prelude::CoreCryptoCallbacks]
pub struct CoreCryptoWasmCallbacks {
    authorize: std::sync::Arc<std::sync::Mutex<js_sys::Function>>,
    is_user_in_group: std::sync::Arc<std::sync::Mutex<js_sys::Function>>,
}

#[wasm_bindgen]
impl CoreCryptoWasmCallbacks {
    #[wasm_bindgen(constructor)]
    pub fn new(authorize: js_sys::Function, is_user_in_group: js_sys::Function) -> Self {
        Self {
            authorize: std::sync::Arc::new(authorize.into()),
            is_user_in_group: std::sync::Arc::new(is_user_in_group.into()),
        }
    }
}

unsafe impl Send for CoreCryptoWasmCallbacks {}
unsafe impl Sync for CoreCryptoWasmCallbacks {}

impl CoreCryptoCallbacks for CoreCryptoWasmCallbacks {
    fn authorize(&self, conversation_id: ConversationId, client_id: String) -> bool {
        if let Ok(authorize) = self.authorize.try_lock() {
            let this = JsValue::null();
            if let Ok(Some(result)) = authorize
                .call2(
                    &this,
                    &js_sys::Uint8Array::from(conversation_id.as_slice()),
                    &JsValue::from_str(&client_id),
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

    fn is_user_in_group(&self, identity: Vec<u8>, other_clients: Vec<Vec<u8>>) -> bool {
        if let Ok(is_user_in_group) = self.is_user_in_group.try_lock() {
            let this = JsValue::null();
            if let Ok(Some(result)) = is_user_in_group
                .call2(
                    &this,
                    &js_sys::Uint8Array::from(identity.as_slice()),
                    &other_clients
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
pub struct CoreCrypto(std::sync::Arc<async_lock::RwLock<MlsCentral>>);

#[wasm_bindgen]
impl CoreCrypto {
    /// see [core_crypto::MlsCentral::try_new]
    pub async fn _internal_new(
        path: String,
        key: String,
        client_id: String,
        entropy_seed: Option<Box<[u8]>>,
    ) -> WasmCryptoResult<CoreCrypto> {
        let mut configuration = MlsCentralConfiguration::try_new(path, key, client_id)?;

        if let Some(seed) = entropy_seed {
            let owned_seed = EntropySeed::try_from_slice(&seed[..EntropySeed::EXPECTED_LEN])?;
            configuration.set_entropy(owned_seed);
        }

        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let central = MlsCentral::try_new(configuration, None).await?;
        Ok(CoreCrypto(async_lock::RwLock::new(central).into()))
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::close]
    pub fn close(self) -> Promise {
        if let Ok(cc) = std::sync::Arc::try_unwrap(self.0).map(async_lock::RwLock::into_inner) {
            future_to_promise(
                async move {
                    cc.close().await?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                }
                .err_into(),
            )
        } else {
            panic!("There are other outstanding references to this CoreCrypto instance")
        }
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::wipe]
    pub fn wipe(self) -> Promise {
        if let Ok(cc) = std::sync::Arc::try_unwrap(self.0).map(async_lock::RwLock::into_inner) {
            future_to_promise(
                async move {
                    cc.wipe().await?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                }
                .err_into(),
            )
        } else {
            panic!("There are other outstanding references to this CoreCrypto instance")
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
                let pk = cc.client_public_key();
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
                    .collect::<CryptoResult<Vec<Vec<u8>>>>()?;

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
                let count = this.read().await.client_valid_keypackages_count().await?;
                WasmCryptoResult::Ok(count.into())
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
                let commit_bundle = central.update_keying_material(&conversation_id).await?;
                let commit_bundle: CommitBundle = commit_bundle.try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit_bundle)?)
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
                    .await?;
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
            async move { WasmCryptoResult::Ok(this.read().await.conversation_epoch(&conversation_id.into())?.into()) }
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
    pub fn process_welcome_message(&self, welcome_message: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let conversation_id = this
                    .write()
                    .await
                    .process_raw_welcome_message(welcome_message.into())
                    .await?;
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
                let messages_raw = central
                    .add_members_to_conversation(&conversation_id, &mut members)
                    .await?;
                let messages: MemberAddedMessages = messages_raw.try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&messages)?)
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
                let commit_bundle = central
                    .remove_members_from_conversation(&conversation_id, &clients)
                    .await?;
                let commit_bundle: CommitBundle = commit_bundle.try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit_bundle)?)
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
                central.wipe_conversation(&conversation_id).await?;
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
                    .await?;

                let decrypted_message: DecryptedMessage = raw_decrypted_message.try_into()?;

                WasmCryptoResult::Ok(decrypted_message.into())
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
                    .map(|ciphertext| Uint8Array::from(ciphertext.as_slice()))?;

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
                    .map_err(CryptoError::from)?;
                let proposal: ProposalBundle = this
                    .write()
                    .await
                    .new_proposal(&conversation_id.to_vec(), MlsProposal::Add(kp))
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
                    .await?
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
                    .await?
                    .to_bytes()
                    .map(|bytes| Uint8Array::from(bytes.as_slice()))
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)?;

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
                    .map_err(|_| CryptoError::InvalidByteArrayError(16))?;
                let kpr = KeyPackageRef::from(*kpr);
                let proposal_bytes = this
                    .write()
                    .await
                    .new_external_remove_proposal(conversation_id.to_vec(), u64::from(epoch).into(), kpr)
                    .await?
                    .to_bytes()
                    .map(|bytes| Uint8Array::from(bytes.as_slice()))
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)?;

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
                    .await?;
                WasmCryptoResult::Ok(Uint8Array::from(state.as_slice()).into())
            }
            .err_into(),
        )
    }

    #[allow(clippy::boxed_local)]
    /// Returns: [`WasmCryptoResult<MlsConversationInitMessage>`]
    ///
    /// see [core_crypto::MlsCentral::join_by_external_commit]
    pub fn join_by_external_commit(&self, group_state: Box<[u8]>) -> Promise {
        use core_crypto::prelude::tls_codec::Deserialize as _;
        use core_crypto::prelude::tls_codec::Serialize as _;

        let this = self.0.clone();
        let state = group_state.to_vec();

        future_to_promise(
            async move {
                let group_state =
                    VerifiablePublicGroupState::tls_deserialize(&mut &state[..]).map_err(MlsError::from)?;
                let (group, commit) = this.read().await.join_by_external_commit(group_state).await?;
                let result = MlsConversationInitMessage {
                    commit: commit
                        .tls_serialize_detached()
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)?,
                    group: group
                        .tls_serialize_detached()
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)?,
                };
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&result)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::MlsCentral::merge_pending_group_from_external_commit]
    pub fn merge_pending_group_from_external_commit(
        &self,
        conversation_id: ConversationId,
        configuration: ConversationConfiguration,
    ) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.write()
                    .await
                    .merge_pending_group_from_external_commit(&conversation_id, configuration.try_into()?)
                    .await?;
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
                this.write().await.commit_accepted(&conversation_id.to_vec()).await?;

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
                    .await?;

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
                    .await?;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
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
                let commit_bundle = central.commit_pending_proposals(&conversation_id).await?;
                let commit_bundle: CommitBundle = commit_bundle.try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit_bundle)?)
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
                let bytes = this.read().await.random_bytes(len)?;
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
                let seed = EntropySeed::try_from_slice(&seed)?;
                this.write().await.provider_mut().reseed(Some(seed));
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    crate::VERSION.into()
}
