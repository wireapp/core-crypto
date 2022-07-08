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

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[allow(dead_code)]
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

use futures_util::future::TryFutureExt;
use js_sys::{Array, Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use std::collections::HashMap;

use core_crypto::prelude::*;
pub use core_crypto::CryptoError;

pub type WasmCryptoError = JsError;
pub type WasmCryptoResult<T> = Result<T, WasmCryptoError>;

#[allow(non_camel_case_types)]
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
pub struct MemberAddedMessages {
    welcome: Box<[u8]>,
    message: Box<[u8]>,
}

#[wasm_bindgen]
impl MemberAddedMessages {
    #[wasm_bindgen(constructor)]
    pub fn new(welcome: Box<[u8]>, message: Box<[u8]>) -> Self {
        Self { welcome, message }
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Box<[u8]> {
        self.welcome.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Box<[u8]> {
        self.message.clone()
    }
}

impl TryFrom<MlsConversationCreationMessage> for MemberAddedMessages {
    type Error = WasmCryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, message) = msg.to_bytes_pairs()?;
        Ok(Self {
            welcome: welcome.into(),
            message: message.into(),
        })
    }
}

#[wasm_bindgen]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConversationLeaveMessages {
    self_removal_proposal: Box<[u8]>,
    other_clients_removal_commit: Option<Box<[u8]>>,
}

#[wasm_bindgen]
impl ConversationLeaveMessages {
    #[wasm_bindgen(constructor)]
    pub fn new(self_removal_proposal: Box<[u8]>, other_clients_removal_commit: Option<Box<[u8]>>) -> Self {
        Self {
            self_removal_proposal,
            other_clients_removal_commit,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn self_removal_proposal(&self) -> Box<[u8]> {
        self.self_removal_proposal.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn other_clients_removal_commit(&self) -> Option<Box<[u8]>> {
        self.other_clients_removal_commit.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitBundle {
    message: Box<[u8]>,
    welcome: Option<Box<[u8]>>,
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MlsConversationInitMessage {
    group: Box<[u8]>,
    message: Box<[u8]>,
}

#[wasm_bindgen]
impl CommitBundle {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Box<[u8]> {
        self.message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Option<Box<[u8]>> {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
impl MlsConversationInitMessage {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Box<[u8]> {
        self.message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn group(&self) -> Box<[u8]> {
        self.group.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Invitee {
    id: Box<[u8]>,
    kp: Box<[u8]>,
}

#[wasm_bindgen]
impl Invitee {
    #[wasm_bindgen(constructor)]
    pub fn new(id: Box<[u8]>, kp: Box<[u8]>) -> Self {
        Self { id, kp }
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Box<[u8]> {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn kp(&self) -> Box<[u8]> {
        self.kp.clone()
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
pub struct ConversationConfiguration {
    // pub admins: Box<[Box<[u8]>]>,
    ciphersuite: Option<Ciphersuite>,
    key_rotation_span: Option<u32>,
    #[serde(default, skip_serializing, skip_deserializing)]
    external_senders: js_sys::Array,
}

#[wasm_bindgen]
impl ConversationConfiguration {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ciphersuite: Option<Ciphersuite>,
        key_rotation_span: Option<u32>,
        external_senders: js_sys::Array,
    ) -> Self {
        Self {
            ciphersuite,
            key_rotation_span,
            external_senders,
        }
    }
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = WasmCryptoError;
    fn try_into(mut self) -> WasmCryptoResult<MlsConversationConfiguration> {
        use tls_codec::Deserialize as _;
        let external_senders = self
            .external_senders
            .iter()
            .map(|s: JsValue| {
                Ok(Credential::tls_deserialize(&mut &Uint8Array::new(&s).to_vec()[..]).map_err(MlsError::from)?)
            })
            .filter_map(|r: CryptoResult<Credential>| r.ok())
            .collect();
        let key_rotation_span = self
            .key_rotation_span
            .map(|span| std::time::Duration::from_secs(span as u64));
        let mut cfg = MlsConversationConfiguration {
            // admins: self.admins.to_vec().into_iter().map(Into::into).collect(),
            key_rotation_span,
            external_senders,
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
pub struct CoreCryptoWasmCallbacks {
    authorize: std::sync::Arc<std::sync::Mutex<js_sys::Function>>,
}

#[wasm_bindgen]
impl CoreCryptoWasmCallbacks {
    #[wasm_bindgen(constructor)]
    pub fn new(authorize: js_sys::Function) -> Self {
        Self {
            authorize: std::sync::Arc::new(authorize.into()),
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
}

#[derive(Debug)]
#[wasm_bindgen]
#[repr(transparent)]
pub struct CoreCrypto(std::rc::Rc<std::cell::RefCell<MlsCentral>>);

#[wasm_bindgen]
impl CoreCrypto {
    pub async fn _internal_new(path: String, key: String, client_id: String) -> WasmCryptoResult<CoreCrypto> {
        let configuration = MlsCentralConfiguration::try_new(path, key, client_id)?;

        // TODO: not exposing certificate bundle ATM. Pending e2e identity solution to be defined
        let central = MlsCentral::try_new(configuration, None).await?;
        Ok(CoreCrypto(std::cell::RefCell::new(central).into()))
    }

    /// Returns: WasmCryptoResult<()>
    pub fn close(self) -> Promise {
        if let Ok(cc) = std::rc::Rc::try_unwrap(self.0).map(std::cell::RefCell::into_inner) {
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

    /// Returns: WasmCryptoResult<()>
    pub fn wipe(self) -> Promise {
        if let Ok(cc) = std::rc::Rc::try_unwrap(self.0).map(std::cell::RefCell::into_inner) {
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

    pub fn set_callbacks(&mut self, callbacks: CoreCryptoWasmCallbacks) -> WasmCryptoResult<()> {
        Ok(self.0.borrow_mut().callbacks(Box::new(callbacks))?)
    }

    pub fn client_public_key(&self) -> WasmCryptoResult<Box<[u8]>> {
        Ok(self.0.borrow().client_public_key().map(Into::into)?)
    }

    /// Returns: WasmCryptoResult<js_sys::Array<js_sys::Uint8Array>>>
    pub fn client_keypackages(&self, amount_requested: u32) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                use core_crypto::prelude::tls_codec::Serialize as _;
                let kps = this
                    .borrow_mut()
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

    /// Returns: WasmCryptoResult<CommitBundle>
    pub fn update_keying_material(&mut self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();

        future_to_promise(
            async move {
                use core_crypto::prelude::tls_codec::Serialize as _;

                let result = this
                    .borrow_mut()
                    .update_keying_material(conversation_id.to_vec())
                    .await?;
                let message = result
                    .0
                    .tls_serialize_detached()
                    .map_err(MlsError::from)?
                    .into_boxed_slice();
                let welcome = result
                    .1
                    .map(|v| v.tls_serialize_detached().map(|v| v.into_boxed_slice()))
                    .transpose()
                    .map_err(MlsError::from)?;

                let wrapper = CommitBundle { message, welcome };

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&wrapper)?)
            }
            .err_into(),
        )
    }

    /// Returns: WasmCryptoResult<()>
    pub fn create_conversation(
        &self,
        conversation_id: Box<[u8]>,
        mut config: ConversationConfiguration,
        external_senders: Array,
    ) -> Promise {
        let this = self.0.clone();
        if external_senders.is_null() || external_senders.is_undefined() {
            config.external_senders = external_senders;
        }
        future_to_promise(
            async move {
                this.borrow_mut()
                    .new_conversation(conversation_id.to_vec(), config.try_into()?)
                    .await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    pub fn conversation_exists(&self, conversation_id: Box<[u8]>) -> bool {
        self.0.borrow().conversation_exists(&conversation_id.into())
    }

    /// Returns: WasmCryptoResult<Uint8Array>
    pub fn process_welcome_message(&self, welcome_message: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let conversation_id = this
                    .borrow_mut()
                    .process_raw_welcome_message(welcome_message.into())
                    .await?;
                WasmCryptoResult::Ok(Uint8Array::from(conversation_id.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns WasmCryptoResult<Option<MemberAddedMessages>>
    pub fn add_clients_to_conversation(&self, conversation_id: Box<[u8]>, clients: Box<[JsValue]>) -> Promise {
        let this = self.0.clone();

        future_to_promise(
            async move {
                let invitees = clients
                    .into_iter()
                    .cloned()
                    .map(|js_client| Ok(serde_wasm_bindgen::from_value(js_client)?))
                    .collect::<WasmCryptoResult<Vec<Invitee>>>()?;

                let mut members = Invitee::group_to_conversation_member(invitees)?;
                let mut messages_raw = this
                    .borrow_mut()
                    .add_members_to_conversation(&conversation_id.into(), &mut members)
                    .await?;

                if let Some(messages_raw) = messages_raw.take() {
                    let messages: MemberAddedMessages = messages_raw.try_into()?;
                    WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&messages)?)
                } else {
                    WasmCryptoResult::Ok(JsValue::NULL)
                }
            }
            .err_into(),
        )
    }

    /// Returns a MLS commit message serialized as TLS
    /// Returns: WasmCryptoResult<Option<Uint8Array>>
    pub fn remove_clients_from_conversation(
        &self,
        conversation_id: Box<[u8]>,
        clients: Box<[js_sys::Uint8Array]>,
    ) -> Promise {
        let this = self.0.clone();

        future_to_promise(
            async move {
                let clients = clients
                    .into_iter()
                    .cloned()
                    .map(|c| c.to_vec().into())
                    .collect::<Vec<ClientId>>();

                let message = this
                    .borrow_mut()
                    .remove_members_from_conversation(&conversation_id.into(), &clients)
                    .await?
                    .map(|m| m.to_bytes().map_err(MlsError::from).map_err(CryptoError::from))
                    .transpose()?
                    .map(|m_bytes| Uint8Array::from(m_bytes.as_slice()));

                WasmCryptoResult::Ok(message.map(Into::into).unwrap_or(JsValue::NULL))
            }
            .err_into(),
        )
    }

    /// Returns: WasmCryptoResult<ConversationLeaveMessages>
    pub fn leave_conversation(&self, conversation_id: Box<[u8]>, other_clients: Box<[js_sys::Uint8Array]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let other_clients = other_clients
                    .into_iter()
                    .cloned()
                    .map(|c| c.to_vec().into())
                    .collect::<Vec<ClientId>>();

                let messages = this
                    .borrow_mut()
                    .leave_conversation(conversation_id.to_vec(), &other_clients)
                    .await?;

                let ret = ConversationLeaveMessages {
                    other_clients_removal_commit: messages
                        .other_clients_removal_commit
                        .and_then(|c| c.to_bytes().map(Into::into).ok()),
                    self_removal_proposal: messages
                        .self_removal_proposal
                        .to_bytes()
                        .map(Into::into)
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)?,
                };

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&ret)?)
            }
            .err_into(),
        )
    }

    /// Returns: WasmCryptoResult<Option<Uint8Array>>
    pub fn decrypt_message(&self, conversation_id: Box<[u8]>, payload: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let maybe_cleartext = this
                    .borrow_mut()
                    .decrypt_message(conversation_id.to_vec(), payload)
                    .await?
                    .map(|cleartext| Uint8Array::from(cleartext.as_slice()));

                WasmCryptoResult::Ok(maybe_cleartext.map(Into::into).unwrap_or(JsValue::NULL))
            }
            .err_into(),
        )
    }

    /// Returns: WasmCryptoResult<Uint8Array>
    pub fn encrypt_message(&self, conversation_id: Box<[u8]>, message: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let ciphertext = this
                    .borrow_mut()
                    .encrypt_message(conversation_id.to_vec(), message)
                    .await
                    .map(|cleartext| Uint8Array::from(cleartext.as_slice()))?;

                WasmCryptoResult::Ok(ciphertext.into())
            }
            .err_into(),
        )
    }

    /// Returns: WasmCryptoResult<Uint8Array>
    pub fn new_add_proposal(&self, conversation_id: Box<[u8]>, keypackage: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let kp = KeyPackage::try_from(&keypackage[..])
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)?;
                let proposal_bytes = this
                    .borrow_mut()
                    .new_proposal(conversation_id.to_vec(), MlsProposal::Add(kp))
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

    /// Returns: WasmCryptoResult<Uint8Array>
    pub fn new_update_proposal(&self, conversation_id: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let proposal_bytes = this
                    .borrow_mut()
                    .new_proposal(conversation_id.to_vec(), MlsProposal::Update)
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

    /// Returns: WasmCryptoResult<Uint8Array>
    pub fn new_remove_proposal(&self, conversation_id: Box<[u8]>, client_id: FfiClientId) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let proposal_bytes = this
                    .borrow_mut()
                    .new_proposal(conversation_id.to_vec(), MlsProposal::Remove(client_id.into()))
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

    /// Returns: WasmCryptoResult<Uint8Array>
    pub fn new_external_add_proposal(&self, conversation_id: Box<[u8]>, epoch: u32, keypackage: Box<[u8]>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let kp = KeyPackage::try_from(&keypackage[..])
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)?;
                let proposal_bytes = this
                    .borrow_mut()
                    .new_external_add_proposal(conversation_id.to_vec(), u64::from(epoch).into(), kp)
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

    /// Returns: WasmCryptoResult<Uint8Array>
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
                    .borrow_mut()
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

    pub fn export_group_state(&self, conversation_id: Box<[u8]>) -> Promise {
        use core_crypto::prelude::tls_codec::Serialize as _;
        let this = self.0.clone();
        future_to_promise(
            async move {
                let state = this.borrow().export_group_state(&conversation_id).await?;
                WasmCryptoResult::Ok(
                    state
                        .tls_serialize_detached()
                        .map(|bytes| Uint8Array::from(bytes.as_slice()))
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)?
                        .into(),
                )
            }
            .err_into(),
        )
    }

    pub fn join_by_external_commit(&self, group_state: Box<[u8]>) -> Promise {
        use core_crypto::prelude::tls_codec::Deserialize as _;
        use core_crypto::prelude::tls_codec::Serialize as _;

        let this = self.0.clone();
        let state = group_state.to_vec();

        future_to_promise(
            async move {
                let group_state =
                    VerifiablePublicGroupState::tls_deserialize(&mut &state[..]).map_err(MlsError::from)?;
                let (group, message) = this.borrow().join_by_external_commit(group_state).await?;
                let result = MlsConversationInitMessage {
                    message: message
                        .tls_serialize_detached()
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)?
                        .into_boxed_slice(),
                    group: group
                        .tls_serialize_detached()
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)?
                        .into_boxed_slice(),
                };
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&result)?)
            }
            .err_into(),
        )
    }

    pub fn merge_pending_group_from_external_commit(
        &self,
        conversation_id: ConversationId,
        configuration: ConversationConfiguration,
    ) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                this.borrow_mut()
                    .merge_pending_group_from_external_commit(&conversation_id, configuration.try_into()?)
                    .await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }
}

// TODO: write export group state with the ratchet tree in the extensions. check if the existing
// method already sets the tree if not make it so in our API
#[wasm_bindgen]
pub fn version() -> String {
    crate::VERSION.into()
}
