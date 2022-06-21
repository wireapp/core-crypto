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

use wasm_bindgen::prelude::*;

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
pub struct SelfUpdateResponse {
    message_out: Box<[u8]>,
    welcome: Option<Box<[u8]>>,
}

#[wasm_bindgen]
impl SelfUpdateResponse {
    #[wasm_bindgen(getter)]
    pub fn message_out(&self) -> Box<[u8]> {
        self.message_out.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Option<Box<[u8]>> {
        self.welcome.clone()
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
}

#[wasm_bindgen]
impl ConversationConfiguration {
    #[wasm_bindgen(constructor)]
    pub fn new(ciphersuite: Option<Ciphersuite>, key_rotation_span: Option<u32>) -> Self {
        Self {
            ciphersuite,
            key_rotation_span,
        }
    }
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = WasmCryptoError;
    fn try_into(mut self) -> WasmCryptoResult<MlsConversationConfiguration> {
        let mut cfg = MlsConversationConfiguration {
            // admins: self.admins.to_vec().into_iter().map(Into::into).collect(),
            key_rotation_span: self
                .key_rotation_span
                .map(|span| std::time::Duration::from_secs(span as u64)),
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
pub struct CoreCrypto(MlsCentral);

#[allow(dead_code, unused_variables)]
#[wasm_bindgen]
impl CoreCrypto {
    #[wasm_bindgen(constructor)]
    pub fn new(path: &str, key: &str, client_id: &str) -> WasmCryptoResult<CoreCrypto> {
        let configuration = MlsCentralConfiguration::try_new(path.into(), key.into(), client_id.into())?;

        let central = MlsCentral::try_new(configuration)?;
        Ok(CoreCrypto(central))
    }

    pub fn wipe(self) {
        self.0.wipe()
    }

    pub fn set_callbacks(&mut self, callbacks: CoreCryptoWasmCallbacks) -> WasmCryptoResult<()> {
        Ok(self.0.callbacks(Box::new(callbacks))?)
    }

    pub fn client_public_key(&self) -> WasmCryptoResult<Box<[u8]>> {
        Ok(self.0.client_public_key().map(Into::into)?)
    }

    pub fn client_keypackages(&self, amount_requested: u32) -> WasmCryptoResult<Box<[js_sys::Uint8Array]>> {
        use core_crypto::prelude::tls_codec::Serialize as _;
        let kps = self
            .0
            .client_keypackages(amount_requested as usize)?
            .into_iter()
            .map(|kpb| {
                kpb.key_package()
                    .tls_serialize_detached()
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map(Into::into)
            })
            .collect::<CryptoResult<Vec<Vec<u8>>>>()?;

        Ok(kps
            .into_iter()
            .map(|kp| js_sys::Uint8Array::from(kp.as_slice()))
            .collect())
    }

    pub fn self_update(
        &mut self,
        conversation_id: ConversationId,
        key_package: Option<Box<[u8]>>,
    ) -> WasmCryptoResult<SelfUpdateResponse> {
        use core_crypto::prelude::tls_codec::Serialize as _;
        let kp = key_package
            .map(|v| KeyPackage::try_from(v.as_ref()))
            .transpose()
            .map_err(MlsError::from)?;
        let result = self.0.self_update(conversation_id, kp)?;
        let message_out = result
            .0
            .tls_serialize_detached()
            .map_err(MlsError::from)?
            .into_boxed_slice();
        let welcome = result
            .1
            .map(|v| v.tls_serialize_detached().map(|v| v.into_boxed_slice()))
            .transpose()
            .map_err(MlsError::from)?;
        Ok(SelfUpdateResponse { message_out, welcome })
    }

    pub fn create_conversation(
        &mut self,
        conversation_id: Box<[u8]>,
        config: ConversationConfiguration,
    ) -> WasmCryptoResult<()> {
        Ok(self.0.new_conversation(conversation_id.to_vec(), config.try_into()?)?)
    }

    pub fn process_welcome_message(&mut self, welcome_message: Box<[u8]>) -> WasmCryptoResult<Box<[u8]>> {
        Ok(self
            .0
            .process_raw_welcome_message(welcome_message.into())
            .map(Into::into)?)
    }

    pub fn add_clients_to_conversation(
        &mut self,
        conversation_id: Box<[u8]>,
        clients: Box<[JsValue]>,
    ) -> WasmCryptoResult<Option<MemberAddedMessages>> {
        let invitees = clients
            .into_iter()
            .cloned()
            .map(|js_client| serde_wasm_bindgen::from_value(js_client).unwrap())
            .collect::<Vec<Invitee>>();

        let mut members = Invitee::group_to_conversation_member(invitees)?;

        self.0
            .add_members_to_conversation(&conversation_id.into(), &mut members)?
            .map(TryInto::try_into)
            .transpose()
    }

    /// Returns a MLS commit message serialized as TLS
    pub fn remove_clients_from_conversation(
        &mut self,
        conversation_id: Box<[u8]>,
        clients: Box<[js_sys::Uint8Array]>,
    ) -> WasmCryptoResult<Option<Box<[u8]>>> {
        let clients = clients
            .into_iter()
            .cloned()
            .map(|c| c.to_vec().into())
            .collect::<Vec<ClientId>>();
        Ok(self
            .0
            .remove_members_from_conversation(&conversation_id.into(), &clients)?
            .map(|m| {
                m.to_bytes()
                    .map(Into::into)
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
            })
            .transpose()?)
    }

    pub fn leave_conversation(
        &mut self,
        conversation_id: Box<[u8]>,
        other_clients: Box<[js_sys::Uint8Array]>,
    ) -> WasmCryptoResult<ConversationLeaveMessages> {
        let other_clients = other_clients
            .into_iter()
            .cloned()
            .map(|c| c.to_vec().into())
            .collect::<Vec<ClientId>>();

        let messages = self.0.leave_conversation(conversation_id.to_vec(), &other_clients)?;
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

        Ok(ret)
    }

    pub fn decrypt_message(
        &mut self,
        conversation_id: Box<[u8]>,
        payload: Box<[u8]>,
    ) -> WasmCryptoResult<Option<Box<[u8]>>> {
        Ok(self
            .0
            .decrypt_message(conversation_id.to_vec(), payload)
            .map(|maybe| maybe.map(Into::into))?)
    }

    pub fn encrypt_message(&mut self, conversation_id: Box<[u8]>, message: Box<[u8]>) -> WasmCryptoResult<Box<[u8]>> {
        Ok(self
            .0
            .encrypt_message(conversation_id.to_vec(), message)
            .map(Into::into)?)
    }

    pub fn conversation_exists(&self, conversation_id: Box<[u8]>) -> bool {
        self.0.conversation_exists(&conversation_id.into())
    }

    pub fn new_add_proposal(
        &mut self,
        conversation_id: Box<[u8]>,
        keypackage: Box<[u8]>,
    ) -> WasmCryptoResult<Box<[u8]>> {
        let kp = KeyPackage::try_from(&keypackage[..])
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?;
        Ok(self
            .0
            .new_proposal(conversation_id.to_vec(), MlsProposal::Add(kp))?
            .to_bytes()
            .map(Into::into)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?)
    }

    pub fn new_update_proposal(&mut self, conversation_id: Box<[u8]>) -> WasmCryptoResult<Box<[u8]>> {
        Ok(self
            .0
            .new_proposal(conversation_id.to_vec(), MlsProposal::Update)?
            .to_bytes()
            .map(Into::into)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?)
    }

    pub fn new_remove_proposal(
        &mut self,
        conversation_id: Box<[u8]>,
        client_id: FfiClientId,
    ) -> WasmCryptoResult<Box<[u8]>> {
        Ok(self
            .0
            .new_proposal(conversation_id.to_vec(), MlsProposal::Remove(client_id.into()))?
            .to_bytes()
            .map(Into::into)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?)
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    crate::VERSION.into()
}
