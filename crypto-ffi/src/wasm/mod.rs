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
use core_crypto::{MlsTransportResponse, prelude::*};
use core_crypto_keystore::Connection as Database;
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

use crate::{
    Ciphersuite, CommitBundle, CoreCryptoError, CredentialType, FfiClientId, InternalError, MlsError, ProposalBundle,
    WasmCryptoResult, lower_ciphersuites,
};

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

/// Updates the key of the CoreCrypto database.
/// To be used only once, when moving from CoreCrypto <= 5.x to CoreCrypto 6.x.
#[wasm_bindgen(js_name = migrateDatabaseKeyTypeToBytes)]
pub async fn migrate_db_key_type_to_bytes(name: &str, old_key: &str, new_key: &DatabaseKey) -> WasmCryptoResult<()> {
    Database::migrate_db_key_type_to_bytes(name, old_key, &new_key.0)
        .await
        .map_err(InternalError::generic())
        .map_err(Into::into)
}

#[derive(Debug)]
#[wasm_bindgen]
pub struct CoreCrypto {
    inner: Arc<core_crypto::CoreCrypto>,
}

#[wasm_bindgen]
impl CoreCrypto {
    /// see [core_crypto::mls::Client::try_new]
    pub async fn _internal_new(
        path: String,
        key: DatabaseKey,
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
            key.0,
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
        key: DatabaseKey,
        entropy_seed: Option<Box<[u8]>>,
    ) -> WasmCryptoResult<CoreCrypto> {
        let entropy_seed = entropy_seed.map(|s| s.to_vec());
        let configuration = MlsClientConfiguration::try_new(path, key.0, None, vec![], entropy_seed, None)
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
#[derive(Debug)]
pub struct DatabaseKey(core_crypto_keystore::DatabaseKey);

#[wasm_bindgen]
impl DatabaseKey {
    #[wasm_bindgen(constructor)]
    pub fn new(buf: &[u8]) -> Result<DatabaseKey, wasm_bindgen::JsError> {
        let key =
            core_crypto_keystore::DatabaseKey::try_from(buf).map_err(|err| InternalError::Other(err.to_string()))?;
        Ok(DatabaseKey(key))
    }
}
