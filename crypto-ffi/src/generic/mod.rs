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
use crate::{Ciphersuite, Ciphersuites, ClientId, CoreCryptoError, CoreCryptoResult, proteus_impl};
use core_crypto::mls::conversation::Conversation as _;
pub use core_crypto::prelude::ConversationId;
use core_crypto::{
    RecursiveError,
    prelude::{
        Client, EntropySeed, MlsBufferedConversationDecryptMessage, MlsClientConfiguration, MlsCommitBundle,
        MlsConversationDecryptMessage, MlsCustomConfiguration, MlsGroupInfoBundle, MlsProposalBundle,
        VerifiableGroupInfo,
    },
};
use core_crypto_keystore::Connection as Database;

pub mod context;
mod epoch_observer;

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
    /// Deprecated: this member will be removed in the future. Prefer using the `EpochObserver` interface.
    #[deprecated = "This member will be removed in the future. Prefer using the `EpochObserver` interface."]
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

        #[expect(deprecated)]
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

        #[expect(deprecated)]
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
/// See [core_crypto::mls::Client::try_new]
pub async fn core_crypto_new(
    path: String,
    key: DatabaseKey,
    client_id: ClientId,
    ciphersuites: Ciphersuites,
    nb_key_package: Option<u32>,
) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::new(path, key, Some(client_id), Some(ciphersuites), nb_key_package).await
}

#[uniffi::export]
/// Similar to [core_crypto_new] but defers MLS initialization. It can be initialized later
/// with [CoreCryptoContext::mls_init].
pub async fn core_crypto_deferred_init(path: String, key: DatabaseKey) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::new(path, key, None, None, None).await
}

#[allow(dead_code, unused_variables)]
#[uniffi::export]
impl CoreCrypto {
    #[uniffi::constructor]
    pub async fn new(
        path: String,
        key: DatabaseKey,
        client_id: Option<ClientId>,
        ciphersuites: Option<Ciphersuites>,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<Self> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CoreCryptoError::generic())?;
        let configuration = MlsClientConfiguration::try_new(
            path,
            key.clone(),
            client_id.map(|cid| cid.0.clone()),
            (&ciphersuites.unwrap_or_default()).into(),
            None,
            nb_key_package,
        )?;

        let client = Client::try_new(configuration).await?;
        let central = core_crypto::CoreCrypto::from(client);

        Ok(CoreCrypto { central })
    }

    /// See [core_crypto::mls::Client::provide_transport]
    pub async fn provide_transport(&self, callbacks: Arc<dyn MlsTransport>) -> CoreCryptoResult<()> {
        self.central
            .provide_transport(Arc::new(MlsTransportWrapper(callbacks)))
            .await;
        Ok(())
    }

    /// See [core_crypto::mls::Client::client_public_key]
    pub async fn client_public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .public_key(ciphersuite.into(), credential_type.into())
            .await?)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::epoch]
    pub async fn conversation_epoch(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<u64> {
        let conversation = self
            .central
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?;
        Ok(conversation.epoch().await)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::ciphersuite]
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let cs = self
            .central
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .ciphersuite()
            .await;
        Ok(Ciphersuite::from(core_crypto::prelude::CiphersuiteName::from(cs)))
    }

    /// See [core_crypto::mls::Client::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<bool> {
        let conversation_exists = self
            .central
            .conversation_exists(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?;
        Ok(conversation_exists)
    }

    /// See [core_crypto::mls::Client::random_bytes]
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
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
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
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .export_secret_key(key_length as usize)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .central
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
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
        let dumped_pki_env = self
            .central
            .e2ei_dump_pki_env()
            .await
            .map_err(RecursiveError::mls_client("dumping pki env"))?
            .map(Into::into);
        Ok(dumped_pki_env)
    }

    /// See [core_crypto::mls::Client::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.central.e2ei_is_pki_env_setup().await
    }

    /// See [core_crypto::mls::Client::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let sc = core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
            .signature_algorithm();
        self.central
            .e2ei_is_enabled(sc)
            .await
            .map_err(RecursiveError::mls_client("is e2ei enabled on client?"))
            .map_err(Into::into)
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
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
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
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .get_user_identities(&user_ids[..])
            .await?
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
            .collect::<HashMap<String, Vec<WireIdentity>>>())
    }

    /// See [core_crypto::mls::Client::get_credential_in_use]
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
        let credential = self
            .central
            .get_credential_in_use(group_info, credential_type.into())
            .await
            .map_err(RecursiveError::mls_client("getting credential in use"))?
            .into();
        Ok(credential)
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
    use crate::MlsError;

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
        let key = DatabaseKey(core_crypto_keystore::DatabaseKey::generate());
        let result = CoreCrypto::new("/root/asdf".into(), key, None, None, None).await;
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

// TODO: We derive Constructor here only because we need to construct an instance in interop.
// Remove it once we drop the FFI client from interop.
#[derive(derive_more::Constructor, derive_more::Deref)]
pub struct DatabaseKey(core_crypto_keystore::DatabaseKey);

uniffi::custom_type!(DatabaseKey, Vec<u8>, {
    lower: |key| key.0.to_vec(),
    try_lift: |vec| {
        Ok(DatabaseKey(core_crypto_keystore::DatabaseKey::try_from(&vec[..])
                        .map_err(|err| CoreCryptoError::Other(err.to_string()))?))
    }
});

/// Updates the key of the CoreCrypto database.
/// To be used only once, when moving from CoreCrypto <= 5.x to CoreCrypto 6.x.
#[uniffi::export(name = "migrateDatabaseKeyTypeToBytes")]
pub async fn migrate_db_key_type_to_bytes(name: &str, old_key: &str, new_key: &DatabaseKey) -> CoreCryptoResult<()> {
    Database::migrate_db_key_type_to_bytes(name, old_key, &new_key.0)
        .await
        .map_err(|err| CoreCryptoError::Other(err.to_string()))
}
