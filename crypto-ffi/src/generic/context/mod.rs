use super::{
    BufferedDecryptedMessage, Ciphersuite, Ciphersuites, ClientId, CommitBundle, ConversationConfiguration,
    ConversationInitBundle, CoreCrypto, CoreCryptoError, CoreCryptoResult, CustomConfiguration, DecryptedMessage,
    MemberAddedMessages, MlsCredentialType, ProposalBundle, WelcomeBundle,
};
use async_lock::{Mutex, OnceCell};
use core_crypto::context::CentralContext;
use core_crypto::{
    prelude::{
        ClientIdentifier, ConversationId, KeyPackageIn, KeyPackageRef, MlsConversationConfiguration,
        VerifiableGroupInfo,
    },
    CryptoError, CryptoResult, MlsError,
};
use std::future::Future;
use std::{ops::Deref, sync::Arc};
use tls_codec::{Deserialize, Serialize};

pub mod e2ei;
pub mod proteus;

#[derive(uniffi::Object)]
pub struct CoreCryptoContext {
    pub(super) context: Arc<CentralContext>,
}

impl Deref for CoreCryptoContext {
    type Target = CentralContext;

    fn deref(&self) -> &Self::Target {
        self.context.as_ref()
    }
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait CoreCryptoCommand: Send + Sync {
    /// Will be called inside a transaction in CoreCrypto
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()>;
}

#[async_trait::async_trait]
impl<F, Fut> CoreCryptoCommand for F
where
    F: Fn(Arc<CoreCryptoContext>) -> Fut + Send + Sync,
    Fut: Future<Output = CoreCryptoResult<()>> + Send,
{
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
        self(context).await
    }
}

/// Helper for working with the new transasction interface.
///
/// This helper serves two purposes: to present a `FnOnce` interface for transactions,
/// and to allow the extraction of data from within transactions.
///
/// ## Extracting Data
///
/// The `CoreCryptoCommand` interface requires some kind of interior mutability to extract
/// any data: it takes an immutable reference to the implementing item, and returns the unit struct
/// in the success case.
///
/// That pattern is relatively arcane and verbose, particularly when we just want to smuggle out
/// some data from within the transaction. This helper is intended to ease and automate
/// that process.
///
/// Use it like this (pseudocode):
///
/// ```ignore
/// // an extractor is always `Arc`-wrapped
/// let extractor: Arc<_> = TransactionHelper::new(move |context| async move {
///     // return whatever you need from the transaction here
/// });
/// core_crypto.transaction(extractor.clone()).await?;
/// let return_value = extractor.into_return_value();
/// ```
///
/// ## Panics
///
/// `TransactionHelper` is a one-shot item. Attempting to use the
/// same extractor in two different transactions will cause a panic.
pub struct TransactionHelper<T, F> {
    func: Mutex<Option<F>>,
    return_value: OnceCell<T>,
}

impl<T, F, Fut> TransactionHelper<T, F>
where
    F: FnOnce(Arc<CoreCryptoContext>) -> Fut + Send + Sync,
    Fut: Future<Output = CoreCryptoResult<T>> + Send,
    T: Send + Sync,
{
    pub fn new(func: F) -> Arc<Self> {
        Arc::new(Self {
            func: Mutex::new(Some(func)),
            return_value: OnceCell::new(),
        })
    }

    /// Get the return value from the internal function.
    ///
    /// ## Panics
    ///
    /// - If there exists more than one strong reference to this extractor
    /// - If the inner function was never called
    /// - If the inner function returned an `Err` variant
    ///
    /// In general if you call this after a call like
    ///
    /// ```ignore
    /// core_crypto.transaction(extractor.clone())?;
    /// ```
    ///
    /// then this will be fine.
    pub fn into_return_value(self: Arc<Self>) -> T {
        Arc::into_inner(self)
            .expect("there should exist exactly one strong ref right now")
            .return_value
            .into_inner()
            .expect("return value should be initialized")
    }

    /// Safely get the return value from the internal function.
    ///
    /// If there exists more than one strong reference to this item, or
    /// the inner function was never called or returned an `Err` variant,
    /// this will return `None`.
    pub fn try_into_return_value(self: Arc<Self>) -> Option<T> {
        Arc::into_inner(self)?.return_value.into_inner()
    }
}

#[async_trait::async_trait]
impl<T, F, Fut> CoreCryptoCommand for TransactionHelper<T, F>
where
    F: FnOnce(Arc<CoreCryptoContext>) -> Fut + Send + Sync,
    Fut: Future<Output = CoreCryptoResult<T>> + Send,
    T: Send + Sync,
{
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
        let func = self
            .func
            .lock()
            .await
            .take()
            .expect("inner function must only be called once");
        let return_value = func(context).await?;
        let set_result = self.return_value.set(return_value).await;
        if set_result.is_err() {
            // can't just `.expect()` here because `T` is not `Debug`
            // though TBH this would be a really weird case; we should already have
            // paniced getting `func` above
            panic!("return value was previously set");
        }
        Ok(())
    }
}

#[uniffi::export]
impl CoreCrypto {
    /// Starts a new transaction in Core Crypto. If the callback succeeds, it will be committed,
    /// otherwise, every operation performed with the context will be discarded.
    ///
    /// When calling this function from within Rust, async functions accepting a context
    /// implement `CoreCryptoCommand`, so operations can be defined inline as follows:
    ///
    /// ```ignore
    /// core_crypto.transaction(Arc::new(|context| async {
    ///     // your implementation here
    ///     Ok(())
    /// }))?;
    /// ```
    pub async fn transaction(&self, command: Arc<dyn CoreCryptoCommand>) -> CoreCryptoResult<()> {
        let context = Arc::new(CoreCryptoContext {
            context: Arc::new(self.central.new_transaction().await?),
        });

        let result = command.execute(context.clone()).await;
        match result {
            Ok(result) => {
                context.context.finish().await?;
                Ok(result)
            }
            Err(err) => {
                context.context.abort().await?;
                Err(err)
            }
        }
    }
}
impl CoreCrypto {
    /// For internal use in deprecated functions.
    pub(crate) async fn deprecated_transaction<F, Fut, R>(&self, callback: F) -> CoreCryptoResult<R>
    where
        F: FnOnce(CentralContext) -> Fut,
        Fut: Future<Output = CryptoResult<R>>,
    {
        let context = self.central.new_transaction().await?;
        let result = callback(context.clone()).await;
        match result {
            Ok(result) => {
                context.finish().await?;
                Ok(result)
            }
            Err(err) => {
                context.abort().await?;
                Err(err.into())
            }
        }
    }
}

#[uniffi::export]
impl CoreCryptoContext {
    /// See [core_crypto::context::CentralContext::set_data].
    pub async fn set_data(&self, data: Vec<u8>) -> CoreCryptoResult<()> {
        self.context.set_data(data).await.map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::get_data].
    pub async fn get_data(&self) -> CoreCryptoResult<Option<Vec<u8>>> {
        self.context.get_data().await.map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::mls_init]
    pub async fn mls_init(
        &self,
        client_id: ClientId,
        ciphersuites: Ciphersuites,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<()> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CryptoError::from)?;
        self.context
            .mls_init(
                ClientIdentifier::Basic(client_id.0),
                (&ciphersuites).into(),
                nb_key_package,
            )
            .await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::mls_generate_keypairs]
    pub async fn mls_generate_keypairs(&self, ciphersuites: Ciphersuites) -> CoreCryptoResult<Vec<ClientId>> {
        Ok(self
            .context
            .mls_generate_keypairs((&ciphersuites).into())
            .await
            .map(|cids| cids.into_iter().map(ClientId).collect())?)
    }

    /// See [core_crypto::context::CentralContext::mls_init_with_client_id]
    pub async fn mls_init_with_client_id(
        &self,
        client_id: ClientId,
        tmp_client_ids: Vec<ClientId>,
        ciphersuites: Ciphersuites,
    ) -> CoreCryptoResult<()> {
        Ok(self
            .context
            .mls_init_with_client_id(
                client_id.0,
                tmp_client_ids.into_iter().map(|cid| cid.0).collect(),
                (&ciphersuites).into(),
            )
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::client_public_key]
    pub async fn client_public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .context
            .client_public_key(ciphersuite.into(), credential_type.into())
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::conversation_epoch]
    pub async fn conversation_epoch(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<u64> {
        Ok(self.context.conversation_epoch(&conversation_id).await?)
    }

    /// See [core_crypto::mls::MlsCentral::conversation_ciphersuite]
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let cs = self.context.conversation_ciphersuite(conversation_id).await?;
        Ok(Ciphersuite::from(core_crypto::prelude::CiphersuiteName::from(cs)))
    }

    /// See [core_crypto::mls::MlsCentral::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<bool> {
        Ok(self.context.conversation_exists(&conversation_id).await?)
    }

    /// See [core_crypto::mls::MlsCentral::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<ClientId>> {
        Ok(self
            .context
            .get_client_ids(&conversation_id)
            .await
            .map(|cids| cids.into_iter().map(ClientId).collect())?)
    }

    /// See [core_crypto::mls::MlsCentral::export_secret_key]
    pub async fn export_secret_key(&self, conversation_id: Vec<u8>, key_length: u32) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .context
            .export_secret_key(&conversation_id, key_length as usize)
            .await?)
    }

    /// See [core_crypto::mls::MlsCentral::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.context.get_external_sender(&conversation_id).await?)
    }

    /// See [core_crypto::context::CentralContext::get_or_create_client_keypackages]
    pub async fn client_keypackages(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
        amount_requested: u32,
    ) -> CoreCryptoResult<Vec<Vec<u8>>> {
        let kps = self
            .context
            .get_or_create_client_keypackages(ciphersuite.into(), credential_type.into(), amount_requested as usize)
            .await?;

        kps.into_iter()
            .map(|kp| {
                Ok(kp
                    .tls_serialize_detached()
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)?)
            })
            .collect::<CoreCryptoResult<Vec<Vec<u8>>>>()
    }

    /// See [core_crypto::context::CentralContext::client_valid_key_packages_count]
    pub async fn client_valid_keypackages_count(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<u64> {
        let count = self
            .context
            .client_valid_key_packages_count(ciphersuite.into(), credential_type.into())
            .await?;

        Ok(count.try_into().unwrap_or(0))
    }

    /// See [core_crypto::context::CentralContext::delete_keypackages]
    pub async fn delete_keypackages(&self, refs: Vec<Vec<u8>>) -> CoreCryptoResult<()> {
        let refs = refs
            .into_iter()
            .map(|r| KeyPackageRef::from_slice(&r))
            .collect::<Vec<_>>();

        self.context.delete_keypackages(&refs[..]).await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::new_conversation]
    pub async fn create_conversation(
        &self,
        conversation_id: Vec<u8>,
        creator_credential_type: MlsCredentialType,
        config: ConversationConfiguration,
    ) -> CoreCryptoResult<()> {
        let mut lower_cfg = MlsConversationConfiguration {
            custom: config.custom.into(),
            ciphersuite: config.ciphersuite.into(),
            ..Default::default()
        };

        self.context
            .set_raw_external_senders(&mut lower_cfg, config.external_senders)
            .await?;

        self.context
            .new_conversation(&conversation_id, creator_credential_type.into(), lower_cfg)
            .await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::process_raw_welcome_message]
    pub async fn process_welcome_message(
        &self,
        welcome_message: Vec<u8>,
        custom_configuration: CustomConfiguration,
    ) -> CoreCryptoResult<WelcomeBundle> {
        let result = self
            .context
            .process_raw_welcome_message(welcome_message, custom_configuration.into())
            .await?
            .into();
        Ok(result)
    }

    /// See [core_crypto::context::CentralContext::add_members_to_conversation]
    pub async fn add_clients_to_conversation(
        &self,
        conversation_id: Vec<u8>,
        key_packages: Vec<Vec<u8>>,
    ) -> CoreCryptoResult<MemberAddedMessages> {
        let key_packages = key_packages
            .into_iter()
            .map(|kp| {
                KeyPackageIn::tls_deserialize(&mut kp.as_slice())
                    .map_err(|e| CoreCryptoError::from(CryptoError::MlsError(e.into())))
            })
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        let result = self
            .context
            .add_members_to_conversation(&conversation_id, key_packages)
            .await?
            .try_into()?;
        Ok(result)
    }

    /// See [core_crypto::context::CentralContext::remove_members_from_conversation]
    pub async fn remove_clients_from_conversation(
        &self,
        conversation_id: Vec<u8>,
        clients: Vec<ClientId>,
    ) -> CoreCryptoResult<CommitBundle> {
        let clients: Vec<core_crypto::prelude::ClientId> = clients.into_iter().map(|c| c.0).collect();
        let result = self
            .context
            .remove_members_from_conversation(&conversation_id, &clients)
            .await?
            .try_into()?;

        Ok(result)
    }

    /// See [core_crypto::context::CentralContext::mark_conversation_as_child_of]
    pub async fn mark_conversation_as_child_of(&self, child_id: Vec<u8>, parent_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.context
            .mark_conversation_as_child_of(&child_id, &parent_id)
            .await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::update_keying_material]
    pub async fn update_keying_material(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<CommitBundle> {
        self.context.update_keying_material(&conversation_id).await?.try_into()
    }

    /// See [core_crypto::context::CentralContext::commit_pending_proposals]
    pub async fn commit_pending_proposals(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Option<CommitBundle>> {
        self.context
            .commit_pending_proposals(&conversation_id)
            .await
            .transpose()
            .map(|r| r?.try_into())
            .transpose()
    }

    /// see [core_crypto::context::CentralContext::wipe_conversation]
    pub async fn wipe_conversation(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.context.wipe_conversation(&conversation_id).await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::decrypt_message]
    pub async fn decrypt_message(
        &self,
        conversation_id: Vec<u8>,
        payload: Vec<u8>,
    ) -> CoreCryptoResult<DecryptedMessage> {
        let raw_decrypted_message = self.context.decrypt_message(&conversation_id, payload).await?;

        let decrypted_message: DecryptedMessage = raw_decrypted_message.try_into()?;

        Ok(decrypted_message)
    }

    /// See [core_crypto::context::CentralContext::encrypt_message]
    pub async fn encrypt_message(&self, conversation_id: Vec<u8>, message: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.context.encrypt_message(&conversation_id, message).await?)
    }

    /// See [core_crypto::context::CentralContext::new_add_proposal]
    pub async fn new_add_proposal(
        &self,
        conversation_id: Vec<u8>,
        keypackage: Vec<u8>,
    ) -> CoreCryptoResult<ProposalBundle> {
        let kp = KeyPackageIn::tls_deserialize(&mut keypackage.as_slice())
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?;
        self.context
            .new_add_proposal(&conversation_id, kp.into())
            .await?
            .try_into()
    }

    /// See [core_crypto::context::CentralContext::new_update_proposal]
    pub async fn new_update_proposal(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<ProposalBundle> {
        self.context.new_update_proposal(&conversation_id).await?.try_into()
    }

    /// See [core_crypto::context::CentralContext::new_remove_proposal]
    pub async fn new_remove_proposal(
        &self,
        conversation_id: Vec<u8>,
        client_id: ClientId,
    ) -> CoreCryptoResult<ProposalBundle> {
        self.context
            .new_remove_proposal(&conversation_id, client_id.0)
            .await?
            .try_into()
    }

    /// See [core_crypto::context::CentralContext::new_external_add_proposal]
    pub async fn new_external_add_proposal(
        &self,
        conversation_id: Vec<u8>,
        epoch: u64,
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .context
            .new_external_add_proposal(
                conversation_id,
                epoch.into(),
                ciphersuite.into(),
                credential_type.into(),
            )
            .await?
            .to_bytes()
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?)
    }

    /// See [core_crypto::context::CentralContext::join_by_external_commit]
    pub async fn join_by_external_commit(
        &self,
        group_info: Vec<u8>,
        custom_configuration: CustomConfiguration,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<ConversationInitBundle> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?;
        self.context
            .join_by_external_commit(group_info, custom_configuration.into(), credential_type.into())
            .await?
            .try_into()
    }

    /// See [core_crypto::context::CentralContext::merge_pending_group_from_external_commit]
    pub async fn merge_pending_group_from_external_commit(
        &self,
        conversation_id: Vec<u8>,
    ) -> CoreCryptoResult<Option<Vec<BufferedDecryptedMessage>>> {
        if let Some(decrypted_messages) = self
            .context
            .merge_pending_group_from_external_commit(&conversation_id)
            .await?
        {
            let result = decrypted_messages
                .into_iter()
                .map(TryInto::try_into)
                .collect::<CoreCryptoResult<Vec<_>>>()?;
            return Ok(Some(result));
        }

        Ok(None)
    }

    /// See [core_crypto::context::CentralContext::clear_pending_group_from_external_commit]
    pub async fn clear_pending_group_from_external_commit(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.context
            .clear_pending_group_from_external_commit(&conversation_id)
            .await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::commit_accepted]
    pub async fn commit_accepted(
        &self,
        conversation_id: Vec<u8>,
    ) -> CoreCryptoResult<Option<Vec<BufferedDecryptedMessage>>> {
        if let Some(decrypted_messages) = self.context.commit_accepted(&conversation_id).await? {
            let result = decrypted_messages
                .into_iter()
                .map(TryInto::try_into)
                .collect::<CoreCryptoResult<Vec<_>>>()?;
            return Ok(Some(result));
        }

        Ok(None)
    }

    /// See [core_crypto::context::CentralContext::clear_pending_proposal]
    pub async fn clear_pending_proposal(
        &self,
        conversation_id: Vec<u8>,
        proposal_ref: Vec<u8>,
    ) -> CoreCryptoResult<()> {
        self.context
            .clear_pending_proposal(&conversation_id, proposal_ref.into())
            .await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::clear_pending_commit]
    pub async fn clear_pending_commit(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.context.clear_pending_commit(&conversation_id).await?;
        Ok(())
    }
}
