use std::{ops::Deref, sync::Arc};

use core_crypto::{
    mls::context::CentralContext,
    prelude::{ClientIdentifier, KeyPackageRef, MlsConversationConfiguration},
    CryptoError, MlsError,
};
use tls_codec::Serialize;

use super::{
    Ciphersuite, Ciphersuites, ClientId, ConversationConfiguration, CoreCrypto, CoreCryptoResult, MlsCredentialType,
};

#[derive(uniffi::Object)]
pub struct CoreCryptoContext {
    context: Arc<CentralContext>,
}

impl Deref for CoreCryptoContext {
    type Target = CentralContext;

    fn deref(&self) -> &Self::Target {
        self.context.as_ref()
    }
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait CoreCryptoCommand: std::fmt::Debug + Send + Sync {
    /// Will be called inside a transaction in CoreCrypto
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()>;
}

impl CoreCrypto {
    /// Starts a new transaction in Core Crypto. If the callback succeeds, it will be committed,
    /// otherwise, every operation performed with the context will be discarded.
    pub async fn transaction(&self, command: Arc<dyn CoreCryptoCommand>) -> CoreCryptoResult<()> {
        let context = Arc::new(CoreCryptoContext {
            context: Arc::new(self.central.new_transaction().await),
        });

        let result = command.execute(context.clone()).await;
        if result.is_ok() {
            context.context.finish().await?;
        }
        Ok(())
    }
}

#[uniffi::export]
impl CoreCryptoContext {
    /// See [core_crypto::mls::context::CentralContext::mls_init]
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

    /// See [core_crypto::mls::context::CentralContext::mls_generate_keypairs]
    pub async fn mls_generate_keypairs(&self, ciphersuites: Ciphersuites) -> CoreCryptoResult<Vec<ClientId>> {
        Ok(self
            .context
            .mls_generate_keypairs((&ciphersuites).into())
            .await
            .map(|cids| cids.into_iter().map(ClientId).collect())?)
    }

    /// See [core_crypto::mls::context::CentralContext::mls_init_with_client_id]
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

    /// See [core_crypto::mls::context::CentralContext::get_or_create_client_keypackages]
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

    /// See [core_crypto::mls::context::CentralContext::client_valid_key_packages_count]
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

    /// See [core_crypto::mls::context::CentralContext::delete_keypackages]
    pub async fn delete_keypackages(&self, refs: Vec<Vec<u8>>) -> CoreCryptoResult<()> {
        let refs = refs
            .into_iter()
            .map(|r| KeyPackageRef::from_slice(&r))
            .collect::<Vec<_>>();

        self.context.delete_keypackages(&refs[..]).await?;
        Ok(())
    }

    /// See [core_crypto::mls::context::CentralContext::new_conversation]
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
}
