use color_eyre::eyre::Result;
use std::cell::Cell;
use std::sync::Arc;
use tls_codec::Serialize;

use core_crypto::prelude::*;

use crate::util::MlsTransportSuccessProvider;
use crate::{
    CIPHERSUITE_IN_USE,
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
};

#[derive(Debug)]
pub(crate) struct CoreCryptoNativeClient {
    cc: CoreCrypto,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: Cell<u16>,
}

#[allow(dead_code)]
impl CoreCryptoNativeClient {
    pub(crate) async fn new() -> Result<Self> {
        Self::internal_new(false).await
    }

    async fn internal_new(deferred: bool) -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();

        let ciphersuites = vec![CIPHERSUITE_IN_USE.into()];
        let cid = if !deferred {
            Some(client_id.as_hyphenated().to_string().as_bytes().into())
        } else {
            None
        };
        let key = core_crypto::DatabaseKey::generate();
        let configuration =
            MlsClientConfiguration::try_new("whatever".into(), key, cid, ciphersuites, None, Some(100))?;

        let cc = CoreCrypto::from(Session::try_new_in_memory(configuration).await?);

        cc.provide_transport(Arc::new(MlsTransportSuccessProvider::default()))
            .await;

        Ok(Self {
            cc,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: Cell::new(0),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedClient for CoreCryptoNativeClient {
    fn client_name(&self) -> &str {
        "CoreCrypto::native"
    }

    fn client_type(&self) -> EmulatedClientType {
        EmulatedClientType::Native
    }

    fn client_id(&self) -> &[u8] {
        self.client_id.as_slice()
    }

    fn client_protocol(&self) -> EmulatedClientProtocol {
        EmulatedClientProtocol::MLS | EmulatedClientProtocol::PROTEUS
    }

    async fn wipe(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedMlsClient for CoreCryptoNativeClient {
    async fn get_keypackage(&self) -> Result<Vec<u8>> {
        let transaction = self.cc.new_transaction().await?;
        let start = std::time::Instant::now();
        let kp = transaction
            .get_or_create_client_keypackages(CIPHERSUITE_IN_USE.into(), MlsCredentialType::Basic, 1)
            .await?
            .pop()
            .unwrap();

        log::info!(
            "KP Init Key [took {}ms]: Client {} [{}] - {}",
            start.elapsed().as_millis(),
            self.client_name(),
            hex::encode(&self.client_id),
            hex::encode(kp.hpke_init_key()),
        );
        transaction.finish().await?;

        Ok(kp.tls_serialize_detached()?)
    }

    async fn add_client(&self, conversation_id: &[u8], kp: &[u8]) -> Result<()> {
        let conversation_id = conversation_id.to_vec();
        let transaction = self.cc.new_transaction().await?;
        if !transaction.conversation_exists(&conversation_id).await? {
            let config = MlsConversationConfiguration {
                ciphersuite: CIPHERSUITE_IN_USE.into(),
                ..Default::default()
            };
            transaction
                .new_conversation(&conversation_id, MlsCredentialType::Basic, config)
                .await?;
        }

        use tls_codec::Deserialize as _;

        let kp = KeyPackageIn::tls_deserialize(&mut &kp[..])?;
        transaction
            .conversation(&conversation_id)
            .await?
            .add_members(vec![kp])
            .await?;
        transaction.finish().await?;

        Ok(())
    }

    async fn kick_client(&self, conversation_id: &[u8], client_id: &[u8]) -> Result<()> {
        let transaction = self.cc.new_transaction().await?;
        transaction
            .conversation(&conversation_id.to_owned())
            .await?
            .remove_members(&[client_id.to_owned().into()])
            .await?;
        transaction.finish().await?;

        Ok(())
    }

    async fn process_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>> {
        let transaction = self.cc.new_transaction().await?;

        let result = transaction
            .process_raw_welcome_message(welcome, MlsCustomConfiguration::default())
            .await?
            .id;
        transaction.finish().await?;
        Ok(result)
    }

    async fn encrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let transaction = self.cc.new_transaction().await?;
        let result = transaction
            .conversation(&conversation_id.to_vec())
            .await?
            .encrypt_message(message)
            .await?;
        transaction.finish().await?;
        Ok(result)
    }

    async fn decrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        let transaction = self.cc.new_transaction().await?;
        let result = transaction
            .conversation(&conversation_id.to_vec())
            .await?
            .decrypt_message(message)
            .await?
            .app_msg;
        transaction.finish().await?;
        Ok(result)
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedProteusClient for CoreCryptoNativeClient {
    async fn init(&mut self) -> Result<()> {
        let transaction = self.cc.new_transaction().await?;
        transaction.proteus_init().await?;
        Ok(transaction.finish().await?)
    }

    async fn get_prekey(&self) -> Result<Vec<u8>> {
        let transaction = self.cc.new_transaction().await?;
        let prekey_last_id = self.prekey_last_id.get() + 1;
        self.prekey_last_id.replace(prekey_last_id);
        let result = transaction.proteus_new_prekey(prekey_last_id).await?;
        transaction.finish().await?;
        Ok(result)
    }

    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let transaction = self.cc.new_transaction().await?;
        let _ = transaction.proteus_session_from_prekey(session_id, prekey).await?;
        transaction.finish().await?;
        Ok(())
    }

    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let transaction = self.cc.new_transaction().await?;
        let (_, ret) = transaction.proteus_session_from_message(session_id, message).await?;
        transaction.finish().await?;
        Ok(ret)
    }

    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let transaction = self.cc.new_transaction().await?;
        let result = transaction.proteus_encrypt(session_id, plaintext).await?;
        transaction.finish().await?;
        Ok(result)
    }

    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let transaction = self.cc.new_transaction().await?;
        let result = transaction.proteus_decrypt(session_id, ciphertext).await?;
        transaction.finish().await?;
        Ok(result)
    }

    async fn fingerprint(&self) -> Result<String> {
        Ok(self.cc.proteus_fingerprint().await?)
    }
}
