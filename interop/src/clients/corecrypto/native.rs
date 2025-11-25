#[cfg(feature = "proteus")]
use std::cell::Cell;
use std::sync::Arc;

use anyhow::Result;
use core_crypto::*;
use tls_codec::Serialize;

use crate::{
    CIPHERSUITE_IN_USE,
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
    util::MlsTransportSuccessProvider,
};

#[derive(Debug)]
pub(crate) struct CoreCryptoNativeClient {
    cc: CoreCrypto,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: Cell<u16>,
}

impl CoreCryptoNativeClient {
    pub(crate) async fn new() -> Result<Self> {
        let client_id = ClientId::from(uuid::Uuid::new_v4().into_bytes());

        let db = Database::open(ConnectionType::InMemory, &DatabaseKey::generate())
            .await
            .unwrap();

        let cc = CoreCrypto::from(Session::try_new(&db).await?);

        cc.provide_transport(Arc::new(MlsTransportSuccessProvider::default()))
            .await;

        let ctx = cc.new_transaction().await?;
        ctx.mls_init(client_id.clone().into(), &[CIPHERSUITE_IN_USE.into()])
            .await?;
        ctx.add_credential(Credential::basic(
            CIPHERSUITE_IN_USE.into(),
            client_id.clone(),
            mls_crypto_provider::RustCrypto::default(),
        )?)
        .await?;
        ctx.finish().await?;

        Ok(Self {
            cc,
            client_id: client_id.into(),
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

        let credentials = transaction
            .find_credentials(
                CredentialFindFilters::builder()
                    .credential_type(CredentialType::Basic)
                    .ciphersuite(CIPHERSUITE_IN_USE.into())
                    .build(),
            )
            .await?;
        let credential = credentials
            .last()
            .expect("at least 1 credential already exists of the requested type and ciphersuite");
        let kp = transaction.generate_keypackage(credential, None).await?;

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
        let conversation_id = ConversationId::from(conversation_id);
        let transaction = self.cc.new_transaction().await?;
        if !transaction.conversation_exists(&conversation_id).await? {
            let config = MlsConversationConfiguration {
                ciphersuite: CIPHERSUITE_IN_USE.into(),
                ..Default::default()
            };
            transaction
                .new_conversation(&conversation_id, CredentialType::Basic, config)
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
        let conversation_id = ConversationId::from(conversation_id);
        transaction
            .conversation(&conversation_id)
            .await?
            .remove_members(&[ClientIdRef::new(client_id)])
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
        Ok(result.into())
    }

    async fn encrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let transaction = self.cc.new_transaction().await?;
        let conversation_id = ConversationId::from(conversation_id);
        let result = transaction
            .conversation(&conversation_id)
            .await?
            .encrypt_message(message)
            .await?;
        transaction.finish().await?;
        Ok(result)
    }

    async fn decrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        let transaction = self.cc.new_transaction().await?;
        let conversation_id = ConversationId::from(conversation_id);
        let result = transaction
            .conversation(&conversation_id)
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
