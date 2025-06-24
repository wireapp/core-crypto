use crate::{
    CIPHERSUITE_IN_USE,
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
};
use color_eyre::eyre::Result;
use core_crypto_ffi::{Ciphersuites, ClientId, CoreCrypto, CredentialType, CustomConfiguration, TransactionHelper};
use std::cell::Cell;
use std::sync::Arc;
use tempfile::NamedTempFile;

#[derive(Debug)]
pub(crate) struct CoreCryptoFfiClient {
    cc: CoreCrypto,
    client_id: Vec<u8>,
    // We will create a NamedTempFile which we will immediately use to get the path.
    // Once we get the path, we don't need to read from it anymore, but the compiler
    // will rightly point out that the value we store in the CoreCryptoFfiClient
    // struct is never read. However, we need to store the NamedTempFile instance in
    // the struct, so that the temporary file is not cleaned up prematurely.
    // So mark the field as unused to silence the compiler here.
    _temp_file: NamedTempFile,
    #[cfg(feature = "proteus")]
    prekey_last_id: Cell<u16>,
}

impl CoreCryptoFfiClient {
    pub(crate) async fn new() -> Result<CoreCryptoFfiClient> {
        let client_id = uuid::Uuid::new_v4();
        let client_id_bytes: Vec<u8> = client_id.as_hyphenated().to_string().as_bytes().into();
        let client_id = Arc::new(ClientId::from(core_crypto::prelude::ClientId::from(
            &client_id_bytes[..],
        )));
        let ciphersuite = CIPHERSUITE_IN_USE.into();
        let temp_file = NamedTempFile::with_prefix("interop-ffi-keystore-")?;

        let cc = CoreCrypto::new(
            temp_file.path().to_string_lossy().into_owned(),
            core_crypto_ffi::DatabaseKey::new(core_crypto::DatabaseKey::generate()),
            Some(client_id),
            Some(Arc::new(Ciphersuites::new(vec![ciphersuite]))),
            None,
            None,
        )
        .await?;

        cc.provide_transport(Arc::new(crate::MlsTransportSuccessProvider::default()))
            .await?;

        Ok(Self {
            cc,
            _temp_file: temp_file,
            client_id: client_id_bytes,
            #[cfg(feature = "proteus")]
            prekey_last_id: Cell::new(0),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedClient for CoreCryptoFfiClient {
    fn client_name(&self) -> &str {
        "CoreCrypto::ffi"
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
impl EmulatedMlsClient for CoreCryptoFfiClient {
    async fn get_keypackage(&self) -> Result<Vec<u8>> {
        let ciphersuite = CIPHERSUITE_IN_USE.into();
        let credential_type = CredentialType::Basic;
        let extractor = TransactionHelper::new(move |context| async move {
            Ok(context
                .client_keypackages(ciphersuite, credential_type, 1)
                .await?
                .pop()
                .unwrap())
        });
        self.cc.transaction(extractor.clone()).await?;
        let kp = extractor.into_return_value();
        Ok(kp)
    }

    async fn add_client(&self, conversation_id: &[u8], kp: &[u8]) -> Result<()> {
        let conversation_id = conversation_id.to_vec();
        if !self.cc.conversation_exists(&conversation_id).await? {
            let cfg = core_crypto_ffi::ConversationConfiguration {
                ciphersuite: Some(CIPHERSUITE_IN_USE.into()),
                external_senders: Default::default(),
                custom: Default::default(),
            };
            let conversation_id = conversation_id.clone();
            self.cc
                .transaction(TransactionHelper::new(async move |context| {
                    let conversation_id = conversation_id.clone();
                    context
                        .create_conversation(&conversation_id, CredentialType::Basic, cfg)
                        .await?;
                    Ok(())
                }))
                .await?;
        }

        let key_packages = vec![kp.to_vec()];
        let extractor = TransactionHelper::new(async move |context| {
            context
                .add_clients_to_conversation(&conversation_id, key_packages)
                .await
        });
        self.cc.transaction(extractor.clone()).await?;
        Ok(())
    }

    async fn kick_client(&self, conversation_id: &[u8], client_id: &[u8]) -> Result<()> {
        let client_id = Arc::new(ClientId::from(core_crypto::prelude::ClientId::from(client_id)));
        let conversation_id = conversation_id.to_vec();
        let extractor = TransactionHelper::new(move |context| async move {
            context
                .remove_clients_from_conversation(&conversation_id, vec![client_id])
                .await
        });
        self.cc.transaction(extractor.clone()).await?;
        Ok(())
    }

    async fn process_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>> {
        let cfg = CustomConfiguration {
            key_rotation_span: None,
            wire_policy: None,
        };
        let welcome = welcome.to_vec();
        let extractor =
            TransactionHelper::new(move |context| async move { context.process_welcome_message(welcome, cfg).await });
        self.cc.transaction(extractor.clone()).await?;
        Ok(extractor.into_return_value().id)
    }

    async fn encrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let conversation_id = conversation_id.to_vec();
        let message = message.to_vec();
        let extractor =
            TransactionHelper::new(
                move |context| async move { context.encrypt_message(&conversation_id, message).await },
            );
        self.cc.transaction(extractor.clone()).await?;
        Ok(extractor.into_return_value())
    }

    async fn decrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        let conversation_id = conversation_id.to_vec();
        let message = message.to_vec();
        let extractor =
            TransactionHelper::new(
                move |context| async move { context.decrypt_message(&conversation_id, message).await },
            );
        self.cc.transaction(extractor.clone()).await?;
        Ok(extractor.into_return_value().message)
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedProteusClient for CoreCryptoFfiClient {
    async fn init(&mut self) -> Result<()> {
        self.cc
            .transaction(TransactionHelper::new(move |context| async move {
                context.proteus_init().await
            }))
            .await?;
        Ok(())
    }

    async fn get_prekey(&self) -> Result<Vec<u8>> {
        let prekey_last_id = self.prekey_last_id.get() + 1;
        self.prekey_last_id.replace(prekey_last_id);
        let extractor =
            TransactionHelper::new(move |context| async move { context.proteus_new_prekey(prekey_last_id).await });
        self.cc.transaction(extractor.clone()).await?;
        Ok(extractor.into_return_value())
    }

    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let session_id = session_id.to_string();
        let prekey = prekey.to_vec();
        self.cc
            .transaction(TransactionHelper::new(move |context| async move {
                context.proteus_session_from_prekey(session_id, prekey).await
            }))
            .await?;
        Ok(())
    }

    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let session_id = session_id.to_string();
        let message = message.to_vec();
        let extractor = TransactionHelper::new(move |context| async move {
            context.proteus_session_from_message(session_id, message).await
        });
        self.cc.transaction(extractor.clone()).await?;
        Ok(extractor.into_return_value())
    }

    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session_id = session_id.to_string();
        let plaintext = plaintext.to_vec();
        let extractor =
            TransactionHelper::new(move |context| async move { context.proteus_encrypt(session_id, plaintext).await });
        self.cc.transaction(extractor.clone()).await?;
        Ok(extractor.into_return_value())
    }

    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let session_id = session_id.to_string();
        let ciphertext = ciphertext.to_vec();
        let extractor =
            TransactionHelper::new(move |context| async move { context.proteus_decrypt(session_id, ciphertext).await });
        self.cc.transaction(extractor.clone()).await?;
        Ok(extractor.into_return_value())
    }

    async fn fingerprint(&self) -> Result<String> {
        self.cc.proteus_fingerprint().await.map_err(Into::into)
    }
}
