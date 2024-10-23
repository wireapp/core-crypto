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

use color_eyre::eyre::Result;
use core_crypto_ffi::{ClientId, CoreCrypto, CustomConfiguration, MlsCredentialType, UniffiCustomTypeConverter};
use std::sync::Arc;

use crate::{
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
    CIPHERSUITE_IN_USE,
};

#[derive(Debug)]
pub(crate) struct CoreCryptoFfiClient {
    cc: CoreCrypto,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: u16,
}

impl CoreCryptoFfiClient {
    pub(crate) async fn new() -> Result<CoreCryptoFfiClient> {
        let client_id = uuid::Uuid::new_v4();
        let client_id_bytes: Vec<u8> = client_id.as_hyphenated().to_string().as_bytes().into();
        let client_id = ClientId::into_custom(client_id_bytes.clone()).unwrap();
        let ciphersuite = CIPHERSUITE_IN_USE.into();
        let cc = CoreCrypto::new(
            "path".into(),
            "key".into(),
            Some(client_id),
            Some(vec![ciphersuite].into()),
            None,
        )
        .await?;
        Ok(Self {
            cc,
            client_id: client_id_bytes,
            #[cfg(feature = "proteus")]
            prekey_last_id: 0,
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

    async fn wipe(mut self) -> Result<()> {
        Ok(Arc::new(self.cc).wipe().await?)
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedMlsClient for CoreCryptoFfiClient {
    async fn get_keypackage(&mut self) -> Result<Vec<u8>> {
        let ciphersuite = CIPHERSUITE_IN_USE.into();
        let credential_type = MlsCredentialType::Basic;
        let kp = self
            .cc
            .client_keypackages(ciphersuite, credential_type, 1)
            .await?
            .pop()
            .unwrap();
        Ok(kp)
    }

    async fn add_client(&mut self, conversation_id: &[u8], kp: &[u8]) -> Result<Vec<u8>> {
        if !self.cc.conversation_exists(conversation_id.to_vec()).await? {
            let cfg = core_crypto_ffi::ConversationConfiguration {
                ciphersuite: CIPHERSUITE_IN_USE.into(),
                external_senders: vec![],
                custom: CustomConfiguration {
                    key_rotation_span: None,
                    wire_policy: None,
                },
            };
            self.cc
                .create_conversation(conversation_id.to_vec(), MlsCredentialType::Basic, cfg)
                .await?;
        }

        let welcome = self
            .cc
            .add_clients_to_conversation(conversation_id.to_vec(), vec![kp.to_vec()])
            .await?;

        Ok(welcome.welcome)
    }

    async fn kick_client(&mut self, conversation_id: &[u8], client_id: &[u8]) -> Result<Vec<u8>> {
        let client_id = ClientId::into_custom(client_id.to_vec()).unwrap();
        let commit = self
            .cc
            .remove_clients_from_conversation(conversation_id.to_vec(), vec![client_id])
            .await?;

        Ok(commit.commit)
    }

    async fn process_welcome(&mut self, welcome: &[u8]) -> Result<Vec<u8>> {
        let cfg = CustomConfiguration {
            key_rotation_span: None,
            wire_policy: None,
        };
        Ok(self.cc.process_welcome_message(welcome.to_vec(), cfg).await?.id)
    }

    async fn encrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        self.cc
            .encrypt_message(conversation_id.to_vec(), message.to_vec())
            .await
            .map_err(Into::into)
    }

    async fn decrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .cc
            .decrypt_message(conversation_id.to_vec(), message.to_vec())
            .await?
            .message)
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedProteusClient for CoreCryptoFfiClient {
    async fn init(&mut self) -> Result<()> {
        self.cc.proteus_init().await.map_err(Into::into)
    }

    async fn get_prekey(&mut self) -> Result<Vec<u8>> {
        self.prekey_last_id += 1;
        self.cc
            .proteus_new_prekey(self.prekey_last_id)
            .await
            .map_err(Into::into)
    }

    async fn session_from_prekey(&mut self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let _ = self
            .cc
            .proteus_session_from_prekey(session_id.to_string(), prekey.to_vec())
            .await?;
        Ok(())
    }

    async fn session_from_message(&mut self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        self.cc
            .proteus_session_from_message(session_id.to_string(), message.to_vec())
            .await
            .map_err(Into::into)
    }

    async fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.cc
            .proteus_encrypt(session_id.to_string(), plaintext.to_vec())
            .await
            .map_err(Into::into)
    }

    async fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.cc
            .proteus_decrypt(session_id.to_string(), ciphertext.to_vec())
            .await
            .map_err(Into::into)
    }

    async fn fingerprint(&self) -> Result<String> {
        self.cc.proteus_fingerprint().await.map_err(Into::into)
    }
}
