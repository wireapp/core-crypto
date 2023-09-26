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
use tls_codec::Serialize;

use core_crypto::prelude::*;

use crate::{
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
    CIPHERSUITE_IN_USE,
};

#[derive(Debug)]
pub struct CoreCryptoNativeClient {
    cc: CoreCrypto,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: u16,
}

#[allow(dead_code)]
impl CoreCryptoNativeClient {
    pub async fn new() -> Result<Self> {
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
        let configuration =
            MlsCentralConfiguration::try_new("whatever".into(), "test".into(), cid, ciphersuites, None, Some(100))?;

        let cc = CoreCrypto::from(MlsCentral::try_new_in_memory(configuration).await?);

        Ok(Self {
            cc,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: 0,
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

    async fn wipe(mut self) -> Result<()> {
        self.cc.take().wipe().await?;
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedMlsClient for CoreCryptoNativeClient {
    async fn get_keypackage(&mut self) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let kp = self
            .cc
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

        Ok(kp.tls_serialize_detached()?)
    }

    async fn add_client(&mut self, conversation_id: &[u8], client_id: &[u8], kp: &[u8]) -> Result<Vec<u8>> {
        let conversation_id = conversation_id.to_vec();
        if !self.cc.conversation_exists(&conversation_id).await {
            let config = MlsConversationConfiguration {
                ciphersuite: CIPHERSUITE_IN_USE.into(),
                ..Default::default()
            };
            self.cc
                .new_conversation(&conversation_id, MlsCredentialType::Basic, config)
                .await?;
        }

        let member = ConversationMember::new_raw(client_id.to_vec().into(), kp.to_vec(), self.cc.provider())?;
        let welcome = self
            .cc
            .add_members_to_conversation(&conversation_id, &mut [member])
            .await?;

        Ok(welcome.welcome.tls_serialize_detached()?)
    }

    async fn kick_client(&mut self, conversation_id: &[u8], client_id: &[u8]) -> Result<Vec<u8>> {
        let commit = self
            .cc
            .remove_members_from_conversation(&conversation_id.to_vec(), &[client_id.to_vec().into()])
            .await?;

        Ok(commit.commit.to_bytes()?)
    }

    async fn process_welcome(&mut self, welcome: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .cc
            .process_raw_welcome_message(welcome.into(), MlsCustomConfiguration::default())
            .await?)
    }

    async fn encrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cc.encrypt_message(&conversation_id.to_vec(), message).await?)
    }

    async fn decrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .cc
            .decrypt_message(&conversation_id.to_vec(), message)
            .await?
            .app_msg)
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedProteusClient for CoreCryptoNativeClient {
    async fn init(&mut self) -> Result<()> {
        Ok(self.cc.proteus_init().await?)
    }

    async fn get_prekey(&mut self) -> Result<Vec<u8>> {
        self.prekey_last_id += 1;
        Ok(self.cc.proteus_new_prekey(self.prekey_last_id).await?)
    }

    async fn session_from_prekey(&mut self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let _ = self.cc.proteus_session_from_prekey(session_id, prekey).await?;
        Ok(())
    }

    async fn session_from_message(&mut self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let (_, ret) = self.cc.proteus_session_from_message(session_id, message).await?;
        Ok(ret)
    }

    async fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cc.proteus_encrypt(session_id, plaintext).await?)
    }

    async fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cc.proteus_decrypt(session_id, ciphertext).await?)
    }

    async fn fingerprint(&self) -> Result<String> {
        Ok(self.cc.proteus_fingerprint()?)
    }
}
