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
use core_crypto::prelude::tls_codec::Serialize;
use core_crypto::prelude::*;

#[derive(Debug)]
pub struct NativeClient {
    cc: MlsCentral,
    client_id: Vec<u8>,
}

impl NativeClient {
    pub async fn new() -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();

        let configuration =
            MlsCentralConfiguration::try_new("whatever".into(), "test".into(), client_id.as_hyphenated().to_string())?;

        let cc = MlsCentral::try_new_in_memory(configuration, None).await?;

        Ok(Self {
            cc,
            client_id: client_id.into_bytes().into(),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl super::EmulatedClient for NativeClient {
    fn client_type(&self) -> super::EmulatedClientType {
        super::EmulatedClientType::Native
    }

    fn client_id(&self) -> &[u8] {
        self.client_id.as_slice()
    }

    async fn get_keypackage(&mut self) -> Result<Vec<u8>> {
        let kps = self.cc.client_keypackages(1).await?;
        Ok(kps[0].key_package().tls_serialize_detached()?)
    }

    async fn add_client(&mut self, conversation_id: &[u8], client_id: &[u8], kp: &[u8]) -> Result<Vec<u8>> {
        if !self.cc.conversation_exists(&conversation_id.to_vec()) {
            self.cc
                .new_conversation(conversation_id.to_vec(), Default::default())
                .await?;
        }

        let member = ConversationMember::new_raw(client_id.to_vec().into(), kp.to_vec())?;
        let welcome = self
            .cc
            .add_members_to_conversation(&conversation_id.to_vec(), &mut [member])
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
        Ok(self.cc.process_raw_welcome_message(welcome.into()).await?)
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
