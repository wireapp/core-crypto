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

//! Primitives to export data from a group, such as derived keys and client ids.

use super::Result;
use crate::{
    MlsError, RecursiveError,
    context::CentralContext,
    mls::{ConversationId, MlsConversation, client::id::ClientId},
};

impl MlsConversation {
    const EXPORTER_LABEL: &'static str = "exporter";
    const EXPORTER_CONTEXT: &'static [u8] = &[];

    /// See [crate::mls::conversation::ImmutableConversation::export_secret_key]
    pub fn export_secret_key(
        &self,
        backend: &impl openmls_traits::OpenMlsCryptoProvider,
        key_length: usize,
    ) -> Result<Vec<u8>> {
        self.group
            .export_secret(backend, Self::EXPORTER_LABEL, Self::EXPORTER_CONTEXT, key_length)
            .map_err(MlsError::wrap("exporting secret key"))
            .map_err(Into::into)
    }

    /// See [crate::mls::conversation::ImmutableConversation::get_client_ids]
    pub fn get_client_ids(&self) -> Vec<ClientId> {
        self.group
            .members()
            .map(|kp| ClientId::from(kp.credential.identity()))
            .collect()
    }
}

impl CentralContext {
    /// See [crate::mls::conversation::ImmutableConversation::export_secret_key]
    #[cfg_attr(test, crate::idempotent)]
    pub async fn export_secret_key(&self, conversation_id: &ConversationId, key_length: usize) -> Result<Vec<u8>> {
        self.get_conversation(conversation_id)
            .await?
            .read()
            .await
            .export_secret_key(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::root("getting mls provider"))?,
                key_length,
            )
    }

    /// See [crate::mls::conversation::ImmutableConversation::get_client_ids]
    #[cfg_attr(test, crate::idempotent)]
    pub async fn get_client_ids(&self, conversation_id: &ConversationId) -> Result<Vec<ClientId>> {
        Ok(self
            .get_conversation(conversation_id)
            .await?
            .read()
            .await
            .get_client_ids())
    }
}
