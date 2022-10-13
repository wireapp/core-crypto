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

use mls_crypto_provider::MlsCryptoProvider;

use crate::{client::ClientId, CryptoError, CryptoResult, MlsCentral, MlsError};

use super::{ConversationId, MlsConversation};

impl MlsConversation {
    /// See [MlsCentral::export_secret_key]
    pub fn export_secret_key(
        &self,
        backend: &MlsCryptoProvider,
        label: &str,
        key_length: usize,
    ) -> CryptoResult<Vec<u8>> {
        self.group
            .export_secret(backend, label, &[], key_length)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    /// See [MlsCentral::export_clients]
    pub fn export_clients(&self) -> Vec<ClientId> {
        self.group
            .members()
            .iter()
            .map(|kp| ClientId::from(kp.credential().identity()))
            .collect()
    }
}

impl MlsCentral {
    /// Derives a new key from the one in the group, allowing it to be use elsewehere.
    ///
    /// # Errors
    /// OpenMls secret generation error or conversation not found
    pub fn export_secret_key(
        &self,
        conversation_id: &ConversationId,
        label: &str,
        key_length: usize,
    ) -> CryptoResult<Vec<u8>> {
        self.get_conversation(conversation_id)?
            .export_secret_key(&self.mls_backend, label, key_length)
    }

    /// Exports the clients from a conversation
    ///
    /// # Errors
    /// if the conversation can't be found
    pub fn export_clients(&self, conversation_id: &ConversationId) -> CryptoResult<Vec<ClientId>> {
        Ok(self.get_conversation(conversation_id)?.export_clients())
    }
}
