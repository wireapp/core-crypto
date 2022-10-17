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

use crate::mls::{client::ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsError};

impl MlsConversation {
    const EXPORTER_LABEL: &str = "exporter";
    // TODO: check if this can be a constant or if we need to pass the group state
    const EXPORTER_CONTEXT: &[u8] = &[];

    /// See [MlsCentral::export_secret_key]
    pub fn export_secret_key(&self, backend: &MlsCryptoProvider, key_length: usize) -> CryptoResult<Vec<u8>> {
        self.group
            .export_secret(backend, Self::EXPORTER_LABEL, Self::EXPORTER_CONTEXT, key_length)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    /// See [MlsCentral::get_client_ids]
    pub fn get_client_ids(&self) -> Vec<ClientId> {
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
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    /// * `key_length` - the length of the key to be derived. If the value is higher than the
    /// bounds of `u16` or the context hash * 255, an error will be returned
    ///
    /// # Errors
    /// OpenMls secret generation error or conversation not found
    pub fn export_secret_key(&self, conversation_id: &ConversationId, key_length: usize) -> CryptoResult<Vec<u8>> {
        self.get_conversation(conversation_id)?
            .export_secret_key(&self.mls_backend, key_length)
    }

    /// Exports the clients from a conversation
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// # Errors
    /// if the conversation can't be found
    pub fn get_client_ids(&self, conversation_id: &ConversationId) -> CryptoResult<Vec<ClientId>> {
        Ok(self.get_conversation(conversation_id)?.get_client_ids())
    }
}

#[cfg(test)]
pub mod export_tests {
    use std::usize;

    use crate::{
        error::{CryptoError, MlsError},
        mls::{credential::CredentialSupplier, MlsConversationConfiguration, ConversationId},
        test_utils::*,
    };
    use openmls::prelude::ExportSecretError;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn can_export_secret_key(credential: CredentialSupplier) {
        run_test_with_client_ids(
            credential,
            ["alice"],
            move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let result = alice_central.export_secret_key(&id, 128);
                    assert!(result.is_ok());
                    assert!(result.unwrap().len() == 128);
                })
            },
        )
        .await
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn cannot_export_secret_key_invalid_length(credential: CredentialSupplier) {
        run_test_with_client_ids(
            credential,
            ["alice"],
            move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let result = alice_central.export_secret_key(&id, usize::MAX);
                    assert!(matches!(
                        result.unwrap_err(),
                        CryptoError::MlsError(MlsError::MlsExportSecretError(ExportSecretError::KeyLengthTooLong))
                    ));
                })
            },
        )
        .await
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn cannot_export_secret_key_not_found(credential: CredentialSupplier) {
        run_test_with_client_ids(
            credential,
            ["alice"],
            move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let wrong = ConversationId::from("not_found");
                    let error = alice_central.get_client_ids(&wrong).unwrap_err();
                    assert!(matches!(error, CryptoError::ConversationNotFound(c) if c == wrong));
                })
            },
        )
        .await
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn can_get_client_ids(credential: CredentialSupplier) {
        run_test_with_client_ids(
            credential,
            ["alice"],
            move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let clients = alice_central.get_client_ids(&id).unwrap();
                    assert!(clients.len() == 1);
                })
            },
        )
        .await
    }

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn cannot_get_client_ids_not_found(credential: CredentialSupplier) {
        run_test_with_client_ids(
            credential,
            ["alice"],
            move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let wrong = ConversationId::from("not_found");
                    let error = alice_central.get_client_ids(&wrong).unwrap_err();
                    assert!(matches!(error, CryptoError::ConversationNotFound(c) if c == wrong));
                })
            },
        )
        .await
    }
}
