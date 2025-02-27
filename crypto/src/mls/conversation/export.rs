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

#[cfg(test)]
mod tests {
    use crate::{MlsErrorKind, test_utils::*};
    use openmls::prelude::ExportSecretError;

    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod export_secret {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_export_secret_key(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let key_length = 128;
                    let result = alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .export_secret_key(key_length)
                        .await;
                    assert!(result.is_ok());
                    assert_eq!(result.unwrap().len(), key_length);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn cannot_export_secret_key_invalid_length(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let result = alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .export_secret_key(usize::MAX)
                        .await;
                    let error = result.unwrap_err();
                    // let error = error.downcast_mls().unwrap().0;
                    assert!(innermost_source_matches!(
                        error,
                        MlsErrorKind::MlsExportSecretError(ExportSecretError::KeyLengthTooLong)
                    ));
                })
            })
            .await
        }
    }

    mod get_client_ids {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_get_client_ids(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    assert_eq!(alice_central.context.get_client_ids(&id).await.unwrap().len(), 1);

                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                    assert_eq!(alice_central.context.get_client_ids(&id).await.unwrap().len(), 2);
                })
            })
            .await
        }
    }
}
