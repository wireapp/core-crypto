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

use core_crypto_keystore::CryptoKeystoreMls;
use openmls::{
    group::{GroupId, MlsGroup},
    prelude::{MlsMessageOut, VerifiablePublicGroupState},
};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    prelude::{MlsConversation, MlsConversationConfiguration},
    CryptoError, CryptoResult, MlsCentral, MlsError,
};

impl MlsCentral {
    pub async fn join_by_external_commit(
        &self,
        group_state: VerifiablePublicGroupState,
    ) -> CryptoResult<(GroupId, MlsMessageOut)> {
        let credentials = self.mls_client.credentials();
        let (group, message) = MlsGroup::join_by_external_commit(
            &self.mls_backend,
            None,
            group_state,
            &MlsConversationConfiguration::default().as_openmls_default_configuration(),
            &[],
            credentials,
        )
        .await
        .map_err(MlsError::from)
        .map_err(CryptoError::from)?;

        let serialized = serde_json::to_string(&group)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)?;
        self.mls_backend
            .key_store()
            .mls_pending_groups_save(group.group_id().as_slice(), &serialized.into_bytes())
            .await
            .map_err(CryptoError::from)?;
        Ok((group.group_id().clone(), message))
    }

    pub async fn merge_pending_group_from_external_commit(
        &mut self,
        group_id: &[u8],
        configuration: MlsConversationConfiguration,
    ) -> CryptoResult<()> {
        let buf = self
            .mls_backend
            .key_store()
            .mls_pending_groups_load(group_id)
            .await
            .map_err(CryptoError::from)?;
        let mut mls_group = MlsGroup::load(&mut &buf[..])?;
        mls_group.merge_pending_commit().map_err(MlsError::from)?;
        let conversation = MlsConversation::from_mls_group(mls_group, configuration, &self.mls_backend).await?;
        self.mls_groups.insert(group_id.to_owned(), conversation);
        self.mls_backend
            .key_store()
            .mls_pending_groups_delete(group_id)
            .await
            .map_err(CryptoError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mls_crypto_provider::MlsCryptoProvider;

    use crate::{credential::CredentialSupplier, member::ConversationMember};

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    pub mod external_join {
        use super::*;
        use crate::{
            credential::{CertificateBundle, CredentialSupplier},
            error::MlsError,
            test_fixture_utils::*,
            test_utils::run_test_with_central,
            MlsConversation, MlsConversationConfiguration,
        };
        use core_crypto_keystore::{CryptoKeystoreError, CryptoKeystoreMls, MissingKeyErrorKind};
        use openmls::prelude::*;
        use wasm_bindgen_test::wasm_bindgen_test;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn test_join_by_external_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |mut central| {
                Box::pin(async move {
                    let central = &mut central[0];
                    let conversation_id = b"conversation".to_vec();
                    let (alice_backend, mut alice) = person("alice", credential).await;

                    // create alice's group
                    let mut alice_group = MlsConversation::create(
                        conversation_id.clone(),
                        alice.local_client_mut(),
                        MlsConversationConfiguration::default(),
                        &alice_backend,
                    )
                    .await
                    .unwrap();

                    // export the state
                    let state = alice_group
                        .group
                        .export_public_group_state(&alice_backend)
                        .await
                        .unwrap();
                    let pgs_encoded: Vec<u8> = state.tls_serialize_detached().expect("Error serializing PGS");

                    let verifiable_state = VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
                        .expect("Error deserializing PGS");

                    // try to join alice's group
                    let (_, message) = central.join_by_external_commit(verifiable_state).await.unwrap();

                    // alice acks the request and adds the new member
                    alice_group
                        .decrypt_message(&message.to_bytes().unwrap(), &alice_backend)
                        .await
                        .unwrap();
                    assert_eq!(alice_group.members().unwrap().len(), 2);

                    // we merge the commit and update the local state
                    central
                        .merge_pending_group_from_external_commit(
                            &conversation_id,
                            MlsConversationConfiguration::default(),
                        )
                        .await
                        .unwrap();

                    assert_eq!(central.group(&conversation_id).unwrap().members().unwrap().len(), 2);

                    let error = central
                        .mls_backend
                        .key_store()
                        .mls_pending_groups_load(&conversation_id)
                        .await;
                    assert!(matches!(
                        error.unwrap_err(),
                        CryptoKeystoreError::MissingKeyInStore(MissingKeyErrorKind::MlsPendingGroup)
                    ));
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn test_join_by_external_commit_bad_epoch(credential: CredentialSupplier) {
            run_test_with_central(credential, move |mut central| {
                Box::pin(async move {
                    let central = &mut central[0];
                    let conversation_id = b"conversation".to_vec();
                    let (alice_backend, mut alice) = person("alice", credential).await;
                    let (_, bob) = person("bob", credential).await;

                    // create alice group
                    let mut alice_group = MlsConversation::create(
                        conversation_id.clone(),
                        alice.local_client_mut(),
                        MlsConversationConfiguration::default(),
                        &alice_backend,
                    )
                    .await
                    .unwrap();

                    // export the group from alice
                    let state = alice_group
                        .group
                        .export_public_group_state(&alice_backend)
                        .await
                        .unwrap();
                    let pgs_encoded: Vec<u8> = state.tls_serialize_detached().expect("Error serializing PGS");

                    let verifiable_state = VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
                        .expect("Error deserializing PGS");

                    // try to make and external join into alice's group
                    let (_, message) = central.join_by_external_commit(verifiable_state).await.unwrap();

                    // alice adds a new member to the group before receiving an ack from the
                    // external join
                    alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();

                    // receive the ack from the external join with outdated epoch
                    // should fail because of the wrong epoch
                    let result = alice_group
                        .decrypt_message(&message.to_bytes().unwrap(), &alice_backend)
                        .await;
                    assert!(matches!(
                        result.unwrap_err(),
                        crate::CryptoError::MlsError(MlsError::MlsParseMessageError(
                            ParseMessageError::ValidationError(ValidationError::WrongEpoch)
                        ))
                    ));
                    assert_eq!(alice_group.members().unwrap().len(), 2);
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn test_join_by_external_commit_no_pending(credential: CredentialSupplier) {
            run_test_with_central(credential, move |mut central| {
                Box::pin(async move {
                    let central = &mut central[0];
                    let conversation_id = b"conversation".to_vec();
                    // try to merge an inexisting pending group
                    let result = central
                        .merge_pending_group_from_external_commit(
                            &conversation_id,
                            MlsConversationConfiguration::default(),
                        )
                        .await;

                    assert!(matches!(
                        result.unwrap_err(),
                        crate::CryptoError::KeyStoreError(CryptoKeystoreError::MissingKeyInStore(
                            MissingKeyErrorKind::MlsPendingGroup
                        ))
                    ));
                })
            })
            .await
        }
    }

    async fn person(name: &str, credential: CredentialSupplier) -> (MlsCryptoProvider, ConversationMember) {
        let backend = MlsCryptoProvider::try_new_in_memory(name).await.unwrap();
        let member = ConversationMember::random_generate(&backend, credential).await.unwrap();
        (backend, member)
    }
}
