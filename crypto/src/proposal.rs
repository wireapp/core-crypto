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

use crate::{ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{KeyPackage, MlsGroup, MlsMessageOut};
use openmls_traits::OpenMlsCryptoProvider;

/// Internal representation of proposal to ease further additions
pub enum MlsProposal {
    /// Requests that a client with a specified KeyPackage be added to the group
    Add(KeyPackage),
    /// Similar mechanism to Add with the distinction that it replaces
    /// the sender's LeafNode in the tree instead of adding a new leaf to the tree
    Update,
    /// Requests that the member with LeafNodeRef removed be removed from the group
    Remove(ClientId),
}

impl MlsProposal {
    /// Creates a new proposal within the specified `MlsGroup`
    async fn create(self, backend: &MlsCryptoProvider, group: &mut MlsGroup) -> CryptoResult<MlsMessageOut> {
        match self {
            MlsProposal::Add(key_package) => group
                .propose_add_member(backend, &key_package)
                .await
                .map_err(MlsError::from),
            MlsProposal::Update => group.propose_self_update(backend, None).await.map_err(MlsError::from),
            MlsProposal::Remove(client_id) => {
                let href = group
                    .members()
                    .into_iter()
                    .find(|kp| kp.credential().identity() == client_id.as_slice())
                    .ok_or(CryptoError::ClientNotFound(client_id))
                    .and_then(|kp| {
                        kp.hash_ref(backend.crypto())
                            .map_err(MlsError::from)
                            .map_err(CryptoError::from)
                    })?;
                group
                    .propose_remove_member(backend, &href)
                    .await
                    .map_err(MlsError::from)
            }
        }
        .map_err(CryptoError::from)
    }
}

impl MlsCentral {
    /// Creates a new proposal within a group
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `proposal` - the proposal do be added in the group
    ///
    /// # Return type
    /// A message will be returned with the proposal that was created
    ///
    /// # Errors
    /// If the conversation is not found, an error will be returned. Errors from OpenMls can be
    /// returned as well, when for example there's a commit pending to be merged
    pub async fn new_proposal(
        &mut self,
        conversation: ConversationId,
        proposal: MlsProposal,
    ) -> CryptoResult<MlsMessageOut> {
        let conversation = Self::get_conversation_mut(&mut self.mls_groups, &conversation)?;
        proposal.create(&self.mls_backend, &mut conversation.group).await
    }
}

#[cfg(test)]
pub mod proposal_tests {
    use super::*;
    use crate::{
        credential::{CertificateBundle, CredentialSupplier},
        test_fixture_utils::*,
        test_utils::run_test_with_central,
        CryptoError, *,
    };
    use openmls::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    pub mod add {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_succeed(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let conversation_id = b"conversation".to_vec();
                    central
                        .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let kp = key_package(&central, credential);
                    let proposal = MlsProposal::Add(kp.key_package().to_owned());
                    let add_proposal = central.new_proposal(conversation_id, proposal);
                    let _ = add_proposal.await.unwrap();
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_unknown_conversation(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    central.mls_groups.clear();
                    let kp = key_package(&central, credential);
                    let conversation_id = b"unknown".to_vec();
                    let proposal = MlsProposal::Add(kp.key_package().to_owned());
                    let add_proposal = central.new_proposal(conversation_id.clone(), proposal).await;
                    match add_proposal {
                        Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                        _ => panic!(""),
                    }
                })
            })
            .await
        }
    }

    pub mod update {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_succeed(credential: CredentialSupplier) {
            run_test_with_central(credential, |[mut central]| {
                Box::pin(async move {
                    let conversation_id = b"conversation".to_vec();
                    central
                        .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let update_proposal = central.new_proposal(conversation_id, MlsProposal::Update);
                    let _ = update_proposal.await.unwrap();
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_unknown_conversation(credential: CredentialSupplier) {
            run_test_with_central(credential, |[mut central]| {
                Box::pin(async move {
                    central.mls_groups.clear();
                    let conversation_id = b"conversation".to_vec();
                    let update_proposal = central.new_proposal(conversation_id.clone(), MlsProposal::Update).await;
                    match update_proposal {
                        Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                        _ => panic!(""),
                    }
                })
            })
            .await
        }
    }

    pub mod remove {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_succeed(credential: CredentialSupplier) {
            run_test_with_central(credential, |[mut central]| {
                Box::pin(async move {
                    let conversation_id = b"conversation".to_vec();
                    central
                        .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let conversation = central.get_conversation(&conversation_id).unwrap();
                    let client_id =
                        ClientId::from(conversation.group.members().get(0).unwrap().credential().identity());
                    let remove_proposal = central
                        .new_proposal(conversation_id, MlsProposal::Remove(client_id))
                        .await;
                    let _ = remove_proposal.unwrap();
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_unknown_client(credential: CredentialSupplier) {
            run_test_with_central(credential, |[mut central]| {
                Box::pin(async move {
                    let conversation_id = b"conversation".to_vec();
                    central
                        .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let client_id = ClientId::from(vec![]);
                    let remove_proposal = central
                        .new_proposal(conversation_id, MlsProposal::Remove(client_id.clone()))
                        .await;
                    match remove_proposal {
                        Err(CryptoError::ClientNotFound(cli_id)) => assert_eq!(cli_id, client_id),
                        _ => panic!(""),
                    }
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_unknown_conversation(credential: CredentialSupplier) {
            run_test_with_central(credential, |[mut central]| {
                Box::pin(async move {
                    central.mls_groups.clear();
                    let conversation_id = b"conversation".to_vec();
                    let client_id = ClientId::from(vec![]);
                    let remove_proposal = central
                        .new_proposal(conversation_id.clone(), MlsProposal::Remove(client_id))
                        .await;
                    match remove_proposal {
                        Err(CryptoError::ConversationNotFound(conv_id)) => assert_eq!(conv_id, conversation_id),
                        _ => panic!(""),
                    }
                })
            })
            .await
        }
    }

    fn key_package(central: &MlsCentral, credential: CredentialSupplier) -> KeyPackageBundle {
        let id = b"test";
        let credential = if let Some(cert) = credential() {
            Client::generate_x509_credential_bundle(&id.to_vec().into(), cert.certificate_chain, cert.private_key)
        } else {
            Client::generate_basic_credential_bundle(&id.to_vec().into(), &central.mls_backend)
        }
        .unwrap();
        KeyPackageBundle::new(
            &[MlsCiphersuite::default().0],
            &credential,
            &central.mls_backend,
            vec![],
        )
        .unwrap()
    }
}
