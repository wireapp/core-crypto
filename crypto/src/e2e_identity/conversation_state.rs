use crate::{
    mls::credential::ext::CredentialExt,
    prelude::{ConversationId, CryptoResult, MlsCentral, MlsConversation, MlsCredentialType},
    MlsError,
};

use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::OpenMlsCryptoProvider;
use wire_e2e_identity::prelude::WireIdentityReader;

use openmls::{
    messages::group_info::VerifiableGroupInfo,
    prelude::{Credential, Node},
    treesync::RatchetTree,
};

/// Indicates the state of a Conversation regarding end-to-end identity.
/// Note: this does not check pending state (pending commit, pending proposals) so it does not
/// consider members about to be added/removed
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum E2eiConversationState {
    /// All clients have a valid E2EI certificate
    Verified,
    /// Some clients are either still Basic or their certificate is expired
    NotVerified,
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is returned.
    NotEnabled,
}

impl MlsCentral {
    /// Indicates when to mark a conversation as not verified i.e. when not all its members have a X509
    /// Credential generated by Wire's end-to-end identity enrollment
    pub async fn e2ei_conversation_state(&mut self, id: &ConversationId) -> CryptoResult<E2eiConversationState> {
        let conversation = self.get_conversation(id).await?;

        let conversation_lock = conversation.read().await;

        Ok(conversation_lock.e2ei_conversation_state(&self.mls_backend))
    }

    /// Gets the e2ei conversation state from a `GroupInfo`. Useful to check if the group has e2ei
    /// turned on or not before joining it.
    pub fn get_credential_in_use(
        &self,
        group_info: VerifiableGroupInfo,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<E2eiConversationState> {
        // Not verifying the supplied the GroupInfo here could let attackers lure the clients about
        // the e2ei state of a conversation and as a consequence degrade this conversation for all
        // participants once joining it.
        // This 👇 verifies the GroupInfo and the RatchetTree btw
        let rt = group_info
            .take_ratchet_tree(&self.mls_backend)
            .map_err(MlsError::from)?;
        self.get_credential_in_use_in_ratchet_tree(rt, credential_type)
    }

    fn get_credential_in_use_in_ratchet_tree(
        &self,
        ratchet_tree: RatchetTree,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<E2eiConversationState> {
        let credentials = ratchet_tree.iter().filter_map(|n| match n {
            Some(Node::LeafNode(ln)) => Some(ln.credential()),
            _ => None,
        });
        Ok(compute_state(credentials, &self.mls_backend, credential_type))
    }
}

impl MlsConversation {
    fn e2ei_conversation_state(&self, backend: &MlsCryptoProvider) -> E2eiConversationState {
        compute_state(self.group.members_credentials(), backend, MlsCredentialType::X509)
    }
}

/// _credential_type will be used in the future to get the usage of VC Credentials, even Basics one.
/// Right now though, we do not need anything other than X509 so let's keep things simple.
pub(crate) fn compute_state<'a>(
    credentials: impl Iterator<Item = &'a Credential>,
    backend: &MlsCryptoProvider,
    _credential_type: MlsCredentialType,
) -> E2eiConversationState {
    let mut one_valid = false;
    let mut all_expired = true;

    let state = credentials.fold(E2eiConversationState::Verified, |mut state, credential| {
        if let Ok(Some(cert)) = credential.parse_leaf_cert() {
            let invalid_identity = cert.extract_identity().is_err();

            // TODO: this is incomplete and has to be applied to the whole cert chain
            use openmls_x509_credential::X509Ext as _;
            let is_time_valid = cert.is_time_valid().unwrap_or(false);
            let is_time_invalid = !is_time_valid;
            let is_revoked_or_invalid = backend
                .authentication_service()
                .borrow()
                .map(|pki_env| {
                    if let Some(pki_env) = &*pki_env {
                        pki_env.validate_cert_and_revocation(&cert).is_err()
                    } else {
                        false
                    }
                })
                .unwrap_or_default();

            all_expired &= is_time_invalid;

            let is_invalid = invalid_identity || is_time_invalid || is_revoked_or_invalid;
            if is_invalid {
                state = E2eiConversationState::NotVerified;
            } else {
                one_valid = true
            }
        } else {
            all_expired = false;
            state = E2eiConversationState::NotVerified;
        };
        state
    });

    match (one_valid, all_expired) {
        (false, true) => E2eiConversationState::NotVerified,
        (false, _) => E2eiConversationState::NotEnabled,
        _ => state,
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        mls::credential::tests::now,
        prelude::{CertificateBundle, Client, MlsCredentialType},
        test_utils::*,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    // testing the case where both Bob & Alice have the same Credential type
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn uniform_conversation_should_be_not_verified_when_basic(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    // That way the conversation creator (Alice) will have the same credential type as Bob
                    let creator_ct = case.credential_type;
                    alice_central
                        .new_conversation(&id, creator_ct, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                    match case.credential_type {
                        MlsCredentialType::Basic => {
                            let alice_state = alice_central.e2ei_conversation_state(&id).await.unwrap();
                            let bob_state = bob_central.e2ei_conversation_state(&id).await.unwrap();
                            assert_eq!(alice_state, E2eiConversationState::NotEnabled);
                            assert_eq!(bob_state, E2eiConversationState::NotEnabled);

                            let gi = alice_central.get_group_info(&id).await;
                            let state = alice_central
                                .get_credential_in_use(gi, MlsCredentialType::X509)
                                .unwrap();
                            assert_eq!(state, E2eiConversationState::NotEnabled);
                        }
                        MlsCredentialType::X509 => {
                            let alice_state = alice_central.e2ei_conversation_state(&id).await.unwrap();
                            let bob_state = bob_central.e2ei_conversation_state(&id).await.unwrap();
                            assert_eq!(alice_state, E2eiConversationState::Verified);
                            assert_eq!(bob_state, E2eiConversationState::Verified);

                            let gi = alice_central.get_group_info(&id).await;
                            let state = alice_central
                                .get_credential_in_use(gi, MlsCredentialType::X509)
                                .unwrap();
                            assert_eq!(state, E2eiConversationState::Verified);
                        }
                    }
                })
            },
        )
        .await
    }

    // testing the case where Bob & Alice have different Credential type
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn heterogeneous_conversation_should_be_not_verified(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    // That way the conversation creator (Alice) will have a different credential type than Bob
                    let creator_client = alice_central.mls_client.as_mut().unwrap();
                    let creator_ct = match case.credential_type {
                        MlsCredentialType::Basic => {
                            let cert_bundle = CertificateBundle::rand(
                                creator_client.id(),
                                case.cfg.ciphersuite.signature_algorithm(),
                            );
                            creator_client
                                .init_x509_credential_bundle_if_missing(
                                    &alice_central.mls_backend,
                                    case.signature_scheme(),
                                    cert_bundle,
                                )
                                .await
                                .unwrap();
                            MlsCredentialType::X509
                        }
                        MlsCredentialType::X509 => {
                            creator_client
                                .init_basic_credential_bundle_if_missing(
                                    &alice_central.mls_backend,
                                    case.signature_scheme(),
                                )
                                .await
                                .unwrap();
                            MlsCredentialType::Basic
                        }
                    };

                    alice_central
                        .new_conversation(&id, creator_ct, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                    // since in that case both have a different credential type the conversation is always not verified
                    let alice_state = alice_central.e2ei_conversation_state(&id).await.unwrap();
                    let bob_state = bob_central.e2ei_conversation_state(&id).await.unwrap();
                    assert_eq!(alice_state, E2eiConversationState::NotVerified);
                    assert_eq!(bob_state, E2eiConversationState::NotVerified);

                    let gi = alice_central.get_group_info(&id).await;
                    let state = alice_central
                        .get_credential_in_use(gi, MlsCredentialType::X509)
                        .unwrap();
                    assert_eq!(state, E2eiConversationState::NotVerified);
                })
            },
        )
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_be_not_verified_when_one_expired(case: TestCase) {
        if case.is_x509() {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                        let expiration_time = core::time::Duration::from_secs(14);
                        let start = fluvio_wasm_timer::Instant::now();
                        let expiration = now() + expiration_time;

                        let builder = wire_e2e_identity::prelude::WireIdentityBuilder {
                            not_after: expiration,
                            ..Default::default()
                        };
                        let cert = CertificateBundle::new_from_builder(builder, case.signature_scheme());
                        let cb = Client::new_x509_credential_bundle(cert.clone()).unwrap();
                        let commit = alice_central.e2ei_rotate(&id, &cb).await.unwrap().commit;
                        alice_central.commit_accepted(&id).await.unwrap();
                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // Needed because 'e2ei_rotate' does not do it directly and it's required for 'get_group_info'
                        alice_central
                            .mls_client
                            .as_mut()
                            .unwrap()
                            .save_new_x509_credential_bundle(&alice_central.mls_backend, case.signature_scheme(), cert)
                            .await
                            .unwrap();

                        // Need to fetch it before it becomes invalid & expires
                        let gi = alice_central.get_group_info(&id).await;

                        let elapsed = start.elapsed();
                        // Give time to the certificate to expire
                        if expiration_time > elapsed {
                            async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1))
                                .await;
                        }

                        let alice_state = alice_central.e2ei_conversation_state(&id).await.unwrap();
                        let bob_state = bob_central.e2ei_conversation_state(&id).await.unwrap();
                        assert_eq!(alice_state, E2eiConversationState::NotVerified);
                        assert_eq!(bob_state, E2eiConversationState::NotVerified);

                        let state = alice_central
                            .get_credential_in_use(gi, MlsCredentialType::X509)
                            .unwrap();
                        assert_eq!(state, E2eiConversationState::NotVerified);
                    })
                },
            )
            .await
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_be_not_verified_when_all_expired(case: TestCase) {
        if case.is_x509() {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let expiration_time = core::time::Duration::from_secs(14);
                    let start = fluvio_wasm_timer::Instant::now();
                    let expiration = now() + expiration_time;

                    let builder = wire_e2e_identity::prelude::WireIdentityBuilder {
                        not_after: expiration,
                        ..Default::default()
                    };
                    let cert = CertificateBundle::new_from_builder(builder, case.signature_scheme());
                    let cb = Client::new_x509_credential_bundle(cert.clone()).unwrap();
                    alice_central.e2ei_rotate(&id, &cb).await.unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();

                    // Needed because 'e2ei_rotate' does not do it directly and it's required for 'get_group_info'
                    alice_central
                        .mls_client
                        .as_mut()
                        .unwrap()
                        .save_new_x509_credential_bundle(&alice_central.mls_backend, case.signature_scheme(), cert)
                        .await
                        .unwrap();

                    let elapsed = start.elapsed();
                    // Give time to the certificate to expire
                    if expiration_time > elapsed {
                        async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                    }

                    let alice_state = alice_central.e2ei_conversation_state(&id).await.unwrap();
                    assert_eq!(alice_state, E2eiConversationState::NotVerified);

                    // Need to fetch it before it becomes invalid & expires
                    let gi = alice_central.get_group_info(&id).await;

                    let state = alice_central
                        .get_credential_in_use(gi, MlsCredentialType::X509)
                        .unwrap();
                    assert_eq!(state, E2eiConversationState::NotVerified);
                })
            })
            .await
        }
    }
}
