use crate::{
    MlsError, RecursiveError,
    mls::credential::ext::CredentialExt,
    prelude::{MlsCentral, MlsCredentialType},
};

use openmls_traits::OpenMlsCryptoProvider;
use wire_e2e_identity::prelude::WireIdentityReader;

use crate::context::CentralContext;
use crate::prelude::MlsCiphersuite;
use openmls::{
    messages::group_info::VerifiableGroupInfo,
    prelude::{Credential, Node},
    treesync::RatchetTree,
};

use super::Result;

/// Indicates the state of a Conversation regarding end-to-end identity.
///
/// Note: this does not check pending state (pending commit, pending proposals) so it does not
/// consider members about to be added/removed
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum E2eiConversationState {
    /// All clients have a valid E2EI certificate
    Verified = 1,
    /// Some clients are either still Basic or their certificate is expired
    NotVerified,
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is returned.
    NotEnabled,
}

impl CentralContext {
    /// See [MlsCentral::e2ei_verify_group_state].
    pub async fn e2ei_verify_group_state(&self, group_info: VerifiableGroupInfo) -> Result<E2eiConversationState> {
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))?;
        let auth_service = mls_provider.authentication_service();
        auth_service.refresh_time_of_interest().await;
        let cs = group_info.ciphersuite().into();

        let is_sender = true; // verify the ratchet tree as sender to turn on hardened verification
        let Ok(rt) = group_info
            .take_ratchet_tree(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::root("getting mls provider"))?,
                is_sender,
            )
            .await
        else {
            return Ok(E2eiConversationState::NotVerified);
        };

        let credentials = rt.iter().filter_map(|n| match n {
            Some(Node::LeafNode(ln)) => Some(ln.credential()),
            _ => None,
        });

        let auth_service = auth_service.borrow().await;
        Ok(compute_state(cs, credentials, MlsCredentialType::X509, auth_service.as_ref()).await)
    }

    /// See [MlsCentral::get_credential_in_use].
    pub async fn get_credential_in_use(
        &self,
        group_info: VerifiableGroupInfo,
        credential_type: MlsCredentialType,
    ) -> Result<E2eiConversationState> {
        let cs = group_info.ciphersuite().into();
        // Not verifying the supplied the GroupInfo here could let attackers lure the clients about
        // the e2ei state of a conversation and as a consequence degrade this conversation for all
        // participants once joining it.
        // This 👇 verifies the GroupInfo and the RatchetTree btw
        let rt = group_info
            .take_ratchet_tree(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::root("getting mls provider"))?,
                false,
            )
            .await
            .map_err(MlsError::wrap("taking ratchet tree"))?;
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))?;
        let auth_service = mls_provider.authentication_service().borrow().await;
        get_credential_in_use_in_ratchet_tree(cs, rt, credential_type, auth_service.as_ref()).await
    }
}

impl MlsCentral {
    /// Verifies a Group state before joining it
    pub async fn e2ei_verify_group_state(&self, group_info: VerifiableGroupInfo) -> Result<E2eiConversationState> {
        self.mls_backend
            .authentication_service()
            .refresh_time_of_interest()
            .await;

        let cs = group_info.ciphersuite().into();

        let is_sender = true; // verify the ratchet tree as sender to turn on hardened verification
        let Ok(rt) = group_info.take_ratchet_tree(&self.mls_backend, is_sender).await else {
            return Ok(E2eiConversationState::NotVerified);
        };

        let credentials = rt.iter().filter_map(|n| match n {
            Some(Node::LeafNode(ln)) => Some(ln.credential()),
            _ => None,
        });

        Ok(compute_state(
            cs,
            credentials,
            MlsCredentialType::X509,
            self.mls_backend.authentication_service().borrow().await.as_ref(),
        )
        .await)
    }

    /// Gets the e2ei conversation state from a `GroupInfo`. Useful to check if the group has e2ei
    /// turned on or not before joining it.
    pub async fn get_credential_in_use(
        &self,
        group_info: VerifiableGroupInfo,
        credential_type: MlsCredentialType,
    ) -> Result<E2eiConversationState> {
        let cs = group_info.ciphersuite().into();
        // Not verifying the supplied the GroupInfo here could let attackers lure the clients about
        // the e2ei state of a conversation and as a consequence degrade this conversation for all
        // participants once joining it.
        // This 👇 verifies the GroupInfo and the RatchetTree btw
        let rt = group_info
            .take_ratchet_tree(&self.mls_backend, false)
            .await
            .map_err(MlsError::wrap("taking ratchet tree"))?;
        get_credential_in_use_in_ratchet_tree(
            cs,
            rt,
            credential_type,
            self.mls_backend.authentication_service().borrow().await.as_ref(),
        )
        .await
    }
}

async fn get_credential_in_use_in_ratchet_tree(
    ciphersuite: MlsCiphersuite,
    ratchet_tree: RatchetTree,
    credential_type: MlsCredentialType,
    env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
) -> Result<E2eiConversationState> {
    let credentials = ratchet_tree.iter().filter_map(|n| match n {
        Some(Node::LeafNode(ln)) => Some(ln.credential()),
        _ => None,
    });
    Ok(compute_state(ciphersuite, credentials, credential_type, env).await)
}

/// _credential_type will be used in the future to get the usage of VC Credentials, even Basics one.
/// Right now though, we do not need anything other than X509 so let's keep things simple.
pub(crate) async fn compute_state<'a>(
    ciphersuite: MlsCiphersuite,
    credentials: impl Iterator<Item = &'a Credential>,
    _credential_type: MlsCredentialType,
    env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
) -> E2eiConversationState {
    let mut is_e2ei = false;
    let mut state = E2eiConversationState::Verified;

    for credential in credentials {
        let Ok(Some(cert)) = credential.parse_leaf_cert() else {
            state = E2eiConversationState::NotVerified;
            if is_e2ei {
                break;
            }
            continue;
        };

        is_e2ei = true;

        let invalid_identity = cert.extract_identity(env, ciphersuite.e2ei_hash_alg()).is_err();

        use openmls_x509_credential::X509Ext as _;
        let is_time_valid = cert.is_time_valid().unwrap_or(false);
        let is_time_invalid = !is_time_valid;
        let is_revoked_or_invalid = env
            .map(|e| e.validate_cert_and_revocation(&cert).is_err())
            .unwrap_or(false);

        let is_invalid = invalid_identity || is_time_invalid || is_revoked_or_invalid;
        if is_invalid {
            state = E2eiConversationState::NotVerified;
            break;
        }
    }

    if is_e2ei {
        state
    } else {
        E2eiConversationState::NotEnabled
    }
}

#[cfg(test)]
mod tests {
    use crate::e2e_identity::rotate::tests::all::failsafe_ctx;
    use wasm_bindgen_test::*;

    use super::*;
    use crate::mls::conversation::Conversation as _;
    use crate::{
        prelude::{CertificateBundle, Client, MlsCredentialType},
        test_utils::*,
    };

    wasm_bindgen_test_configure!(run_in_browser);

    // testing the case where both Bob & Alice have the same Credential type
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn uniform_conversation_should_be_not_verified_when_basic(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();

                // That way the conversation creator (Alice) will have the same credential type as Bob
                let creator_ct = case.credential_type;
                alice_central
                    .context
                    .new_conversation(&id, creator_ct, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                match case.credential_type {
                    MlsCredentialType::Basic => {
                        let alice_state = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .e2ei_conversation_state()
                            .await
                            .unwrap();
                        let bob_state = bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .e2ei_conversation_state()
                            .await
                            .unwrap();
                        assert_eq!(alice_state, E2eiConversationState::NotEnabled);
                        assert_eq!(bob_state, E2eiConversationState::NotEnabled);

                        let gi = alice_central.get_group_info(&id).await;
                        let state = alice_central
                            .context
                            .get_credential_in_use(gi, MlsCredentialType::X509)
                            .await
                            .unwrap();
                        assert_eq!(state, E2eiConversationState::NotEnabled);
                    }
                    MlsCredentialType::X509 => {
                        let alice_state = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .e2ei_conversation_state()
                            .await
                            .unwrap();
                        let bob_state = bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .e2ei_conversation_state()
                            .await
                            .unwrap();
                        assert_eq!(alice_state, E2eiConversationState::Verified);
                        assert_eq!(bob_state, E2eiConversationState::Verified);

                        let gi = alice_central.get_group_info(&id).await;
                        let state = alice_central
                            .context
                            .get_credential_in_use(gi, MlsCredentialType::X509)
                            .await
                            .unwrap();
                        assert_eq!(state, E2eiConversationState::Verified);
                    }
                }
            })
        })
        .await
    }

    // testing the case where Bob & Alice have different Credential type
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn heterogeneous_conversation_should_be_not_verified(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let x509_test_chain_arc =
                        failsafe_ctx(&mut [&mut alice_central, &mut bob_central], case.signature_scheme()).await;

                    let x509_test_chain = x509_test_chain_arc.as_ref().as_ref().unwrap();

                    // That way the conversation creator (Alice) will have a different credential type than Bob
                    let alice_client = alice_central.context.mls_client().await.unwrap();
                    let alice_provider = alice_central.context.mls_provider().await.unwrap();
                    let creator_ct = match case.credential_type {
                        MlsCredentialType::Basic => {
                            let intermediate_ca = x509_test_chain.find_local_intermediate_ca();
                            let cert_bundle =
                                CertificateBundle::rand(&alice_client.id().await.unwrap(), intermediate_ca);
                            alice_client
                                .init_x509_credential_bundle_if_missing(
                                    &alice_provider,
                                    case.signature_scheme(),
                                    cert_bundle,
                                )
                                .await
                                .unwrap();
                            MlsCredentialType::X509
                        }
                        MlsCredentialType::X509 => {
                            alice_client
                                .init_basic_credential_bundle_if_missing(&alice_provider, case.signature_scheme())
                                .await
                                .unwrap();
                            MlsCredentialType::Basic
                        }
                    };

                    alice_central
                        .context
                        .new_conversation(&id, creator_ct, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    // since in that case both have a different credential type the conversation is always not verified
                    let alice_state = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .e2ei_conversation_state()
                        .await
                        .unwrap();
                    let bob_state = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .e2ei_conversation_state()
                        .await
                        .unwrap();
                    assert_eq!(alice_state, E2eiConversationState::NotVerified);
                    assert_eq!(bob_state, E2eiConversationState::NotVerified);

                    let gi = alice_central.get_group_info(&id).await;
                    let state = alice_central
                        .context
                        .get_credential_in_use(gi, MlsCredentialType::X509)
                        .await
                        .unwrap();
                    assert_eq!(state, E2eiConversationState::NotVerified);
                })
            },
        )
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_be_not_verified_when_one_expired(case: TestCase) {
        if !case.is_x509() {
            return;
        }
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();

                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                let expiration_time = core::time::Duration::from_secs(14);
                let start = web_time::Instant::now();

                let intermediate_ca = alice_central
                    .x509_test_chain
                    .as_ref()
                    .as_ref()
                    .expect("No x509 test chain")
                    .find_local_intermediate_ca();
                let cert = CertificateBundle::new_with_default_values(intermediate_ca, Some(expiration_time));
                let cb = Client::new_x509_credential_bundle(cert.clone()).unwrap();
                alice_central
                    .context
                    .conversation(&id)
                    .await
                    .unwrap()
                    .e2ei_rotate(Some(&cb))
                    .await
                    .unwrap();
                let commit = alice_central.mls_transport.latest_commit().await;
                bob_central
                    .context
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();

                let alice_client = alice_central.context.mls_client().await.unwrap();
                let alice_provider = alice_central.context.mls_provider().await.unwrap();
                // Needed because 'e2ei_rotate' does not do it directly and it's required for 'get_group_info'
                alice_client
                    .save_new_x509_credential_bundle(&alice_provider.keystore(), case.signature_scheme(), cert)
                    .await
                    .unwrap();

                // Need to fetch it before it becomes invalid & expires
                let gi = alice_central.get_group_info(&id).await;

                let elapsed = start.elapsed();
                // Give time to the certificate to expire
                if expiration_time > elapsed {
                    async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                }

                let alice_state = alice_central
                    .context
                    .conversation(&id)
                    .await
                    .unwrap()
                    .e2ei_conversation_state()
                    .await
                    .unwrap();
                let bob_state = bob_central
                    .context
                    .conversation(&id)
                    .await
                    .unwrap()
                    .e2ei_conversation_state()
                    .await
                    .unwrap();
                assert_eq!(alice_state, E2eiConversationState::NotVerified);
                assert_eq!(bob_state, E2eiConversationState::NotVerified);

                let state = alice_central
                    .context
                    .get_credential_in_use(gi, MlsCredentialType::X509)
                    .await
                    .unwrap();
                assert_eq!(state, E2eiConversationState::NotVerified);
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_be_not_verified_when_all_expired(case: TestCase) {
        if case.is_x509() {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let expiration_time = core::time::Duration::from_secs(14);
                    let start = web_time::Instant::now();
                    let alice_test_chain = alice_central.x509_test_chain.as_ref().as_ref().unwrap();

                    let alice_intermediate_ca = alice_test_chain.find_local_intermediate_ca();
                    let mut alice_cert = alice_test_chain
                        .actors
                        .iter()
                        .find(|actor| actor.name == "alice")
                        .unwrap()
                        .clone();
                    alice_intermediate_ca.update_end_identity(&mut alice_cert.certificate, Some(expiration_time));

                    let cert_bundle =
                        CertificateBundle::from_certificate_and_issuer(&alice_cert.certificate, alice_intermediate_ca);
                    let cb = Client::new_x509_credential_bundle(cert_bundle.clone()).unwrap();
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .e2ei_rotate(Some(&cb))
                        .await
                        .unwrap();

                    let alice_client = alice_central.client().await;
                    let alice_provider = alice_central.context.mls_provider().await.unwrap();

                    // Needed because 'e2ei_rotate' does not do it directly and it's required for 'get_group_info'
                    alice_client
                        .save_new_x509_credential_bundle(
                            &alice_provider.keystore(),
                            case.signature_scheme(),
                            cert_bundle,
                        )
                        .await
                        .unwrap();

                    let elapsed = start.elapsed();
                    // Give time to the certificate to expire
                    if expiration_time > elapsed {
                        async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                    }

                    let alice_state = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .e2ei_conversation_state()
                        .await
                        .unwrap();
                    assert_eq!(alice_state, E2eiConversationState::NotVerified);

                    // Need to fetch it before it becomes invalid & expires
                    let gi = alice_central.get_group_info(&id).await;

                    let state = alice_central
                        .context
                        .get_credential_in_use(gi, MlsCredentialType::X509)
                        .await
                        .unwrap();
                    assert_eq!(state, E2eiConversationState::NotVerified);
                })
            })
            .await
        }
    }
}
