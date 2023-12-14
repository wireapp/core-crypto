use openmls::prelude::{MlsGroup, MlsMessageIn, MlsMessageInBody, Welcome};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Deserialize;

use core_crypto_keystore::entities::PersistedMlsPendingGroup;
use mls_crypto_provider::MlsCryptoProvider;

use crate::{
    group_store::GroupStore,
    prelude::{
        ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsConversationConfiguration,
        MlsCustomConfiguration, MlsError,
    },
};

impl MlsCentral {
    /// Create a conversation from a TLS serialized MLS Welcome message. The `MlsConversationConfiguration` used in this function will be the default implementation.
    ///
    /// # Arguments
    /// * `welcome` - a TLS serialized welcome message
    /// * `configuration` - configuration of the MLS conversation fetched from the Delivery Service
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// see [MlsCentral::process_welcome_message]
    #[cfg_attr(test, crate::dispotent)]
    pub async fn process_raw_welcome_message(
        &mut self,
        welcome: Vec<u8>,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<ConversationId> {
        let mut cursor = std::io::Cursor::new(welcome);
        let welcome = MlsMessageIn::tls_deserialize(&mut cursor).map_err(MlsError::from)?;
        self.process_welcome_message(welcome, custom_cfg).await
    }

    /// Create a conversation from a received MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - a `Welcome` message received as a result of a commit adding new members to a group
    /// * `configuration` - configuration of the group/conversation
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore of from OpenMls:
    /// * if no [openmls::key_packages::KeyPackage] can be read from the KeyStore
    /// * if the message can't be decrypted
    #[cfg_attr(test, crate::dispotent)]
    pub async fn process_welcome_message(
        &mut self,
        welcome: MlsMessageIn,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<ConversationId> {
        let welcome = match welcome.extract() {
            MlsMessageInBody::Welcome(welcome) => welcome,
            _ => return Err(CryptoError::ConsumerError),
        };
        let cs = welcome.ciphersuite().into();
        let configuration = MlsConversationConfiguration {
            ciphersuite: cs,
            custom: custom_cfg,
            ..Default::default()
        };
        let conversation =
            MlsConversation::from_welcome_message(welcome, configuration, &mut self.mls_backend, &mut self.mls_groups)
                .await?;

        let conversation_id = conversation.id.clone();
        self.mls_groups.insert(conversation_id.clone(), conversation);
        Ok(conversation_id)
    }
}

impl MlsConversation {
    // ? Do we need to provide the ratchet_tree to the MlsGroup? Does everything crumble down if we can't actually get it?
    /// Create the MLS conversation from an MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - welcome message to create the group from
    /// * `config` - group configuration
    /// * `backend` - the KeyStore to persist the group
    ///
    /// # Errors
    /// Errors can happen from OpenMls or from the KeyStore
    async fn from_welcome_message(
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
        backend: &mut MlsCryptoProvider,
        mls_groups: &mut GroupStore<MlsConversation>,
    ) -> CryptoResult<Self> {
        let mls_group_config = configuration.as_openmls_default_configuration(backend)?;

        let group = MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None).await;

        let group = match group {
            Err(openmls::prelude::WelcomeError::NoMatchingKeyPackage) => return Err(CryptoError::OrphanWelcome),
            _ => group.map_err(MlsError::from)?,
        };

        let id = ConversationId::from(group.group_id().as_slice());
        let existing_conversation = mls_groups.get_fetch(&id[..], backend.borrow_keystore_mut(), None).await;
        let conversation_exists = existing_conversation.ok().flatten().is_some();

        let pending_group = backend.key_store().find::<PersistedMlsPendingGroup>(&id[..]).await;
        let pending_group_exists = pending_group.ok().flatten().is_some();

        if conversation_exists || pending_group_exists {
            return Err(CryptoError::ConversationAlreadyExists(id));
        }

        Self::from_mls_group(group, configuration, backend).await
    }
}

#[cfg(test)]
pub mod tests {
    use openmls::prelude::{CreationFromExternalError, KeyPackageIn, KeyPackageVerifyError, LeafNodeValidationError, ProtocolVersion, WelcomeError};
    use openmls::treesync::errors::{LifetimeError, TreeSyncFromNodesError};
    use wasm_bindgen_test::*;

    use crate::mls::credential::tests::now;
    use crate::{mls::conversation::handshake::MlsConversationCreationMessage, test_utils::*};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn joining_from_welcome_should_prune_local_key_material(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    // has to be before the original key_package count because it creates one
                    let bob = bob_central.rand_key_package(&case).await;
                    // Keep track of the whatever amount was initially generated
                    let prev_count = bob_central.count_entities().await;

                    // Create a conversation from alice, where she invites bob
                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let MlsConversationCreationMessage { welcome, .. } =
                        alice_central.add_members_to_conversation(&id, vec![bob]).await.unwrap();

                    // Bob accepts the welcome message, and as such, it should prune the used keypackage from the store
                    bob_central
                        .process_welcome_message(welcome.into(), case.custom_cfg())
                        .await
                        .unwrap();

                    // Ensure we're left with 1 less keypackage bundle in the store, because it was consumed with the OpenMLS Welcome message
                    let next_count = bob_central.count_entities().await;
                    assert_eq!(next_count.key_package, prev_count.key_package - 1);
                    assert_eq!(next_count.hpke_private_key, prev_count.hpke_private_key - 1);
                    assert_eq!(next_count.encryption_keypair, prev_count.encryption_keypair - 1);
                })
            },
        )
            .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn process_welcome_should_fail_when_already_exists(case: TestCase) {
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
                    let bob = bob_central.rand_key_package(&case).await;
                    let welcome = alice_central
                        .add_members_to_conversation(&id, vec![bob])
                        .await
                        .unwrap()
                        .welcome;

                    // Meanwhile Bob creates a conversation with the exact same id as the one he's trying to join
                    bob_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let join_welcome = bob_central
                        .process_welcome_message(welcome.into(), case.custom_cfg())
                        .await;
                    assert!(matches!(join_welcome.unwrap_err(), CryptoError::ConversationAlreadyExists(i) if i == id));
                })
            },
        )
            .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn process_welcome_should_fail_when_key_package_expired(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    let expiration_time = core::time::Duration::from_secs(14);
                    let start = fluvio_wasm_timer::Instant::now();

                    let bob = bob_central
                        .rand_soon_to_expire_key_package(&case, expiration_time)
                        .await;

                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let add_bob_commit = alice_central.add_members_to_conversation(&id, vec![bob]).await.unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();

                    let elapsed = start.elapsed();
                    if expiration_time > elapsed {
                        async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                    }
                    // Bob is now expired

                    let process_welcome = bob_central
                        .process_welcome_message(add_bob_commit.welcome.into(), case.custom_cfg())
                        .await;
                    assert!(process_welcome.is_err());
                })
            },
        )
            .await;
    }

    // #[apply(all_cred_cipher)]
    // #[wasm_bindgen_test]
    #[async_std::test]
    pub async fn process_welcome_should_fail_when_other_member_expired(/*case: TestCase*/) {
        let case = TestCase::default();
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie"],
            move |[mut alice_central, mut bob_central, mut charlie_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    let expiration_time = core::time::Duration::from_secs(2);
                    let start = fluvio_wasm_timer::Instant::now();

                    let bob: KeyPackageIn = bob_central
                        .rand_soon_to_expire_key_package(&case, expiration_time)
                        .await;
                    let charlie = charlie_central.rand_key_package(&case).await;

                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    alice_central
                        .add_members_to_conversation(&id, vec![bob.clone()])
                        .await
                        .unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();
                    let add_charlie = alice_central
                        .add_members_to_conversation(&id, vec![charlie])
                        .await
                        .unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();

                    let elapsed = start.elapsed();
                    if expiration_time > elapsed {
                        async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(5)).await;
                    }
                    // Bob is now expired

                    assert!(matches!(
                        bob.standalone_validate(alice_central.mls_backend.crypto(), ProtocolVersion::default()).unwrap_err(),
                        KeyPackageVerifyError::InvalidLeafNode(LeafNodeValidationError::Lifetime(LifetimeError::NotCurrent))
                    ));

                    let process_welcome = charlie_central
                        .process_welcome_message(add_charlie.welcome.into(), case.custom_cfg())
                        .await;
                    assert!(matches!(
                        process_welcome.unwrap_err(),
                        CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::PublicGroupError(CreationFromExternalError::TreeSyncError(TreeSyncFromNodesError::LeafNodeValidationError(LeafNodeValidationError::Lifetime(LifetimeError::NotCurrent))))))
                    ));
                })
            },
        )
            .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn process_welcome_should_fail_when_one_x509_member_cert_expired(case: TestCase) {
        if case.is_x509() {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        let expiration_time = core::time::Duration::from_secs(14);
                        let start = fluvio_wasm_timer::Instant::now();
                        let expiration = now() + expiration_time;

                        bob_central
                            .rotate_credential(&case, "handle", "bob", None, Some(expiration))
                            .await;

                        let bob = bob_central.rand_key_package(&case).await;
                        let charlie = charlie_central.rand_key_package(&case).await;

                        alice_central.add_members_to_conversation(&id, vec![bob]).await.unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        let add_charlie = alice_central
                            .add_members_to_conversation(&id, vec![charlie])
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        let elapsed = start.elapsed();
                        if expiration_time > elapsed {
                            async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1))
                                .await;
                        }
                        // Bob is now expired

                        let process_welcome = charlie_central
                            .process_welcome_message(add_charlie.welcome.into(), case.custom_cfg())
                            .await;
                        assert!(process_welcome.is_err());
                    })
                },
            )
                .await;
        }
    }
}
