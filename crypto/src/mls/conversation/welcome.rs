use std::borrow::BorrowMut;

use crate::{
    e2e_identity::init_certificates::NewCrlDistributionPoint,
    group_store::GroupStore,
    mls::{
        context::CentralContext,
        credential::crl::{extract_crl_uris_from_group, get_new_crl_distribution_points},
    },
    prelude::{
        ConversationId, CryptoError, CryptoResult, MlsConversation, MlsConversationConfiguration,
        MlsCustomConfiguration, MlsError,
    },
};
use core_crypto_keystore::{connection::FetchFromDatabase, entities::PersistedMlsPendingGroup};
use mls_crypto_provider::TransactionalCryptoProvider;
use openmls::prelude::{MlsGroup, MlsMessageIn, MlsMessageInBody, Welcome};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Deserialize;

/// Contains everything client needs to know after decrypting an (encrypted) Welcome message
#[derive(Debug)]
pub struct WelcomeBundle {
    /// MLS Group Id
    pub id: ConversationId,
    /// New CRL distribution points that appeared by the introduction of a new credential
    pub crl_new_distribution_points: NewCrlDistributionPoint,
}

impl CentralContext {
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
        &self,
        welcome: Vec<u8>,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<WelcomeBundle> {
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
        &self,
        welcome: MlsMessageIn,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<WelcomeBundle> {
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
        let mls_provider = self.mls_provider().await?;
        let mut mls_groups = self.mls_groups().await?;
        let conversation =
            MlsConversation::from_welcome_message(welcome, configuration, &mls_provider, mls_groups.borrow_mut())
                .await?;

        // We wait for the group to be created then we iterate through all members
        let crl_new_distribution_points =
            get_new_crl_distribution_points(&mls_provider, extract_crl_uris_from_group(&conversation.group)?).await?;

        let id = conversation.id.clone();
        mls_groups.insert(id.clone(), conversation);

        Ok(WelcomeBundle {
            id,
            crl_new_distribution_points,
        })
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
        backend: &TransactionalCryptoProvider,
        mls_groups: &mut GroupStore<MlsConversation>,
    ) -> CryptoResult<Self> {
        let mls_group_config = configuration.as_openmls_default_configuration()?;

        let group = MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None).await;

        let group = match group {
            Err(openmls::prelude::WelcomeError::NoMatchingKeyPackage)
            | Err(openmls::prelude::WelcomeError::NoMatchingEncryptionKey) => return Err(CryptoError::OrphanWelcome),
            _ => group.map_err(MlsError::from)?,
        };

        let id = ConversationId::from(group.group_id().as_slice());
        let existing_conversation = mls_groups.get_fetch(&id[..], &backend.transaction(), None).await;
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
mod tests {
    use wasm_bindgen_test::*;

    use crate::{prelude::MlsConversationCreationMessage, test_utils::*};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn joining_from_welcome_should_prune_local_key_material(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    // has to be before the original key_package count because it creates one
                    let bob = bob_central.mls_central.rand_key_package(&case).await;
                    // Keep track of the whatever amount was initially generated
                    let prev_count = bob_central.mls_central.count_entities().await;

                    // Create a conversation from alice, where she invites bob
                    alice_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let MlsConversationCreationMessage { welcome, .. } = alice_central
                        .mls_central
                        .add_members_to_conversation(&id, vec![bob])
                        .await
                        .unwrap();

                    // Bob accepts the welcome message, and as such, it should prune the used keypackage from the store
                    bob_central
                        .mls_central
                        .process_welcome_message(welcome.into(), case.custom_cfg())
                        .await
                        .unwrap();

                    // Ensure we're left with 1 less keypackage bundle in the store, because it was consumed with the OpenMLS Welcome message
                    let next_count = bob_central.mls_central.count_entities().await;
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
    async fn process_welcome_should_fail_when_already_exists(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let bob = bob_central.mls_central.rand_key_package(&case).await;
                    let welcome = alice_central
                        .mls_central
                        .add_members_to_conversation(&id, vec![bob])
                        .await
                        .unwrap()
                        .welcome;

                    // Meanwhile Bob creates a conversation with the exact same id as the one he's trying to join
                    bob_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let join_welcome = bob_central
                        .mls_central
                        .process_welcome_message(welcome.into(), case.custom_cfg())
                        .await;
                    assert!(matches!(join_welcome.unwrap_err(), CryptoError::ConversationAlreadyExists(i) if i == id));
                })
            },
        )
        .await;
    }
}
