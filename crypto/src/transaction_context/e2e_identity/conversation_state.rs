use crate::{
    MlsError, RecursiveError,
    prelude::{MlsCredentialType, Session},
};

use openmls_traits::OpenMlsCryptoProvider;

use crate::transaction_context::TransactionContext;
use openmls::{messages::group_info::VerifiableGroupInfo, prelude::Node};

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

impl TransactionContext {
    /// See [crate::mls::session::Session::e2ei_verify_group_state].
    pub async fn e2ei_verify_group_state(&self, group_info: VerifiableGroupInfo) -> Result<E2eiConversationState> {
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        let auth_service = mls_provider.authentication_service();
        auth_service.refresh_time_of_interest().await;
        let cs = group_info.ciphersuite().into();

        let is_sender = true; // verify the ratchet tree as sender to turn on hardened verification
        let Ok(rt) = group_info
            .take_ratchet_tree(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting mls provider"))?,
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
        Ok(Session::compute_conversation_state(cs, credentials, MlsCredentialType::X509, auth_service.as_ref()).await)
    }

    /// See [crate::mls::session::Session::get_credential_in_use].
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
                    .map_err(RecursiveError::transaction("getting mls provider"))?,
                false,
            )
            .await
            .map_err(MlsError::wrap("taking ratchet tree"))?;
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        let auth_service = mls_provider.authentication_service().borrow().await;
        Session::get_credential_in_use_in_ratchet_tree(cs, rt, credential_type, auth_service.as_ref())
            .await
            .map_err(RecursiveError::mls_client("getting credentials in use"))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        prelude::{CertificateBundle, MlsCredentialType, Session},
        test_utils::*,
    };

    // testing the case where both Bob & Alice have the same Credential type
    #[apply(all_cred_cipher)]
    async fn uniform_conversation_should_be_not_verified_when_basic(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            match case.credential_type {
                MlsCredentialType::Basic => {
                    let alice_state = conversation.e2ei_state().await;
                    let bob_state = conversation.e2ei_state_of(&bob).await;
                    assert_eq!(alice_state, E2eiConversationState::NotEnabled);
                    assert_eq!(bob_state, E2eiConversationState::NotEnabled);

                    let state = conversation.e2ei_state_via_group_info().await;
                    assert_eq!(state, E2eiConversationState::NotEnabled);
                }
                MlsCredentialType::X509 => {
                    let alice_state = conversation.e2ei_state().await;
                    let bob_state = conversation.e2ei_state_of(&bob).await;
                    assert_eq!(alice_state, E2eiConversationState::Verified);
                    assert_eq!(bob_state, E2eiConversationState::Verified);

                    let state = conversation.e2ei_state_via_group_info().await;
                    assert_eq!(state, E2eiConversationState::Verified);
                }
            }
        })
        .await
    }

    // testing the case where Bob & Alice have different Credential type
    #[apply(all_cred_cipher)]
    async fn heterogeneous_conversation_should_be_not_verified(case: TestContext) {
        let ([x509_session], [basic_session]) = case.sessions_mixed_credential_types().await;
        Box::pin(async move {
            // That way the conversation creator (Alice) will have a different credential type than Bob
            let (alice, bob, alice_credential_type) = match case.credential_type {
                MlsCredentialType::Basic => (x509_session, basic_session, MlsCredentialType::X509),
                MlsCredentialType::X509 => (basic_session, x509_session, MlsCredentialType::Basic),
            };

            let conversation = case
                .create_heterogeneous_conversation(alice_credential_type, case.credential_type, [&alice, &bob])
                .await;

            // since in that case both have a different credential type the conversation is always not verified
            let alice_state = conversation.e2ei_state().await;
            let bob_state = conversation.e2ei_state_of(&bob).await;
            assert_eq!(alice_state, E2eiConversationState::NotVerified);
            assert_eq!(bob_state, E2eiConversationState::NotVerified);

            let state = conversation.e2ei_state_via_group_info().await;
            assert_eq!(state, E2eiConversationState::NotVerified);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_be_not_verified_when_one_expired(case: TestContext) {
        if !case.is_x509() {
            return;
        }

        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            let expiration_time = core::time::Duration::from_secs(14);
            let start = web_time::Instant::now();

            let intermediate_ca = alice.x509_chain_unchecked().find_local_intermediate_ca();
            let cert = CertificateBundle::new_with_default_values(intermediate_ca, Some(expiration_time));
            let cb = Session::new_x509_credential_bundle(cert.clone()).unwrap();
            let conversation = conversation.e2ei_rotate_notify(Some(&cb)).await;

            let alice_client = alice.transaction.session().await.unwrap();
            let alice_provider = alice.transaction.mls_provider().await.unwrap();
            // Needed because 'e2ei_rotate' does not do it directly and it's required for 'get_group_info'
            alice_client
                .save_new_x509_credential_bundle(&alice_provider.keystore(), case.signature_scheme(), cert)
                .await
                .unwrap();

            // Need to fetch it before it becomes invalid & expires
            let gi = conversation.export_group_info().await;

            let elapsed = start.elapsed();
            // Give time to the certificate to expire
            if expiration_time > elapsed {
                async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
            }

            let alice_state = conversation.e2ei_state().await;
            let bob_state = conversation.e2ei_state_of(&bob).await;
            assert_eq!(alice_state, E2eiConversationState::NotVerified);
            assert_eq!(bob_state, E2eiConversationState::NotVerified);

            let state = alice
                .transaction
                .get_credential_in_use(gi, MlsCredentialType::X509)
                .await
                .unwrap();
            assert_eq!(state, E2eiConversationState::NotVerified);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_be_not_verified_when_all_expired(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let alice_user_id = uuid::Uuid::new_v4();
        let [client_id] = case.x509_client_ids_for_user(&alice_user_id);
        let [alice] = case.sessions_x509_with_client_ids([client_id]).await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            let expiration_time = core::time::Duration::from_secs(14);
            let start = web_time::Instant::now();
            let alice_test_chain = alice.x509_chain_unchecked();

            let alice_intermediate_ca = alice_test_chain.find_local_intermediate_ca();
            let mut alice_cert = alice_test_chain
                .actors
                .iter()
                .find(|actor| actor.name == alice_user_id.to_string())
                .unwrap()
                .clone();
            alice_intermediate_ca.update_end_identity(&mut alice_cert.certificate, Some(expiration_time));

            let cert_bundle =
                CertificateBundle::from_certificate_and_issuer(&alice_cert.certificate, alice_intermediate_ca);
            let cb = Session::new_x509_credential_bundle(cert_bundle.clone()).unwrap();
            let conversation = conversation.e2ei_rotate_notify(Some(&cb)).await;

            let alice_client = alice.session().await;
            let alice_provider = alice.transaction.mls_provider().await.unwrap();

            // Needed because 'e2ei_rotate' does not do it directly and it's required for 'get_group_info'
            alice_client
                .save_new_x509_credential_bundle(&alice_provider.keystore(), case.signature_scheme(), cert_bundle)
                .await
                .unwrap();

            let elapsed = start.elapsed();
            // Give time to the certificate to expire
            if expiration_time > elapsed {
                async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
            }

            let alice_state = conversation.e2ei_state().await;
            assert_eq!(alice_state, E2eiConversationState::NotVerified);

            // Need to fetch it before it becomes invalid & expires
            let state = conversation.e2ei_state_via_group_info().await;
            assert_eq!(state, E2eiConversationState::NotVerified);
        })
        .await
    }
}
