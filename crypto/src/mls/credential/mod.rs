use openmls::prelude::{Credential, CredentialWithKey};
use openmls_basic_credential::SignatureKeyPair;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

pub(crate) mod crl;
mod error;
pub(crate) mod ext;
pub(crate) mod typ;
pub(crate) mod x509;

pub(crate) use error::{Error, Result};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CredentialBundle {
    pub(crate) credential: Credential,
    pub(crate) signature_key: SignatureKeyPair,
    pub(crate) created_at: u64,
}

impl CredentialBundle {
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    pub(crate) fn signature_key(&self) -> &SignatureKeyPair {
        &self.signature_key
    }

    pub fn to_mls_credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.credential.clone(),
            signature_key: self.signature_key.to_public_vec().into(),
        }
    }
}

impl From<CredentialBundle> for CredentialWithKey {
    fn from(cb: CredentialBundle) -> Self {
        Self {
            credential: cb.credential,
            signature_key: cb.signature_key.public().into(),
        }
    }
}

impl Clone for CredentialBundle {
    fn clone(&self) -> Self {
        Self {
            credential: self.credential.clone(),
            signature_key: SignatureKeyPair::from_raw(
                self.signature_key.signature_scheme(),
                self.signature_key.private().to_vec(),
                self.signature_key.to_public_vec(),
            ),
            created_at: self.created_at,
        }
    }
}

impl Eq for CredentialBundle {}
impl PartialEq for CredentialBundle {
    fn eq(&self, other: &Self) -> bool {
        self.credential.eq(&other.credential)
            && self.created_at.eq(&other.created_at)
            && self
                .signature_key
                .signature_scheme()
                .eq(&other.signature_key.signature_scheme())
            && self.signature_key.public().eq(other.signature_key.public())
    }
}

impl Hash for CredentialBundle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.created_at.hash(state);
        self.signature_key.signature_scheme().hash(state);
        self.signature_key.public().hash(state);
        self.credential().identity().hash(state);
        match self.credential().mls_credential() {
            openmls::prelude::MlsCredentialType::X509(cert) => {
                cert.certificates.hash(state);
            }
            openmls::prelude::MlsCredentialType::Basic(_) => {}
        };
    }
}

impl Ord for CredentialBundle {
    fn cmp(&self, other: &Self) -> Ordering {
        self.created_at.cmp(&other.created_at)
    }
}

impl PartialOrd for CredentialBundle {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// TODO: ensure certificate signature must match the group's ciphersuite ; fails otherwise. Tracking issue: WPB-9632
// Requires more than 1 ciphersuite supported at the moment.
#[cfg(test)]
mod tests {
    use mls_crypto_provider::PkiKeypair;
    use std::collections::HashMap;
    use wasm_bindgen_test::*;

    use super::x509::CertificateBundle;
    use super::*;
    use crate::mls::conversation::Conversation as _;
    use crate::{
        RecursiveError,
        mls::credential::x509::CertificatePrivateKey,
        prelude::{ClientIdentifier, ConversationId, E2eiConversationState, MlsCredentialType},
        test_utils::{
            x509::{CertificateParams, X509TestChain},
            *,
        },
    };

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn basic_clients_can_send_messages(case: TestContext) {
        if !case.is_basic() {
            return;
        }
        let [alice, bob] = case.sessions_basic().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        assert!(conversation.is_functional_with([&alice, &bob]).await);
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn certificate_clients_can_send_messages(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let [alice, bob] = case.sessions_x509().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        assert!(conversation.is_functional_with([&alice, &bob]).await);
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn heterogeneous_clients_can_send_messages(case: TestContext) {
        // check that both credentials can initiate/join a group
        let ([x509_session], [basic_session]) = case.sessions_mixed_credential_types().await;
        // That way the conversation creator (Alice) will have a different credential type than Bob
        let (alice, bob, alice_credential_type) = match case.credential_type {
            MlsCredentialType::Basic => (x509_session, basic_session, MlsCredentialType::X509),
            MlsCredentialType::X509 => (basic_session, x509_session, MlsCredentialType::Basic),
        };

        let conversation = case
            .create_heterogeneous_conversation(alice_credential_type, case.credential_type, [&alice, &bob])
            .await;
        assert!(conversation.is_functional_with([&alice, &bob]).await);
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_is_empty(case: TestContext) {
        let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

        let x509_intermediate = x509_test_chain.find_local_intermediate_ca();

        let mut certs = CertificateBundle::rand(&"alice".into(), x509_intermediate);
        certs.certificate_chain = vec![];
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), certs)]));

        let err = SessionContext::new_with_identifier(&case, alice_identifier, Some(&x509_test_chain))
            .await
            .unwrap_err();
        assert!(innermost_source_matches!(err, Error::InvalidIdentity));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_has_a_single_self_signed(case: TestContext) {
        use crate::MlsErrorKind;

        if !case.is_x509() {
            return;
        }
        let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

        let (_alice_identifier, alice_cert) = x509_test_chain.issue_simple_certificate_bundle("alice", None);

        let new_cert = alice_cert
            .pki_keypair
            .re_sign(&alice_cert.certificate, &alice_cert.certificate, None)
            .unwrap();
        let mut alice_cert = alice_cert.clone();
        alice_cert.certificate = new_cert;
        let cb = CertificateBundle::from_self_signed_certificate(&alice_cert);
        let alice_identifier = ClientIdentifier::X509([(case.signature_scheme(), cb)].into());

        let alice = SessionContext::new_with_identifier(&case, alice_identifier, Some(&x509_test_chain))
            .await
            .unwrap();
        let [bob] = case.sessions_x509().await;
        let bob_key_package = bob.rand_key_package(&case).await;
        let conversation = case.create_conversation([&alice]).await;
        let err = conversation
            .guard()
            .await
            .add_members([bob_key_package].into())
            .await
            .unwrap_err();
        assert!(innermost_source_matches!(err, MlsErrorKind::MlsAddMembersError(_)));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_signature_key_doesnt_match_certificate_public_key(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
        let x509_intermediate = x509_test_chain.find_local_intermediate_ca();

        let certs = CertificateBundle::rand(&"alice".into(), x509_intermediate);
        let new_pki_kp = PkiKeypair::rand_unchecked(case.signature_scheme());

        let eve_key = CertificatePrivateKey {
            value: new_pki_kp.signing_key_bytes(),
            signature_scheme: case.ciphersuite().signature_algorithm(),
        };
        let cb = CertificateBundle {
            certificate_chain: certs.certificate_chain,
            private_key: eve_key,
        };
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), cb)]));

        let err = SessionContext::new_with_identifier(&case, alice_identifier, Some(&x509_test_chain))
            .await
            .unwrap_err();
        assert!(innermost_source_matches!(
            err,
            crate::MlsErrorKind::MlsCryptoError(openmls::prelude::CryptoError::MismatchKeypair),
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_not_fail_but_degrade_when_certificate_expired(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        Box::pin(async move {
            let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

            let expiration_time = core::time::Duration::from_secs(14);
            let start = web_time::Instant::now();

            let (alice_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("alice", None);
            let (bob_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("bob", Some(expiration_time));
            let alice = SessionContext::new_with_identifier(&case, alice_identifier, Some(&x509_test_chain))
                .await
                .unwrap();
            let bob = SessionContext::new_with_identifier(&case, bob_identifier, Some(&x509_test_chain))
                .await
                .unwrap();

            let conversation = case.create_conversation([&alice, &bob]).await;
            // this should work since the certificate is not yet expired
            assert!(conversation.is_functional_with([&alice, &bob]).await);

            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::Verified
            );

            let elapsed = start.elapsed();
            // Give time to the certificate to expire
            if expiration_time > elapsed {
                async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(2)).await;
            }

            assert!(conversation.is_functional_with([&alice, &bob]).await);
            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::NotVerified
            );
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_not_fail_but_degrade_when_basic_joins(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        Box::pin(async {
            let ([alice, bob], [charlie]) = case.sessions_mixed_credential_types().await;
            let conversation = case.create_conversation([&alice, &bob]).await;

            // this should work since the certificate is not yet expired
            assert!(conversation.is_functional_with([&alice, &bob]).await);
            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::Verified
            );
            assert_eq!(
                conversation
                    .guard_of(&bob)
                    .await
                    .e2ei_conversation_state()
                    .await
                    .unwrap(),
                E2eiConversationState::Verified
            );

            // Charlie is a basic client that tries to join (i.e. emulates guest links in Wire)
            let conversation = conversation
                .invite_with_credential_type(MlsCredentialType::Basic, [&charlie])
                .await;

            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::NotVerified
            );
            assert!(conversation.is_functional_with([&alice, &bob, &charlie]).await);
            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::NotVerified
            );
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_not_valid_yet(case: TestContext) {
        use crate::MlsErrorKind;

        if !case.is_x509() {
            return;
        }
        let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

        let tomorrow = now_std() + core::time::Duration::from_secs(3600 * 24);
        let local_ca = x509_test_chain.find_local_intermediate_ca();
        let alice_cert = {
            let name = "alice";
            let common_name = format!("{name} Smith");
            let handle = format!("{}_wire", name.to_lowercase());
            let client_id: String = crate::e2e_identity::id::QualifiedE2eiClientId::generate_with_domain("wire.com")
                .try_into()
                .unwrap();
            local_ca.create_and_sign_end_identity(CertificateParams {
                common_name: Some(common_name.clone()),
                handle: Some(handle.clone()),
                client_id: Some(client_id.clone()),
                validity_start: Some(tomorrow),
                ..Default::default()
            })
        };
        let cb = CertificateBundle::from_certificate_and_issuer(&alice_cert, local_ca);
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), cb)]));
        let err = SessionContext::new_with_identifier(&case, alice_identifier, Some(&x509_test_chain))
            .await
            .unwrap_err();

        assert!(innermost_source_matches!(
            err,
            MlsErrorKind::MlsCryptoError(openmls::prelude::CryptoError::ExpiredCertificate),
        ))
    }

    /// In order to be WASM-compatible
    // pub fn now() -> wire_e2e_identity::prelude::OffsetDateTime {
    //     let now_since_epoch = now_std().as_secs() as i64;
    //     wire_e2e_identity::prelude::OffsetDateTime::from_unix_timestamp(now_since_epoch).unwrap()
    // }
    pub(crate) fn now_std() -> std::time::Duration {
        let now = web_time::SystemTime::now();
        now.duration_since(web_time::UNIX_EPOCH).unwrap()
    }

    async fn try_talk(
        case: &TestContext,
        x509_test_chain: Option<&X509TestChain>,
        creator_identifier: ClientIdentifier,
        guest_identifier: ClientIdentifier,
    ) -> Result<(SessionContext, SessionContext, ConversationId)> {
        let id = conversation_id();

        let creator_ct = match &creator_identifier {
            ClientIdentifier::Basic(_) => MlsCredentialType::Basic,
            ClientIdentifier::X509(_) => MlsCredentialType::X509,
        };
        let guest_ct = match &guest_identifier {
            ClientIdentifier::Basic(_) => MlsCredentialType::Basic,
            ClientIdentifier::X509(_) => MlsCredentialType::X509,
        };

        let creator = SessionContext::new_with_identifier(case, creator_identifier, x509_test_chain)
            .await
            .map_err(RecursiveError::root("new session context"))?;

        let guest = SessionContext::new_with_identifier(case, guest_identifier, x509_test_chain)
            .await
            .map_err(RecursiveError::root("new session context"))?;

        creator
            .transaction
            .new_conversation(&id, creator_ct, case.cfg.clone())
            .await
            .map_err(RecursiveError::transaction("creating new transaction"))?;

        let guest_kp = guest.rand_key_package_of_type(case, guest_ct).await;
        creator
            .invite_all_members(case, &id, [(&guest, guest_kp)])
            .await
            .map_err(RecursiveError::test())?;

        creator.try_talk_to(&id, &guest).await.map_err(RecursiveError::test())?;
        Ok((creator, guest, id))
    }
}
