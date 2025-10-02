use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use openmls::prelude::{Credential as MlsCredential, CredentialWithKey, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;

pub(crate) mod crl;
mod error;
pub(crate) mod ext;
pub(crate) mod typ;
pub(crate) mod x509;

pub(crate) use error::{Error, Result};

use crate::{ClientId, MlsError};

/// A cryptographic credential.
///
/// This is tied to a particular client via either its client id or certificate bundle,
/// depending on its credential type, but is independent of any client instance or storage.
///
/// To attach to a particular client instance and store, see [`Session::add_credential`][crate::Session::add_credential].
#[derive(core_crypto_macros::Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    /// MLS internal credential. Stores the credential type.
    pub(crate) mls_credential: MlsCredential,
    /// Public and private keys, and the signature scheme.
    #[sensitive]
    pub(crate) signature_key_pair: SignatureKeyPair,
    /// Earliest valid time of creation for this credential.
    ///
    /// This is represented as seconds after the unix epoch.
    ///
    /// Only meaningful for X509, where it is the "valid_from" claim of the leaf credential.
    /// For basic credentials, this is always 0.
    pub(crate) created_at: u64,
}

impl Credential {
    /// Generate a basic credential.
    ///
    /// The result is independent of any client instance and the database; it lives in memory only.
    pub fn basic(signature_scheme: SignatureScheme, client_id: &ClientId, crypto: impl OpenMlsCrypto) -> Result<Self> {
        let (private, public) = crypto
            .signature_key_gen(signature_scheme)
            .map_err(MlsError::wrap("generating signature keys for basic credential"))?;
        let mls_credential = MlsCredential::new_basic(client_id.0.clone());
        let signature_key_pair = SignatureKeyPair::from_raw(signature_scheme, private, public);

        Ok(Self {
            mls_credential,
            signature_key_pair,
            created_at: 0,
        })
    }

    /// Get the Openmls Credential type.
    ///
    /// This stores the credential type (basic/x509).
    pub fn credential(&self) -> &MlsCredential {
        &self.mls_credential
    }

    /// Get a reference to the `SignatureKeyPair`.
    pub(crate) fn signature_key(&self) -> &SignatureKeyPair {
        &self.signature_key_pair
    }

    /// Generate a `CredentialWithKey`, which combines the credential type with the public portion of the keypair.
    pub fn to_mls_credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.mls_credential.clone(),
            signature_key: self.signature_key_pair.to_public_vec().into(),
        }
    }
}

impl From<Credential> for CredentialWithKey {
    fn from(cb: Credential) -> Self {
        Self {
            credential: cb.mls_credential,
            signature_key: cb.signature_key_pair.public().into(),
        }
    }
}

impl Eq for Credential {}
impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        self.mls_credential == other.mls_credential && self.created_at == other.created_at && {
            let sk = &self.signature_key_pair;
            let ok = &other.signature_key_pair;
            sk.signature_scheme() == ok.signature_scheme() && sk.public() == ok.public() && sk.private() == ok.private()
        }
    }
}

impl Hash for Credential {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.created_at.hash(state);
        self.signature_key_pair.signature_scheme().hash(state);
        self.signature_key_pair.public().hash(state);
        // self.mls_credential.credential_type().hash(state); // not implemented for Reasons, idk
        self.mls_credential.identity().hash(state);
        match self.credential().mls_credential() {
            openmls::prelude::MlsCredentialType::X509(cert) => {
                cert.certificates.hash(state);
            }
            openmls::prelude::MlsCredentialType::Basic(_) => {}
        };
    }
}

impl Ord for Credential {
    fn cmp(&self, other: &Self) -> Ordering {
        self.created_at.cmp(&other.created_at)
    }
}

impl PartialOrd for Credential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// TODO: ensure certificate signature must match the group's ciphersuite ; fails otherwise. Tracking issue: WPB-9632
// Requires more than 1 ciphersuite supported at the moment.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mls_crypto_provider::PkiKeypair;

    use super::{x509::CertificateBundle, *};
    use crate::{
        ClientIdentifier, E2eiConversationState, MlsCredentialType,
        mls::{conversation::Conversation as _, credential::x509::CertificatePrivateKey},
        test_utils::{
            x509::{CertificateParams, X509TestChain},
            *,
        },
    };

    #[apply(all_cred_cipher)]
    async fn basic_clients_can_send_messages(case: TestContext) {
        if !case.is_basic() {
            return;
        }
        let [alice, bob] = case.sessions_basic().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
    }

    #[apply(all_cred_cipher)]
    async fn certificate_clients_can_send_messages(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let [alice, bob] = case.sessions_x509().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
    }

    #[apply(all_cred_cipher)]
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
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
    }

    #[apply(all_cred_cipher)]
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
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);

            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::Verified
            );

            let elapsed = start.elapsed();
            // Give time to the certificate to expire
            if expiration_time > elapsed {
                smol::Timer::after(expiration_time - elapsed + core::time::Duration::from_secs(2)).await;
            }

            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::NotVerified
            );
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    async fn should_not_fail_but_degrade_when_basic_joins(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        Box::pin(async {
            let ([alice, bob], [charlie]) = case.sessions_mixed_credential_types().await;
            let conversation = case.create_conversation([&alice, &bob]).await;

            // this should work since the certificate is not yet expired
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
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
                .invite_with_credential_type_notify(MlsCredentialType::Basic, [&charlie])
                .await;

            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::NotVerified
            );
            assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);
            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::NotVerified
            );
        })
        .await;
    }

    #[apply(all_cred_cipher)]
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
}
