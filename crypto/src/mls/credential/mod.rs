//! This module focuses on [`Credential`]s: cryptographic assertions of identity.
//!
//! Credentials can be basic, or based on an x509 certificate chain.

pub(crate) mod credential_ref;
pub(crate) mod credential_type;
pub(crate) mod crl;
mod error;
pub(crate) mod ext;
mod persistence;
pub(crate) mod x509;

use openmls::prelude::{Credential as MlsCredential, CredentialWithKey, MlsCredentialType, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;

pub(crate) use self::error::Result;
pub use self::{
    credential_ref::{CredentialRef, FindFilters, FindFiltersBuilder},
    credential_type::CredentialType,
    error::Error,
};
use crate::{
    Ciphersuite, ClientId, ClientIdRef, ClientIdentifier, MlsError, RecursiveError,
    mls::credential::{error::CredentialValidationError, ext::CredentialExt as _},
};

/// A cryptographic credential.
///
/// This is tied to a particular client via either its client id or certificate bundle,
/// depending on its credential type, but is independent of any client instance or storage.
///
/// To attach to a particular client instance and store, see
/// [`TransactionContext::add_credential`][crate::transaction_context::TransactionContext::add_credential].
///
/// Note: the current database design makes some questionable assumptions:
///
/// - There are always either 0 or 1 `StoredSignatureKeypair` instances in the DB for a particular signature scheme
/// - There may be multiple `StoredCredential` instances in the DB for a particular signature scheme, but they all share
///   the same `ClientId` / signing key. In other words, the same signing keypair is _reused_ between credentials.
/// - Practically, the code ensures that there is a 1:1 correspondence between signing scheme <-> identity/credential,
///   and we need to maintain that property for now.
///
/// Work is ongoing to fix those limitations; see WPB-20844. Until that is resolved, we enforce those restrictions by
/// raising errors as required to preserve DB integrity.
#[derive(core_crypto_macros::Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    /// Ciphersuite used by this credential
    pub(crate) ciphersuite: Ciphersuite,
    /// Credential type
    pub(crate) credential_type: CredentialType,
    /// MLS internal credential. Stores the MLS credential
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
    pub(crate) earliest_validity: u64,
}

impl Credential {
    /// Ensure that the provided `MlsCredential` matches the client id / signature key provided
    pub(crate) fn validate_mls_credential(
        mls_credential: &MlsCredential,
        client_id: &ClientIdRef,
        signature_key: &SignatureKeyPair,
    ) -> Result<(), CredentialValidationError> {
        match mls_credential.mls_credential() {
            MlsCredentialType::Basic(_) => {
                if client_id.as_slice() != mls_credential.identity() {
                    return Err(CredentialValidationError::WrongCredential);
                }
            }
            MlsCredentialType::X509(cert) => {
                let certificate_public_key = cert
                    .extract_public_key()
                    .map_err(RecursiveError::mls_credential(
                        "extracting public key from certificate in credential validation",
                    ))?
                    .ok_or(CredentialValidationError::NoPublicKey)?;
                if signature_key.public() != certificate_public_key {
                    return Err(CredentialValidationError::WrongCredential);
                }
            }
        }
        Ok(())
    }

    /// Generate a basic credential.
    ///
    /// The result is independent of any client instance and the database; it lives in memory only.
    ///
    /// The earliest validity of this credential is always 0. It will be updated once the credential is added to a session.
    pub fn basic(ciphersuite: Ciphersuite, client_id: ClientId, crypto: impl OpenMlsCrypto) -> Result<Self> {
        let signature_scheme = ciphersuite.signature_algorithm();
        let (private_key, public_key) = crypto
            .signature_key_gen(signature_scheme)
            .map_err(MlsError::wrap("generating signature key"))?;
        let signature_key_pair = SignatureKeyPair::from_raw(signature_scheme, private_key, public_key);

        Ok(Self {
            ciphersuite,
            credential_type: CredentialType::Basic,
            mls_credential: MlsCredential::new_basic(client_id.into_inner()),
            signature_key_pair,
            earliest_validity: 0,
        })
    }

    /// Get the Openmls Credential type.
    ///
    /// This stores the credential type (basic/x509).
    pub fn mls_credential(&self) -> &MlsCredential {
        &self.mls_credential
    }

    /// Get the credential type
    pub fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    /// Get a reference to the `SignatureKeyPair`.
    pub(crate) fn signature_key(&self) -> &SignatureKeyPair {
        &self.signature_key_pair
    }

    /// Get the signature scheme
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_key_pair.signature_scheme()
    }

    /// Get the ciphersuite
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// Generate a `CredentialWithKey`, which combines the credential type with the public portion of the keypair.
    pub fn to_mls_credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.mls_credential.clone(),
            signature_key: self.signature_key_pair.to_public_vec().into(),
        }
    }

    /// Earliest valid time of creation for this credential.
    ///
    /// This is represented as seconds after the unix epoch.
    ///
    /// Only meaningful for X509, where it is the "valid_from" claim of the leaf credential.
    /// For basic credentials, this is always 0 when the credential is first created.
    /// It is updated upon being persisted to the database.
    pub fn earliest_validity(&self) -> u64 {
        self.earliest_validity
    }

    /// Get the client ID associated with this credential
    pub fn client_id(&self) -> &ClientIdRef {
        self.mls_credential.identity().into()
    }
}

impl Credential {
    /// Create a credential from an identifier
    // currently only used in test code, but generally applicable
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn from_identifier(
        identifier: &ClientIdentifier,
        ciphersuite: Ciphersuite,
        crypto: impl OpenMlsCrypto,
    ) -> Result<Self> {
        match identifier {
            ClientIdentifier::Basic(client_id) => Self::basic(ciphersuite, client_id.clone(), crypto),
            ClientIdentifier::X509(certs) => {
                let signature_scheme = ciphersuite.signature_algorithm();
                let cert = certs
                    .get(&signature_scheme)
                    .ok_or(Error::SignatureSchemeNotPresentInX509Identity(signature_scheme))?;
                Self::x509(ciphersuite, cert.clone())
            }
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
        self.mls_credential == other.mls_credential && self.earliest_validity == other.earliest_validity && {
            let sk = &self.signature_key_pair;
            let ok = &other.signature_key_pair;
            sk.signature_scheme() == ok.signature_scheme() && sk.public() == ok.public()
            // public key equality implies private key equality
        }
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
        ClientIdentifier, CredentialType, E2eiConversationState,
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
            CredentialType::Basic => (x509_session, basic_session, CredentialType::X509),
            CredentialType::X509 => (basic_session, x509_session, CredentialType::Basic),
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
        let bob_key_package = bob.new_keypackage(&case).await;
        let conversation = case.create_conversation([&alice]).await;
        let err = conversation
            .guard()
            .await
            .add_members([bob_key_package.into()].into())
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
                .invite_with_credential_type_notify(CredentialType::Basic, [&charlie])
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
