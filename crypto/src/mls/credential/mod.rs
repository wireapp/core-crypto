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

use core_crypto_keystore::entities::StoredCredential;
use openmls::prelude::{Credential as MlsCredential, CredentialWithKey, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::Deserialize as _;

pub(crate) use self::error::Result;
pub use self::{
    credential_ref::{CredentialRef, FindFilters, FindFiltersBuilder},
    credential_type::CredentialType,
    error::Error,
};
use crate::{Ciphersuite, ClientId, ClientIdRef, ClientIdentifier, MlsError, RecursiveError, mls_provider::CRYPTO};

/// A cryptographic credential.
///
/// This is tied to a particular client via either its client id or certificate bundle,
/// depending on its credential type, but is independent of any client instance or storage.
///
/// To attach to a particular client instance and store, see
/// [`TransactionContext::add_credential`][crate::transaction_context::TransactionContext::add_credential].
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

impl TryFrom<&StoredCredential> for Credential {
    type Error = Error;

    fn try_from(stored_credential: &StoredCredential) -> Result<Credential> {
        let mls_credential = MlsCredential::tls_deserialize(&mut stored_credential.credential.as_slice())
            .map_err(Error::tls_deserialize("mls credential"))?;
        let ciphersuite = Ciphersuite::try_from(stored_credential.ciphersuite)
            .map_err(RecursiveError::mls("loading ciphersuite from db"))?;
        let signature_key_pair = openmls_basic_credential::SignatureKeyPair::from_raw(
            ciphersuite.signature_algorithm(),
            stored_credential.private_key.to_owned(),
            stored_credential.public_key.to_owned(),
        );
        let credential_type = mls_credential
            .credential_type()
            .try_into()
            .map_err(RecursiveError::mls_credential("loading credential from db"))?;
        let earliest_validity = stored_credential.created_at;
        Ok(Credential {
            ciphersuite,
            signature_key_pair,
            credential_type,
            mls_credential,
            earliest_validity,
        })
    }
}

impl Credential {
    /// Generate a basic credential.
    ///
    /// The result is independent of any client instance and the database; it lives in memory only.
    ///
    /// The earliest validity of this credential is always 0. It will be updated once the credential is added to a
    /// session.
    pub fn basic(ciphersuite: Ciphersuite, client_id: ClientId) -> Result<Self> {
        let signature_scheme = ciphersuite.signature_algorithm();
        let (private_key, public_key) = CRYPTO
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
    pub(crate) fn from_identifier(identifier: &ClientIdentifier, ciphersuite: Ciphersuite) -> Result<Self> {
        match identifier {
            ClientIdentifier::Basic(client_id) => Self::basic(ciphersuite, client_id.clone()),
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

    use super::{x509::CertificateBundle, *};
    use crate::{
        ClientIdentifier, CredentialType, E2eiConversationState,
        mls::{conversation::Conversation as _, credential::x509::CertificatePrivateKey},
        mls_provider::PkiKeypair,
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
        let (alice, bob) = match case.credential_type {
            CredentialType::Basic => (x509_session, basic_session),
            CredentialType::X509 => (basic_session, x509_session),
        };

        let conversation = case.create_conversation([&alice, &bob]).await;
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
    async fn should_fail_when_signature_key_doesnt_match_certificate_public_key(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
        let x509_intermediate = x509_test_chain.find_local_intermediate_ca();

        let certs = CertificateBundle::rand(&"alice".into(), x509_intermediate);
        let new_pki_kp = PkiKeypair::rand_unchecked(case.signature_scheme());

        let eve_key = CertificatePrivateKey::new(new_pki_kp.signing_key_bytes());
        let cb = CertificateBundle {
            certificate_chain: certs.certificate_chain,
            private_key: eve_key,
            signature_scheme: case.ciphersuite().signature_algorithm(),
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
                .invite_with_credential_notify([(&charlie, &charlie.initial_credential)])
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
    // pub fn now() -> wire_e2e_identity::OffsetDateTime {
    //     let now_since_epoch = now_std().as_secs() as i64;
    //     wire_e2e_identity::OffsetDateTime::from_unix_timestamp(now_since_epoch).unwrap()
    // }
    pub(crate) fn now_std() -> std::time::Duration {
        let now = web_time::SystemTime::now();
        now.duration_since(web_time::UNIX_EPOCH).unwrap()
    }
}
