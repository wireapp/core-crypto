use openmls::prelude::{CredentialWithKey, OpenMlsCrypto};
use openmls_traits::OpenMlsCryptoProvider;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

pub(crate) mod crl;
pub(crate) mod ext;
pub(crate) mod typ;
pub(crate) mod x509;

use openmls::prelude::Credential;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;
use openmls_x509_credential::CertificateKeyPair;

use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::{CertificateBundle, Client, ClientId, CryptoResult, MlsError};

#[derive(Debug)]
pub struct CredentialBundle {
    pub(crate) credential: Credential,
    pub(crate) signature_key: SignatureKeyPair,
    pub(crate) created_at: u64,
}

impl CredentialBundle {
    pub fn credential(&self) -> &Credential {
        &self.credential
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

impl Client {
    pub(crate) fn new_basic_credential_bundle(
        id: &ClientId,
        sc: SignatureScheme,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<CredentialBundle> {
        let (sk, pk) = backend.crypto().signature_key_gen(sc).map_err(MlsError::from)?;

        let signature_key = SignatureKeyPair::from_raw(sc, sk, pk);
        let credential = Credential::new_basic(id.to_vec());
        let cb = CredentialBundle {
            credential,
            signature_key,
            created_at: 0,
        };

        Ok(cb)
    }

    pub(crate) fn new_x509_credential_bundle(cert: CertificateBundle) -> CryptoResult<CredentialBundle> {
        let created_at = cert.get_created_at()?;
        let (sk, ..) = cert.private_key.into_parts();
        let chain = cert.certificate_chain;

        let kp = CertificateKeyPair::new(sk, chain.clone()).map_err(MlsError::from)?;

        let credential = Credential::new_x509(chain).map_err(MlsError::from)?;

        let cb = CredentialBundle {
            credential,
            signature_key: kp.0,
            created_at,
        };
        Ok(cb)
    }
}

// TODO: ensure certificate signature must match the group's ciphersuite ; fails otherwise.
// Requires more than 1 ciphersuite supported at the moment.
#[cfg(test)]
pub mod tests {
    use mls_crypto_provider::PkiKeypair;
    use std::collections::HashMap;
    use wasm_bindgen_test::*;

    use crate::{
        mls::credential::x509::CertificatePrivateKey,
        prelude::{
            ClientIdentifier, ConversationId, CryptoError, E2eiConversationState, MlsCentral, MlsCentralConfiguration,
            MlsCredentialType, INITIAL_KEYING_MATERIAL_COUNT,
        },
        test_utils::{
            x509::{CertificateParams, X509TestChain},
            *,
        },
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn basic_clients_can_send_messages(case: TestCase) {
        if case.is_basic() {
            let alice_identifier = ClientIdentifier::Basic("alice".into());
            let bob_identifier = ClientIdentifier::Basic("bob".into());
            assert!(try_talk(&case, None, alice_identifier, bob_identifier).await.is_ok());
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn certificate_clients_can_send_messages(case: TestCase) {
        if case.is_x509() {
            let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

            let (alice_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("alice", None);
            let (bob_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("bob", None);
            assert!(
                try_talk(&case, Some(&x509_test_chain), alice_identifier, bob_identifier)
                    .await
                    .is_ok()
            );
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn heterogeneous_clients_can_send_messages(case: TestCase) {
        let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

        // check that both credentials can initiate/join a group
        {
            let alice_identifier = ClientIdentifier::Basic("alice".into());
            let (bob_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("bob", None);
            assert!(
                try_talk(&case, Some(&x509_test_chain), alice_identifier, bob_identifier)
                    .await
                    .is_ok()
            );
            // drop alice & bob key stores
        }
        {
            let (alice_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("alice", None);
            let bob_identifier = ClientIdentifier::Basic("bob".into());
            assert!(
                try_talk(&case, Some(&x509_test_chain), alice_identifier, bob_identifier)
                    .await
                    .is_ok()
            );
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_is_empty(case: TestCase) {
        let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

        let x509_intermediate = x509_test_chain.find_local_intermediate_ca();

        let mut certs = CertificateBundle::rand(&"alice".into(), x509_intermediate);
        certs.certificate_chain = vec![];
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), certs)]));

        let (bob_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("bob", None);
        assert!(matches!(
            try_talk(&case, Some(&x509_test_chain), alice_identifier, bob_identifier)
                .await
                .unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_has_a_single_self_signed(case: TestCase) {
        if case.is_x509() {
            let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

            let (_alice_identifier, alice_cert) = x509_test_chain.issue_simple_certificate_bundle("alice", None);

            let new_cert = alice_cert
                .pki_keypair
                .re_sign(&alice_cert.certificate, &alice_cert.certificate, None)
                .unwrap();
            let mut alice_cert = alice_cert.clone();
            alice_cert.certificate = new_cert;
            let alice_identifier = ClientIdentifier::X509([(case.signature_scheme(), alice_cert.into())].into());

            let (bob_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("bob", None);
            assert!(matches!(
                try_talk(&case, Some(&x509_test_chain), bob_identifier, alice_identifier)
                    .await
                    .unwrap_err(),
                CryptoError::InvalidIdentity
            ));
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_signature_key_doesnt_match_certificate_public_key(case: TestCase) {
        if case.is_x509() {
            let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
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

            let (bob_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("bob", None);
            assert!(matches!(
                try_talk(&case, Some(&x509_test_chain), alice_identifier, bob_identifier)
                    .await
                    .unwrap_err(),
                CryptoError::MlsError(MlsError::MlsCryptoError(openmls::prelude::CryptoError::MismatchKeypair))
            ));
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_not_fail_but_degrade_when_certificate_expired(case: TestCase) {
        if case.is_x509() {
            let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

            let expiration_time = core::time::Duration::from_secs(14);
            let start = fluvio_wasm_timer::Instant::now();

            let (alice_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("alice", None);
            let (bob_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("bob", Some(expiration_time));

            // this should work since the certificate is not yet expired
            let (mut alice_central, mut bob_central, id) =
                try_talk(&case, Some(&x509_test_chain), alice_identifier, bob_identifier)
                    .await
                    .unwrap();

            assert_eq!(
                alice_central.e2ei_conversation_state(&id).await.unwrap(),
                E2eiConversationState::Verified
            );

            let elapsed = start.elapsed();
            // Give time to the certificate to expire
            if expiration_time > elapsed {
                async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(2)).await;
            }

            let _ = alice_central.try_talk_to(&id, &mut bob_central).await.unwrap();
            assert_eq!(
                alice_central.e2ei_conversation_state(&id).await.unwrap(),
                E2eiConversationState::NotVerified
            );
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_not_valid_yet(case: TestCase) {
        if case.is_x509() {
            let mut x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

            let tomorrow = now_std() + core::time::Duration::from_secs(3600 * 24);
            let local_ca = x509_test_chain.find_local_intermediate_ca();
            let alice_cert = {
                let name = "alice";
                let common_name = format!("{name} Smith");
                let handle = format!("{}_wire", name.to_lowercase());
                let client_id: String =
                    crate::e2e_identity::id::QualifiedE2eiClientId::generate_with_domain("wire.com")
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
            let cb = alice_cert.into();
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), cb)]));

            let (bob_identifier, _) = x509_test_chain.issue_simple_certificate_bundle("bob", None);

            match try_talk(&case, Some(&x509_test_chain), alice_identifier, bob_identifier)
                .await
                .unwrap_err()
            {
                CryptoError::MlsError(MlsError::MlsCryptoError(openmls::prelude::CryptoError::ExpiredCertificate)) => {}
                e => panic!("Unexpected error: {e:?}"),
            }
        }
    }

    /// In order to be WASM-compatible
    // pub fn now() -> wire_e2e_identity::prelude::OffsetDateTime {
    //     let now_since_epoch = now_std().as_secs() as i64;
    //     wire_e2e_identity::prelude::OffsetDateTime::from_unix_timestamp(now_since_epoch).unwrap()
    // }

    pub fn now_std() -> std::time::Duration {
        let now = fluvio_wasm_timer::SystemTime::now();
        now.duration_since(fluvio_wasm_timer::UNIX_EPOCH).unwrap()
    }

    async fn try_talk(
        case: &TestCase,
        x509_test_chain: Option<&X509TestChain>,
        creator_identifier: ClientIdentifier,
        guest_identifier: ClientIdentifier,
    ) -> CryptoResult<(MlsCentral, MlsCentral, ConversationId)> {
        let id = conversation_id();
        let ciphersuites = vec![case.ciphersuite()];

        let creator_ct = match creator_identifier {
            ClientIdentifier::Basic(_) => MlsCredentialType::Basic,
            ClientIdentifier::X509(_) => MlsCredentialType::X509,
        };
        let guest_ct = match guest_identifier {
            ClientIdentifier::Basic(_) => MlsCredentialType::Basic,
            ClientIdentifier::X509(_) => MlsCredentialType::X509,
        };

        let creator_path = tmp_db_file();

        let creator_cfg = MlsCentralConfiguration::try_new(
            creator_path.0,
            "alice".into(),
            None,
            ciphersuites.clone(),
            None,
            Some(INITIAL_KEYING_MATERIAL_COUNT),
        )?;

        let mut creator_central = MlsCentral::try_new(creator_cfg).await?;
        if let Some(x509_test_chain) = &x509_test_chain {
            x509_test_chain.register_with_central(&creator_central).await;
        }
        creator_central
            .mls_init(
                creator_identifier,
                ciphersuites.clone(),
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            )
            .await?;

        let guest_path = tmp_db_file();
        let guest_cfg = MlsCentralConfiguration::try_new(
            guest_path.0,
            "bob".into(),
            None,
            ciphersuites.clone(),
            None,
            Some(INITIAL_KEYING_MATERIAL_COUNT),
        )?;

        let mut guest_central = MlsCentral::try_new(guest_cfg).await?;
        if let Some(x509_test_chain) = &x509_test_chain {
            x509_test_chain.register_with_central(&guest_central).await;
        }
        guest_central
            .mls_init(
                guest_identifier,
                ciphersuites.clone(),
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            )
            .await?;

        creator_central
            .new_conversation(&id, creator_ct, case.cfg.clone())
            .await?;
        let guest = guest_central.rand_key_package_of_type(case, guest_ct).await;
        creator_central
            .invite_all_members(case, &id, [(&mut guest_central, guest)])
            .await?;
        creator_central.try_talk_to(&id, &mut guest_central).await?;
        Ok((creator_central, guest_central, id))
    }
}
