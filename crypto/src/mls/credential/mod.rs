use openmls::prelude::{CredentialWithKey, OpenMlsCrypto};
use openmls_traits::OpenMlsCryptoProvider;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

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
                cert.cert_data.hash(state);
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
        self.created_at.partial_cmp(&other.created_at)
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
        let client_id = cert.get_client_id()?;
        let created_at = cert.get_created_at()?;
        let (sk, ..) = cert.private_key.into_parts();
        let chain = cert.certificate_chain;

        let kp = CertificateKeyPair::new(sk, chain.clone()).map_err(MlsError::from)?;

        let credential = Credential::new_x509(client_id.into(), chain).map_err(MlsError::from)?;

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
    use std::collections::HashMap;
    use wasm_bindgen_test::*;
    use wire_e2e_identity::prelude::WireIdentityBuilder;

    use crate::{
        mls::credential::x509::CertificatePrivateKey,
        prelude::{
            ClientIdentifier, ConversationId, CryptoError, MlsCentral, MlsCentralConfiguration, MlsCredentialType,
        },
        test_utils::*,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn basic_clients_can_send_messages(case: TestCase) {
        if case.is_basic() {
            let alice_identifier = ClientIdentifier::Basic("alice".into());
            let bob_identifier = ClientIdentifier::Basic("bob".into());
            assert!(try_talk(&case, alice_identifier, bob_identifier).await.is_ok());
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn certificate_clients_can_send_messages(case: TestCase) {
        if case.is_x509() {
            let alice_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "alice".into());
            let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());
            assert!(try_talk(&case, alice_identifier, bob_identifier).await.is_ok());
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn heterogeneous_clients_can_send_messages(case: TestCase) {
        // check that both credentials can initiate/join a group
        {
            let alice_identifier = ClientIdentifier::Basic("alice".into());
            let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());
            assert!(try_talk(&case, alice_identifier, bob_identifier).await.is_ok());
            // drop alice & bob key stores
        }
        {
            let alice_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "alice".into());
            let bob_identifier = ClientIdentifier::Basic("bob".into());
            assert!(try_talk(&case, alice_identifier, bob_identifier).await.is_ok());
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_is_empty(case: TestCase) {
        let mut certs = CertificateBundle::rand(&"alice".into(), case.signature_scheme());
        certs.certificate_chain = vec![];
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), certs)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());
        assert!(matches!(
            try_talk(&case, alice_identifier, bob_identifier).await.unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_has_a_single_self_signed(case: TestCase) {
        let mut certs = CertificateBundle::rand(&"alice".into(), case.signature_scheme());
        let root_ca = certs.certificate_chain.last().unwrap().to_owned();
        certs.certificate_chain = vec![root_ca];
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), certs)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());
        assert!(matches!(
            try_talk(&case, alice_identifier, bob_identifier).await.unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_is_orphan(case: TestCase) {
        if case.is_x509() {
            // remove root_ca from the chain
            let mut certs = CertificateBundle::rand(&"alice".into(), case.signature_scheme());
            let leaf = certs.certificate_chain.first().unwrap().to_owned();
            certs.certificate_chain = vec![leaf];
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), certs)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());

            assert!(matches!(
                try_talk(&case, alice_identifier, bob_identifier).await.unwrap_err(),
                CryptoError::MlsError(MlsError::MlsCryptoError(
                    openmls::prelude::CryptoError::IncompleteCertificateChain
                ))
            ));
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_is_unordered(case: TestCase) {
        // chain must be [leaf, leaf-issuer, ..., root-ca]
        let mut certs = CertificateBundle::rand(&"alice".into(), case.signature_scheme());
        certs.certificate_chain.reverse();
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), certs)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());
        assert!(matches!(
            try_talk(&case, alice_identifier, bob_identifier).await.unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_invalid_intermediates(case: TestCase) {
        if case.is_x509() {
            let eve_ca = WireIdentityBuilder::default().new_ca_certificate();
            let mut certs = CertificateBundle::rand(&"alice".into(), case.signature_scheme());
            // remove the valid intermediate
            certs.certificate_chain.pop().unwrap();
            // and replace it with the malicious one
            certs.certificate_chain.push(eve_ca.serialize_der().unwrap());
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), certs)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());

            assert!(matches!(
                try_talk(&case, alice_identifier, bob_identifier).await.unwrap_err(),
                CryptoError::MlsError(MlsError::MlsMessageError(
                    openmls::prelude::ProcessMessageError::CryptoError(openmls::prelude::CryptoError::InvalidSignature)
                ))
            ));
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_signature_key_doesnt_match_certificate_public_key(case: TestCase) {
        if case.is_x509() {
            let certs = CertificateBundle::rand(&"alice".into(), case.signature_scheme());
            let (_, sign_key) = WireIdentityBuilder::default().new_key_pair();
            let eve_key = CertificatePrivateKey {
                value: sign_key,
                signature_scheme: case.ciphersuite().signature_algorithm(),
            };
            let cb = CertificateBundle {
                certificate_chain: certs.certificate_chain,
                private_key: eve_key,
            };
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), cb)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());

            assert!(matches!(
                try_talk(&case, alice_identifier, bob_identifier).await.unwrap_err(),
                CryptoError::MlsError(MlsError::MlsCryptoError(openmls::prelude::CryptoError::MismatchKeypair))
            ));
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_expired(case: TestCase) {
        if case.is_x509() {
            let expiration_time = core::time::Duration::from_secs(14);
            let start = fluvio_wasm_timer::Instant::now();
            let expiration = now() + expiration_time;
            let (certificate_chain, sign_key) = WireIdentityBuilder {
                not_after: expiration,
                ..Default::default()
            }
            .build_x509_der();

            let cb = CertificateBundle {
                certificate_chain,
                private_key: CertificatePrivateKey {
                    value: sign_key,
                    signature_scheme: case.ciphersuite().signature_algorithm(),
                },
            };
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), cb)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());
            // this should work since the certificate is not yet expired
            let (mut alice_central, mut bob_central, id) =
                try_talk(&case, alice_identifier, bob_identifier).await.unwrap();

            let elapsed = start.elapsed();
            // Give time to the certificate to expire
            if expiration_time > elapsed {
                async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
            }

            assert!(matches!(
                alice_central.try_talk_to(&id, &mut bob_central).await.unwrap_err(),
                CryptoError::MlsError(MlsError::MlsMessageError(
                    openmls::prelude::ProcessMessageError::CryptoError(
                        openmls::prelude::CryptoError::InvalidCertificate
                    )
                ))
            ));
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_not_valid_yet(case: TestCase) {
        if case.is_x509() {
            let tomorrow = now() + core::time::Duration::from_secs(3600 * 24);
            let (certificate_chain, sign_key) = WireIdentityBuilder {
                not_before: tomorrow,
                ..Default::default()
            }
            .build_x509_der();

            let cb = CertificateBundle {
                certificate_chain,
                private_key: CertificatePrivateKey {
                    value: sign_key,
                    signature_scheme: case.ciphersuite().signature_algorithm(),
                },
            };
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.signature_scheme(), cb)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.signature_scheme()], "bob".into());

            assert!(matches!(
                try_talk(&case, alice_identifier, bob_identifier).await.unwrap_err(),
                CryptoError::MlsError(MlsError::MlsCryptoError(
                    openmls::prelude::CryptoError::InvalidCertificate
                ))
            ));
        }
    }

    /// In order to be WASM-compatible
    fn now() -> wire_e2e_identity::prelude::OffsetDateTime {
        let now = fluvio_wasm_timer::SystemTime::now();
        let now_since_epoch = now.duration_since(fluvio_wasm_timer::UNIX_EPOCH).unwrap().as_secs() as i64;
        wire_e2e_identity::prelude::OffsetDateTime::from_unix_timestamp(now_since_epoch).unwrap()
    }

    async fn try_talk(
        case: &TestCase,
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

        let creator_cfg =
            MlsCentralConfiguration::try_new(creator_path.0, "alice".into(), None, ciphersuites.clone(), None)?;

        let mut creator_central = MlsCentral::try_new(creator_cfg).await?;
        creator_central
            .mls_init(creator_identifier, ciphersuites.clone())
            .await?;

        let guest_path = tmp_db_file();
        let guest_cfg = MlsCentralConfiguration::try_new(guest_path.0, "bob".into(), None, ciphersuites.clone(), None)?;

        let mut guest_central = MlsCentral::try_new(guest_cfg).await?;
        guest_central.mls_init(guest_identifier, ciphersuites.clone()).await?;

        creator_central
            .new_conversation(id.clone(), creator_ct, case.cfg.clone())
            .await?;
        let guest_member = guest_central.rand_member_of_type(case, guest_ct).await;
        creator_central
            .invite_all_members(case, &id, [(&mut guest_central, guest_member)])
            .await?;
        creator_central.try_talk_to(&id, &mut guest_central).await?;
        Ok((creator_central, guest_central, id))
    }
}
