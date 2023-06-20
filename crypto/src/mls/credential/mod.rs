use openmls::prelude::{CredentialWithKey, OpenMlsCrypto};
use openmls_traits::OpenMlsCryptoProvider;
pub(crate) mod ext;
pub(crate) mod typ;
pub(crate) mod x509;

use openmls::prelude::Credential;
use openmls_basic_credential::SignatureKeyPair;
use openmls_x509_credential::CertificateKeyPair;

use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::{CertificateBundle, Client, ClientId, CryptoResult, MlsCiphersuite, MlsError};

#[derive(Debug)]
pub struct CredentialBundle {
    pub(crate) credential: Credential,
    pub(crate) signature_key: SignatureKeyPair,
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

#[cfg(test)]
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
        }
    }
}

impl Client {
    pub(crate) fn new_basic_credential_bundle(
        id: &ClientId,
        ciphersuite: MlsCiphersuite,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<CredentialBundle> {
        let signature_scheme = ciphersuite.signature_algorithm();
        let (sk, pk) = backend
            .crypto()
            .signature_key_gen(signature_scheme)
            .map_err(MlsError::from)?;

        let signature_key = SignatureKeyPair::from_raw(signature_scheme, sk, pk);
        let credential = Credential::new_basic(id.to_vec());
        let cb = CredentialBundle {
            credential,
            signature_key,
        };

        Ok(cb)
    }

    pub(crate) fn new_x509_credential_bundle(cert: CertificateBundle) -> CryptoResult<CredentialBundle> {
        let client_id = cert.get_client_id()?;
        let (sk, ..) = cert.private_key.into_parts();
        let chain = cert.certificate_chain;

        let kp = CertificateKeyPair::new(sk, chain.clone()).map_err(MlsError::from)?;

        let credential = Credential::new_x509(client_id.into(), chain).map_err(MlsError::from)?;

        let cb = CredentialBundle {
            credential,
            signature_key: kp.0,
        };
        Ok(cb)
    }
}

// TODO: ensure certificate signature must match the group's ciphersuite ; fails otherwise.
// Requires more than 1 ciphersuite supported at the moment.
#[cfg(test)]
pub mod tests {
    use openmls::{
        prelude::{CreationFromExternalError, WelcomeError},
        treesync::{errors::TreeSyncFromNodesError, RatchetTreeError},
    };
    use std::collections::HashMap;
    use wasm_bindgen_test::*;
    use wire_e2e_identity::prelude::WireIdentityBuilder;

    use crate::{
        error::CryptoError,
        mls::{
            credential::x509::CertificatePrivateKey, MlsCentral, MlsCentralConfiguration, MlsConversationConfiguration,
        },
        prelude::{ClientIdentifier, ConversationId, MlsCredentialType},
        test_utils::*,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn basic_clients_can_send_messages(case: TestCase) {
        if matches!(case.credential_type, MlsCredentialType::Basic) {
            let alice_identifier = ClientIdentifier::Basic("alice".into());
            let bob_identifier = ClientIdentifier::Basic("bob".into());
            assert!(
                try_talk(alice_identifier, bob_identifier, MlsCredentialType::Basic, case.cfg)
                    .await
                    .is_ok()
            );
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn certificate_clients_can_send_messages(case: TestCase) {
        if matches!(case.credential_type, MlsCredentialType::X509) {
            let alice_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "alice".into());
            let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
            assert!(
                try_talk(alice_identifier, bob_identifier, MlsCredentialType::X509, case.cfg)
                    .await
                    .is_ok()
            );
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn heterogeneous_clients_can_send_messages(case: TestCase) {
        // check that both credentials can initiate/join a group
        {
            let alice_identifier = ClientIdentifier::Basic("alice".into());
            let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
            assert!(try_talk(
                alice_identifier,
                bob_identifier,
                MlsCredentialType::Basic,
                case.cfg.clone()
            )
            .await
            .is_ok());
            // drop alice & bob key stores
        }
        {
            let alice_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "alice".into());
            let bob_identifier = ClientIdentifier::Basic("bob".into());
            assert!(
                try_talk(alice_identifier, bob_identifier, MlsCredentialType::X509, case.cfg)
                    .await
                    .is_ok()
            );
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_is_empty(case: TestCase) {
        let mut certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
        certs.certificate_chain = vec![];
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), certs)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
        assert!(matches!(
            try_talk(alice_identifier, bob_identifier, MlsCredentialType::X509, case.cfg)
                .await
                .unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_chain_has_a_single_self_signed(case: TestCase) {
        let mut certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
        let root_ca = certs.certificate_chain.last().unwrap().to_owned();
        certs.certificate_chain = vec![root_ca];
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), certs)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
        assert!(matches!(
            try_talk(alice_identifier, bob_identifier, MlsCredentialType::X509, case.cfg)
                .await
                .unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_is_orphan(case: TestCase) {
        if matches!(case.credential_type, MlsCredentialType::X509) {
            // remove root_ca from the chain
            let mut certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
            let leaf = certs.certificate_chain.first().unwrap().to_owned();
            certs.certificate_chain = vec![leaf];
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), certs)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());

            assert!(matches!(
                try_talk(alice_identifier, bob_identifier, MlsCredentialType::X509, case.cfg)
                    .await
                    .unwrap_err(),
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
        let mut certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
        certs.certificate_chain.reverse();
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), certs)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
        assert!(matches!(
            try_talk(alice_identifier, bob_identifier, MlsCredentialType::X509, case.cfg)
                .await
                .unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_invalid_intermediates(case: TestCase) {
        if matches!(case.credential_type, MlsCredentialType::X509) {
            let eve_ca = WireIdentityBuilder::default().new_ca_certificate();
            let mut certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
            // remove the valid intermediate
            certs.certificate_chain.pop().unwrap();
            // and replace it with the malicious one
            certs.certificate_chain.push(eve_ca.serialize_der().unwrap());
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), certs)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());

            assert!(matches!(
                try_talk(alice_identifier, bob_identifier, case.credential_type, case.cfg)
                    .await
                    .unwrap_err(),
                CryptoError::MlsError(MlsError::MlsMessageError(
                    openmls::prelude::ProcessMessageError::CryptoError(openmls::prelude::CryptoError::InvalidSignature)
                ))
            ));
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_signature_key_doesnt_match_certificate_public_key(case: TestCase) {
        if matches!(case.credential_type, MlsCredentialType::X509) {
            let certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
            let (_, sign_key) = WireIdentityBuilder::default().new_key_pair();
            let eve_key = CertificatePrivateKey {
                value: sign_key,
                signature_scheme: case.ciphersuite().signature_algorithm(),
            };
            let cb = CertificateBundle {
                certificate_chain: certs.certificate_chain,
                private_key: eve_key,
            };
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), cb)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());

            assert!(matches!(
                try_talk(alice_identifier, bob_identifier, case.credential_type, case.cfg)
                    .await
                    .unwrap_err(),
                CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::PublicGroupError(
                    CreationFromExternalError::TreeSyncError(TreeSyncFromNodesError::RatchetTreeError(
                        RatchetTreeError::InvalidNodeSignature
                    ))
                )))
            ));
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_expired(case: TestCase) {
        if matches!(case.credential_type, MlsCredentialType::X509) {
            let in_2_secs = now() + core::time::Duration::from_secs(2);
            let (certificate_chain, sign_key) = WireIdentityBuilder {
                not_after: in_2_secs,
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
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), cb)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
            // this should work since the certificate is not yet expired
            let (mut alice_central, mut bob_central, id) =
                try_talk(alice_identifier, bob_identifier, case.credential_type, case.cfg)
                    .await
                    .unwrap();

            // Give time to the certificate to expire
            async_std::task::sleep(core::time::Duration::from_secs(6)).await;

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
        if matches!(case.credential_type, MlsCredentialType::X509) {
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
            let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), cb)]));

            let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());

            assert!(matches!(
                try_talk(alice_identifier, bob_identifier, case.credential_type, case.cfg)
                    .await
                    .unwrap_err(),
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
        alice_identifier: ClientIdentifier,
        bob_identifier: ClientIdentifier,
        creator_ct: MlsCredentialType,
        cfg: MlsConversationConfiguration,
    ) -> CryptoResult<(MlsCentral, MlsCentral, ConversationId)> {
        let id = conversation_id();
        let ciphersuites = vec![cfg.ciphersuite];
        let alice_path = tmp_db_file();

        let alice_cfg =
            MlsCentralConfiguration::try_new(alice_path.0, "alice".into(), None, ciphersuites.clone(), None)?;

        let mut alice_central = MlsCentral::try_new(alice_cfg).await?;
        alice_central.mls_init(alice_identifier, ciphersuites.clone()).await?;

        let bob_path = tmp_db_file();
        let bob_cfg = MlsCentralConfiguration::try_new(bob_path.0, "bob".into(), None, ciphersuites.clone(), None)?;

        let mut bob_central = MlsCentral::try_new(bob_cfg).await?;
        bob_central.mls_init(bob_identifier, ciphersuites.clone()).await?;

        alice_central
            .new_conversation(id.clone(), creator_ct, cfg.clone())
            .await?;
        alice_central.invite(&id, &mut bob_central, cfg.custom).await?;
        alice_central.try_talk_to(&id, &mut bob_central).await?;
        Ok((alice_central, bob_central, id))
    }
}
