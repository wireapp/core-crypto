pub(crate) mod ext;
pub(crate) mod typ;
pub(crate) mod x509;

use openmls::prelude::CredentialBundle;

use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::{CertificateBundle, Client, ClientId, CryptoResult, MlsCiphersuite, MlsError};

impl Client {
    pub(crate) fn new_basic_credential_bundle(
        id: &ClientId,
        ciphersuite: MlsCiphersuite,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<CredentialBundle> {
        let signature_scheme = ciphersuite.signature_algorithm();
        let cb = CredentialBundle::new_basic(id.to_vec(), signature_scheme, backend).map_err(MlsError::from)?;
        Ok(cb)
    }

    pub(crate) fn new_x509_credential_bundle(cert: CertificateBundle) -> CryptoResult<CredentialBundle> {
        let client_id = cert.get_client_id()?;
        let cb = CredentialBundle::new_x509(client_id.into(), cert.certificate_chain, cert.private_key)
            .map_err(MlsError::from)?;
        Ok(cb)
    }
}

// TODO: ensure certificate signature must match the group's ciphersuite ; fails otherwise.
// Requires more than 1 ciphersuite supported at the moment.
#[cfg(test)]
pub mod tests {
    use openmls::prelude::{CredentialError, SignaturePrivateKey, WelcomeError};
    use std::collections::HashMap;
    use wasm_bindgen_test::*;
    use wire_e2e_identity::prelude::WireIdentityBuilder;

    use crate::prelude::ClientIdentifier;
    use crate::{
        error::CryptoError,
        mls::{MlsCentral, MlsCentralConfiguration, MlsConversationConfiguration},
        test_utils::*,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn basic_clients_can_send_messages(case: TestCase) {
        let alice_identifier = ClientIdentifier::Basic("alice".into());
        let bob_identifier = ClientIdentifier::Basic("bob".into());
        assert!(try_talk(alice_identifier, bob_identifier, case.cfg).await.is_ok());
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn certificate_clients_can_send_messages(case: TestCase) {
        let alice_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "alice".into());
        let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
        assert!(try_talk(alice_identifier, bob_identifier, case.cfg).await.is_ok());
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn heterogeneous_clients_can_send_messages(case: TestCase) {
        // check that both credentials can initiate/join a group
        {
            let alice_identifier = ClientIdentifier::Basic("alice".into());
            let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
            assert!(try_talk(alice_identifier, bob_identifier, case.cfg.clone())
                .await
                .is_ok());
            // drop alice & bob key stores
        }
        {
            let alice_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "alice".into());
            let bob_identifier = ClientIdentifier::Basic("bob".into());
            assert!(try_talk(alice_identifier, bob_identifier, case.cfg).await.is_ok());
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
            try_talk(alice_identifier, bob_identifier, case.cfg).await.unwrap_err(),
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
            try_talk(alice_identifier, bob_identifier, case.cfg).await.unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_is_orphan(case: TestCase) {
        // remove root_ca from the chain
        let mut certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
        let leaf = certs.certificate_chain.first().unwrap().to_owned();
        certs.certificate_chain = vec![leaf];
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), certs)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
        assert!(matches!(
            try_talk(alice_identifier, bob_identifier, case.cfg).await.unwrap_err(),
            CryptoError::MlsError(MlsError::MlsCredentialError(
                CredentialError::IncompleteCertificateChain
            ))
        ));
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
            try_talk(alice_identifier, bob_identifier, case.cfg).await.unwrap_err(),
            CryptoError::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_invalid_intermediates(case: TestCase) {
        let eve_ca = WireIdentityBuilder::default().new_ca_certificate();
        let mut certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
        // remove the valid intermediate
        certs.certificate_chain.pop().unwrap();
        // and replace it with the malicious one
        certs.certificate_chain.push(eve_ca.serialize_der().unwrap());
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), certs)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
        assert!(matches!(
            try_talk(alice_identifier, bob_identifier, case.cfg).await.unwrap_err(),
            CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::InvalidGroupInfoSignature))
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_signature_key_doesnt_match_certificate_public_key(case: TestCase) {
        let certs = CertificateBundle::rand(case.ciphersuite(), "alice".into());
        let (_, sign_key) = WireIdentityBuilder::default().new_key_pair();
        let eve_key = SignaturePrivateKey {
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
            try_talk(alice_identifier, bob_identifier, case.cfg).await.unwrap_err(),
            CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::InvalidGroupInfoSignature))
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_expired(case: TestCase) {
        let yesterday =
            wire_e2e_identity::prelude::OffsetDateTime::now_utc() - core::time::Duration::from_secs(3600 * 24);
        let (certificate_chain, sign_key) = WireIdentityBuilder {
            not_after: yesterday,
            ..Default::default()
        }
        .build_x509_der();

        let cb = CertificateBundle {
            certificate_chain,
            private_key: SignaturePrivateKey {
                value: sign_key,
                signature_scheme: case.ciphersuite().signature_algorithm(),
            },
        };
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), cb)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
        assert!(matches!(
            try_talk(alice_identifier, bob_identifier, case.cfg).await.unwrap_err(),
            CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::InvalidGroupInfoSignature))
        ));
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_certificate_not_valid_yet(case: TestCase) {
        let tomorrow =
            wire_e2e_identity::prelude::OffsetDateTime::now_utc() + core::time::Duration::from_secs(3600 * 24);
        let (certificate_chain, sign_key) = WireIdentityBuilder {
            not_before: tomorrow,
            ..Default::default()
        }
        .build_x509_der();

        let cb = CertificateBundle {
            certificate_chain,
            private_key: SignaturePrivateKey {
                value: sign_key,
                signature_scheme: case.ciphersuite().signature_algorithm(),
            },
        };
        let alice_identifier = ClientIdentifier::X509(HashMap::from([(case.ciphersuite(), cb)]));

        let bob_identifier = CertificateBundle::rand_identifier(&[case.ciphersuite()], "bob".into());
        assert!(matches!(
            try_talk(alice_identifier, bob_identifier, case.cfg).await.unwrap_err(),
            CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::InvalidGroupInfoSignature))
        ));
    }

    async fn try_talk(
        alice_identifier: ClientIdentifier,
        bob_identifier: ClientIdentifier,
        cfg: MlsConversationConfiguration,
    ) -> CryptoResult<()> {
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

        alice_central.new_conversation(id.clone(), cfg.clone()).await?;
        alice_central.invite(&id, &mut bob_central, cfg.custom).await?;
        alice_central.try_talk_to(&id, &mut bob_central).await
    }
}
