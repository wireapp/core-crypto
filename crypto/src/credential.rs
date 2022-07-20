use crate::{Client, ClientId, CryptoError, CryptoResult, MlsCiphersuite, MlsError};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{CredentialBundle, SignaturePrivateKey};

/// For test fixtures (test with basic or x509 credential)
#[cfg(test)]
pub type CredentialSupplier = fn() -> Option<CertificateBundle>;

/// Represents a x509 certificate chain supplied by the client
/// It can fetch it after an end-to-end identity process where it can get back a certificate
/// from the Authentication Service
#[derive(Debug, Clone)]
pub struct CertificateBundle {
    /// x509 certificate chain
    /// First entry is the leaf certificate and each subsequent is its issuer
    pub certificate_chain: Vec<Vec<u8>>,
    /// Leaf certificate private key
    pub private_key: SignaturePrivateKey,
}

#[cfg(test)]
impl CertificateBundle {
    /// Basic credentials are generated once clients are created
    /// It will effectively return `None`
    pub fn rnd_basic() -> CredentialSupplier {
        || None
    }

    /// Generates a supplier that is later turned into a [openmls::prelude::CredentialBundle]
    pub fn rnd_certificate_bundle() -> CredentialSupplier {
        || {
            // generate the leaf certificate
            let (leaf_kp, leaf_sk) = Self::key_pair();
            let leaf_params = Self::certificate_params(leaf_kp, false);
            Some(Self::certificate_bundle_from_leaf(leaf_params, leaf_sk))
            // None
        }
    }

    fn certificate_bundle_from_leaf(
        leaf_params: rcgen::CertificateParams,
        leaf_sk: SignaturePrivateKey,
    ) -> CertificateBundle {
        // those fields are lost when we generate a csr, hence we restore it later
        let not_after = leaf_params.not_after;
        let not_before = leaf_params.not_before;

        // generate a csr from leaf certificate
        let leaf = rcgen::Certificate::from_params(leaf_params).unwrap();
        let csr_der = leaf.serialize_request_der().unwrap();

        let mut csr = rcgen::CertificateSigningRequest::from_der(&csr_der).unwrap();

        csr.params.not_after = not_after;
        csr.params.not_before = not_before;

        // generate an issuer who is also a root ca
        let (issuer_kp, _) = Self::key_pair();
        let issuer_params = Self::certificate_params(issuer_kp, true);
        let issuer = rcgen::Certificate::from_params(issuer_params).unwrap();
        let issuer_der = issuer.serialize_der().unwrap();

        // generate leaf certificate from the csr
        let leaf_der = csr.serialize_der_with_signer(&issuer).unwrap();

        Self {
            certificate_chain: vec![leaf_der, issuer_der],
            private_key: leaf_sk,
        }
    }

    /// A keypair compatible with rcgen
    /// We then extract from it the public/private key we require for an MLS [openmls::prelude::CredentialBundle]
    fn key_pair() -> (rcgen::KeyPair, SignaturePrivateKey) {
        /// used to parse a pkcs8 documents with [OneAsymmetricKey](https://datatracker.ietf.org/doc/html/rfc5958#section-2)
        const KEY_LEN: usize = 32;
        const PRIV_KEY_IDX: usize = 16;
        const PUB_KEY_IDX: usize = 53;
        let kp = rcgen::KeyPair::generate(&rcgen::PKCS_ED25519).unwrap();
        let kp_der = kp.serialize_der();

        let sk = &kp_der[PRIV_KEY_IDX..PRIV_KEY_IDX + KEY_LEN];
        let pk = &kp_der[PUB_KEY_IDX..PUB_KEY_IDX + KEY_LEN];
        let sign_key = [sk, pk].concat();
        let private_key = SignaturePrivateKey {
            value: sign_key,
            signature_scheme: MlsCiphersuite::default().signature_algorithm(),
        };
        (kp, private_key)
    }

    /// Generates a x509 certificate
    fn certificate_params(key_pair: rcgen::KeyPair, is_ca: bool) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(vec!["wire.com".to_string()]);
        params.alg = &rcgen::PKCS_ED25519;
        params.key_pair = Some(key_pair);
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        }
        params
    }
}

impl Client {
    pub(crate) fn generate_basic_credential_bundle(
        id: &ClientId,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<CredentialBundle> {
        let signature_scheme = MlsCiphersuite::default().signature_algorithm();
        CredentialBundle::new_basic(id.to_vec(), signature_scheme, backend)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    pub(crate) fn generate_x509_credential_bundle(
        id: &ClientId,
        certificate: Vec<Vec<u8>>,
        private_key: SignaturePrivateKey,
    ) -> CryptoResult<CredentialBundle> {
        CredentialBundle::new_x509(id.to_vec(), certificate, private_key)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_fixture_utils::*, MlsConversation, MlsConversationConfiguration};
    use openmls::prelude::{CredentialError, WelcomeError};

    #[async_std::test]
    async fn basic_clients_can_send_messages() {
        let alice_cred = CertificateBundle::rnd_basic();
        let bob_cred = CertificateBundle::rnd_basic();
        alice_and_bob_send_messages(alice_cred, bob_cred).await.unwrap();
    }

    #[async_std::test]
    async fn certificate_clients_can_send_messages() {
        let alice_cred = CertificateBundle::rnd_certificate_bundle();
        let bob_cred = CertificateBundle::rnd_certificate_bundle();
        alice_and_bob_send_messages(alice_cred, bob_cred).await.unwrap();
    }

    #[async_std::test]
    async fn heterogeneous_clients_can_send_messages() {
        // check that both credentials can initiate/join a group
        {
            let alice_cred = CertificateBundle::rnd_basic();
            let bob_cred = CertificateBundle::rnd_certificate_bundle();
            alice_and_bob_send_messages(alice_cred, bob_cred).await.unwrap();
            // drop alice & bob key stores
        }
        {
            let alice_cred = CertificateBundle::rnd_certificate_bundle();
            let bob_cred = CertificateBundle::rnd_basic();
            alice_and_bob_send_messages(alice_cred, bob_cred).await.unwrap();
        }
    }

    #[async_std::test]
    async fn should_fail_when_certificate_chain_is_empty() {
        let alice_cred = || {
            let bundle = CertificateBundle::rnd_certificate_bundle()().unwrap();
            Some(CertificateBundle {
                certificate_chain: vec![],
                private_key: bundle.private_key,
            })
        };
        let bob_cred = CertificateBundle::rnd_certificate_bundle();
        match alice_and_bob_send_messages(alice_cred, bob_cred).await {
            Err(CryptoError::MlsError(MlsError::MlsCredentialError(CredentialError::IncompleteCertificateChain))) => {}
            _ => panic!(),
        };
    }

    #[async_std::test]
    async fn should_fail_when_certificate_chain_has_a_single_self_signed() {
        let alice_cred = || {
            let mut bundle = CertificateBundle::rnd_certificate_bundle()().unwrap();
            let root_ca = bundle.certificate_chain.last().unwrap().to_owned();
            bundle.certificate_chain = vec![root_ca];
            Some(bundle)
        };
        let bob_cred = CertificateBundle::rnd_certificate_bundle();
        match alice_and_bob_send_messages(alice_cred, bob_cred).await {
            Err(CryptoError::MlsError(MlsError::MlsCredentialError(CredentialError::IncompleteCertificateChain))) => {}
            _ => panic!(),
        };
    }

    #[async_std::test]
    async fn should_fail_when_certificate_chain_is_unordered() {
        // chain must be [leaf, leaf-issuer, ..., root-ca]
        let alice_cred = || {
            let mut bundle = CertificateBundle::rnd_certificate_bundle()().unwrap();
            bundle.certificate_chain.reverse();
            Some(bundle)
        };
        let bob_cred = CertificateBundle::rnd_certificate_bundle();
        match alice_and_bob_send_messages(alice_cred, bob_cred).await {
            Err(CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::InvalidGroupInfoSignature))) => {}
            _ => panic!(),
        };
    }

    #[async_std::test]
    async fn should_fail_when_signature_key_doesnt_match_certificate_public_key() {
        let alice_cred = || {
            let bundle = CertificateBundle::rnd_certificate_bundle()().unwrap();
            let other_bundle = CertificateBundle::rnd_certificate_bundle()().unwrap();
            Some(CertificateBundle {
                certificate_chain: bundle.certificate_chain,
                private_key: other_bundle.private_key,
            })
        };
        let bob_cred = CertificateBundle::rnd_certificate_bundle();
        match alice_and_bob_send_messages(alice_cred, bob_cred).await {
            Err(CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::InvalidGroupInfoSignature))) => {}
            _ => panic!(),
        };
    }

    #[async_std::test]
    async fn should_fail_when_certificate_expired() {
        let alice_cred = || {
            let (leaf_kp, leaf_sk) = CertificateBundle::key_pair();
            let mut params = rcgen::CertificateParams::new(vec!["wire.com".to_string()]);
            params.alg = &rcgen::PKCS_ED25519;
            params.key_pair = Some(leaf_kp);
            params.not_after = rcgen::date_time_ymd(1970, 1, 1);
            Some(CertificateBundle::certificate_bundle_from_leaf(params, leaf_sk))
        };

        let bob_cred = CertificateBundle::rnd_certificate_bundle();
        match alice_and_bob_send_messages(alice_cred, bob_cred).await {
            Err(CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::InvalidGroupInfoSignature))) => {}
            _ => panic!(),
        };
    }

    #[async_std::test]
    async fn should_fail_when_certificate_not_valid_yet() {
        let alice_cred = || {
            let (leaf_kp, leaf_sk) = CertificateBundle::key_pair();
            let mut params = rcgen::CertificateParams::new(vec!["wire.com".to_string()]);
            params.alg = &rcgen::PKCS_ED25519;
            params.key_pair = Some(leaf_kp);
            params.not_before = rcgen::date_time_ymd(3000, 1, 1);
            Some(CertificateBundle::certificate_bundle_from_leaf(params, leaf_sk))
        };

        let bob_cred = CertificateBundle::rnd_certificate_bundle();
        match alice_and_bob_send_messages(alice_cred, bob_cred).await {
            Err(CryptoError::MlsError(MlsError::MlsWelcomeError(WelcomeError::InvalidGroupInfoSignature))) => {}
            _ => panic!(),
        };
    }

    async fn alice_and_bob_send_messages(
        alice_cred: CredentialSupplier,
        bob_cred: CredentialSupplier,
    ) -> CryptoResult<()> {
        let conversation_id = conversation_id();
        let (alice_backend, mut alice) = alice(alice_cred).await?;
        let (bob_backend, bob) = bob(bob_cred).await?;
        let configuration = MlsConversationConfiguration::default();
        let mut alice_group =
            MlsConversation::create(conversation_id, alice.local_client_mut(), configuration, &alice_backend).await?;
        let welcome = alice_group
            .add_members(&mut [bob], &alice_backend)
            .await
            .unwrap()
            .welcome;

        let mut bob_group =
            MlsConversation::from_welcome_message(welcome, MlsConversationConfiguration::default(), &bob_backend)
                .await?;

        let msg = b"Hello World!";

        // alice -> bob
        let encrypted_msg = alice_group.encrypt_message(msg, &alice_backend).await?;
        let decrypted_msg = bob_group
            .decrypt_message(&encrypted_msg, &bob_backend)
            .await?
            .ok_or(CryptoError::Unauthorized)?;
        assert_eq!(msg, decrypted_msg.as_slice());

        // bob -> alice
        let encrypted_msg = bob_group.encrypt_message(decrypted_msg, &bob_backend).await?;
        let decrypted_msg = alice_group
            .decrypt_message(&encrypted_msg, &alice_backend)
            .await?
            .ok_or(CryptoError::Unauthorized)?;
        assert_eq!(msg, decrypted_msg.as_slice());
        Ok(())
    }
}
