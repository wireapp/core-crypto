use std::sync::Arc;

pub use crate::prelude::{
    MlsCiphersuite, MlsConversationConfiguration, MlsCredentialType, MlsCustomConfiguration, MlsWirePolicy,
};
use crate::{
    e2e_identity::id::{QualifiedE2eiClientId, WireQualifiedClientId},
    prelude::ClientId,
    test_utils::SessionContext,
};
pub use openmls_traits::types::SignatureScheme;
pub use rstest::*;
pub use rstest_reuse::{self, *};

use super::{
    ClientIdentifier, CoreCryptoTransportSuccessProvider, MlsTransportTestExt, TestCertificateSource, TestConversation,
    init_x509_test_chain, tmp_db_file,
    x509::{CertificateParams, X509TestChain},
};

#[template]
#[rstest(
    case,
    case::basic_cs1(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    case::cert_cs1(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs2(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs2(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs3(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs3(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs5(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs5(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs7(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs7(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    case::pure_ciphertext(TestContext::default_cipher()),
)]
#[allow(non_snake_case)]
pub fn all_cred_cipher(case: TestContext) {}

#[derive(Debug, Clone)]
pub struct TestContext {
    pub credential_type: MlsCredentialType,
    pub cfg: MlsConversationConfiguration,
    pub transport: Arc<dyn MlsTransportTestExt>,
    #[cfg(not(target_family = "wasm"))]
    db_file: Option<(String, Arc<tempfile::TempDir>)>,
    #[cfg(target_family = "wasm")]
    db_file: Option<(String, Arc<()>)>,
}

impl TestContext {
    pub fn new(credential_type: MlsCredentialType, cs: openmls::prelude::Ciphersuite) -> Self {
        Self {
            credential_type,
            cfg: MlsConversationConfiguration {
                ciphersuite: cs.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn ciphersuite(&self) -> MlsCiphersuite {
        self.cfg.ciphersuite
    }

    pub fn signature_scheme(&self) -> SignatureScheme {
        self.cfg.ciphersuite.signature_algorithm()
    }

    pub fn custom_cfg(&self) -> MlsCustomConfiguration {
        self.cfg.custom.clone()
    }

    pub fn default_x509() -> Self {
        Self {
            credential_type: MlsCredentialType::X509,
            cfg: MlsConversationConfiguration::default(),
            transport: Arc::<CoreCryptoTransportSuccessProvider>::default(),
            db_file: None,
        }
    }

    pub fn default_cipher() -> Self {
        let mut default = Self::default();
        default.cfg.custom.wire_policy = MlsWirePolicy::Ciphertext;
        default
    }

    pub fn is_x509(&self) -> bool {
        matches!(self.credential_type, MlsCredentialType::X509)
    }

    pub fn is_basic(&self) -> bool {
        matches!(self.credential_type, MlsCredentialType::Basic)
    }

    pub fn is_pure_ciphertext(&self) -> bool {
        matches!(self.cfg.custom.wire_policy, MlsWirePolicy::Ciphertext)
    }

    /// Create a new temporary directory a db can be opened at. Will be deleted on drop of [TestContext].
    /// Use this only if you're not instantiating a [SessionContext] in your test.
    pub async fn tmp_dir(&mut self) -> String {
        let (db_dir_string, db_dir) = tmp_db_file();
        self.db_file = Some((db_dir_string.clone(), Arc::new(db_dir)));
        db_dir_string
    }

    pub fn client_ids<const N: usize>(&self) -> [ClientId; N] {
        self.client_ids_inner(QualifiedE2eiClientId::generate, WireQualifiedClientId::generate)
    }

    fn x509_client_ids<const N: usize>(&self) -> [ClientId; N] {
        std::array::from_fn(|_| QualifiedE2eiClientId::generate().into())
    }

    pub fn client_ids_for_user<const N: usize>(&self, user: &uuid::Uuid) -> [ClientId; N] {
        self.client_ids_inner(
            move || QualifiedE2eiClientId::generate_from_user_id(user),
            move || WireQualifiedClientId::generate_from_user_id(user),
        )
    }

    fn client_ids_inner<const N: usize>(
        &self,
        x509_id_factory: impl Fn() -> QualifiedE2eiClientId,
        basic_id_factory: impl Fn() -> WireQualifiedClientId,
    ) -> [ClientId; N] {
        let generator: &dyn Fn() -> ClientId = if self.is_x509() {
            &|| x509_id_factory().into()
        } else {
            &|| basic_id_factory().into()
        };
        std::array::from_fn(|_idx| generator())
    }

    async fn test_chain(
        &self,
        client_ids: &[ClientId],
        revoked_display_names: &[String],
        cert_params: Option<CertificateParams>,
    ) -> X509TestChain {
        let string_triples = client_ids.iter().map(|id| id.to_string_triple()).collect::<Vec<_>>();
        let str_triples = string_triples
            .iter()
            .map(|triple| std::array::from_fn(|i| triple[i].as_str()))
            .collect::<Vec<_>>();
        let revoked_display_names = revoked_display_names
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<&str>>();
        init_x509_test_chain(
            self,
            &str_triples,
            &revoked_display_names,
            cert_params.unwrap_or_default(),
        )
    }

    async fn x509_identifiers<const N: usize>(
        &self,
        client_ids: [ClientId; N],
        chain: &X509TestChain,
    ) -> [ClientIdentifier; N] {
        let mut x509_identifiers = Vec::with_capacity(N);
        let signature_scheme = self.signature_scheme();
        for (i, client_id) in client_ids.iter().enumerate() {
            x509_identifiers.push(SessionContext::x509_client_id(
                client_id,
                signature_scheme,
                &TestCertificateSource::TestChainActor(i),
                chain,
            ))
        }
        x509_identifiers.try_into().expect("Vector should be of length N.")
    }

    pub async fn sessions<const N: usize>(&self) -> [SessionContext; N] {
        if self.is_basic() {
            return self.sessions_basic().await;
        }
        self.sessions_x509().await
    }

    pub async fn sessions_x509_with_client_ids<const N: usize>(
        &self,
        client_ids: [ClientId; N],
    ) -> [SessionContext; N] {
        let test_chain = self.test_chain(&client_ids, &[], None).await;
        self.sessions_x509_inner(client_ids, &test_chain).await
    }

    pub async fn sessions_x509_with_client_ids_and_revocation<const N: usize>(
        &self,
        client_ids: [ClientId; N],
        revoked_display_names: &[String],
    ) -> [SessionContext; N] {
        let test_chain = self.test_chain(&client_ids, revoked_display_names, None).await;
        self.sessions_x509_inner(client_ids, &test_chain).await
    }

    pub async fn sessions_basic<const N: usize>(&self) -> [SessionContext; N] {
        let client_ids = self.client_ids::<N>();
        self.sessions_basic_inner(client_ids).await
    }

    async fn sessions_basic_inner<const N: usize>(&self, client_ids: [ClientId; N]) -> [SessionContext; N] {
        let mut sessions = Vec::with_capacity(N);
        for client_id in client_ids {
            sessions.push(
                SessionContext::new_with_identifier(self, ClientIdentifier::Basic(client_id), None)
                    .await
                    .unwrap(),
            );
        }
        sessions.try_into().expect("Vector should be of length N.")
    }

    pub async fn sessions_x509<const N: usize>(&self) -> [SessionContext; N] {
        let client_ids = self.x509_client_ids();
        let test_chain = self.test_chain(&client_ids, &[], None).await;
        self.sessions_x509_inner(client_ids, &test_chain).await
    }

    async fn sessions_x509_inner<const N: usize>(
        &self,
        client_ids: [ClientId; N],
        chain: &X509TestChain,
    ) -> [SessionContext; N] {
        let identifiers = self.x509_identifiers(client_ids, chain).await;
        let mut sessions = Vec::with_capacity(N);
        for client_id in identifiers {
            sessions.push(
                SessionContext::new_with_identifier(self, client_id, Some(chain))
                    .await
                    .unwrap(),
            );
        }
        sessions.try_into().expect("Vector should be of length N.")
    }

    /// Use this to create sessions with a test chain that has cross-signed another
    pub async fn sessions_x509_cross_signed<const N: usize, const M: usize>(
        &self,
    ) -> ([SessionContext; N], [SessionContext; M]) {
        let client_ids1 = self.x509_client_ids();
        let client_ids2 = self.x509_client_ids();
        self.sessions_x509_cross_signed_with_client_ids(client_ids1, client_ids2)
            .await
    }

    pub async fn sessions_x509_cross_signed_with_client_ids<const N: usize, const M: usize>(
        &self,
        client_ids1: [ClientId; N],
        client_ids2: [ClientId; M],
    ) -> ([SessionContext; N], [SessionContext; M]) {
        self.sessions_x509_cross_signed_with_client_ids_and_revocation(client_ids1, client_ids2, &[])
            .await
    }

    pub async fn sessions_x509_cross_signed_with_client_ids_and_revocation<const N: usize, const M: usize>(
        &self,
        client_ids1: [ClientId; N],
        client_ids2: [ClientId; M],
        revoked_display_names: &[String],
    ) -> ([SessionContext; N], [SessionContext; M]) {
        let mut chain1 = self.test_chain(&client_ids1, revoked_display_names, None).await;
        let sessions2 = if M == 0 {
            core::array::from_fn(|_| unreachable!())
        } else {
            let params = CertificateParams {
                org: "federated-with-wire.com".into(),
                domain: Some("federated-with-wire.com".into()),
                ..CertificateParams::default()
            };
            let mut chain2 = self.test_chain(&client_ids2, revoked_display_names, Some(params)).await;
            chain1.cross_sign(&mut chain2);
            self.sessions_x509_inner(client_ids2, &chain2).await
        };
        let sessions1 = self.sessions_x509_inner(client_ids1, &chain1).await;
        (sessions1, sessions2)
    }

    /// Create a test conversation.
    ///
    /// The first member is required, and is the conversation's creator.
    pub async fn create_conversation<'a>(
        &'a self,
        members: impl IntoIterator<Item = &'a SessionContext>,
    ) -> TestConversation<'a> {
        self.create_conversation_with_credential_type(self.credential_type, members)
            .await
    }

    /// Create a test conversation with the specified credential type.
    ///
    /// The first member is required, and is the conversation's creator.
    pub async fn create_conversation_with_credential_type<'a>(
        &'a self,
        credential_type: MlsCredentialType,
        members: impl IntoIterator<Item = &'a SessionContext>,
    ) -> TestConversation<'a> {
        let mut members = members.into_iter();
        let creator = members
            .next()
            .expect("each conversation needs at least 1 member, the creator");

        let conversation = TestConversation::new_with_credential_type(self, creator, credential_type).await;

        // if members are empty, return early here
        let mut members = members.peekable();
        if members.peek().is_none() {
            return conversation;
        }

        conversation.invite(members).await
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            credential_type: MlsCredentialType::Basic,
            cfg: MlsConversationConfiguration::default(),
            transport: Arc::<CoreCryptoTransportSuccessProvider>::default(),
            db_file: None,
        }
    }
}
