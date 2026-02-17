use std::sync::Arc;

use async_lock::RwLock;
pub use openmls_traits::types::SignatureScheme;
pub use rstest::*;
pub use rstest_reuse::{self, *};

use super::{
    ClientIdentifier, CoreCryptoTransportSuccessProvider, MlsTransportTestExt, TestConversation, init_x509_test_chain,
    tmp_db_file,
    x509::{CertificateParams, X509TestChain},
};
pub use crate::{Ciphersuite, CredentialType, MlsConversationConfiguration, MlsCustomConfiguration, MlsWirePolicy};
use crate::{
    ClientId, ConnectionType, CredentialRef, Database, DatabaseKey,
    e2e_identity::id::{QualifiedE2eiClientId, WireQualifiedClientId},
    test_utils::SessionContext,
};

#[template]
#[rstest(
    case,
    case::basic_cs1(TestContext::new(
        crate::CredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    case::cert_cs1(TestContext::new(
        crate::CredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs2(TestContext::new(
        crate::CredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs2(TestContext::new(
        crate::CredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs3(TestContext::new(
        crate::CredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs3(TestContext::new(
        crate::CredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs5(TestContext::new(
        crate::CredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs5(TestContext::new(
        crate::CredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs7(TestContext::new(
        crate::CredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs7(TestContext::new(
        crate::CredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
)]
#[test_attr(macro_rules_attribute::apply(smol_macros::test))]
#[allow(non_snake_case)]
pub fn all_cred_cipher(case: TestContext) {}

#[derive(Debug, Clone)]
pub struct TestContext {
    pub credential_type: CredentialType,
    pub cfg: MlsConversationConfiguration,
    pub transport: Arc<dyn MlsTransportTestExt>,
    pub db: Option<(Database, Option<Arc<tempfile::TempDir>>)>,
    pub chain: Arc<RwLock<Option<X509TestChain>>>,
}

impl TestContext {
    pub fn new(credential_type: CredentialType, cs: openmls::prelude::Ciphersuite) -> Self {
        Self {
            credential_type,
            cfg: MlsConversationConfiguration {
                ciphersuite: cs.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn ciphersuite(&self) -> Ciphersuite {
        self.cfg.ciphersuite
    }

    pub fn signature_scheme(&self) -> SignatureScheme {
        self.cfg.ciphersuite.signature_algorithm()
    }

    pub fn custom_cfg(&self) -> MlsCustomConfiguration {
        self.cfg.custom.clone()
    }

    pub async fn create_in_memory_database(&mut self) -> Database {
        let database = Database::open(ConnectionType::InMemory, &DatabaseKey::generate())
            .await
            .unwrap();
        let out = database.clone();
        self.db = Some((database, None));
        out
    }

    pub fn default_x509() -> Self {
        Self {
            credential_type: CredentialType::X509,
            cfg: MlsConversationConfiguration::default(),
            transport: Arc::<CoreCryptoTransportSuccessProvider>::default(),
            ..Default::default()
        }
    }

    pub fn default_cipher() -> Self {
        let mut default = Self::default();
        default.cfg.custom.wire_policy = MlsWirePolicy::Ciphertext;
        default
    }

    pub fn is_x509(&self) -> bool {
        matches!(self.credential_type, CredentialType::X509)
    }

    pub fn is_basic(&self) -> bool {
        matches!(self.credential_type, CredentialType::Basic)
    }

    pub fn is_pure_ciphertext(&self) -> bool {
        matches!(self.cfg.custom.wire_policy, MlsWirePolicy::Ciphertext)
    }

    /// Create a new temporary directory and open a db there. Will be deleted on drop of [TestContext].
    /// Use this only if you're not instantiating a [SessionContext] in your test.
    pub async fn create_persistent_db(&mut self) -> Database {
        let (db_dir_string, db_dir) = tmp_db_file();
        let db = Database::open(ConnectionType::Persistent(&db_dir_string), &DatabaseKey::generate())
            .await
            .unwrap();
        let out = db.clone();
        self.db = Some((db, Some(db_dir.into())));
        out
    }

    pub fn x509_client_ids<const N: usize>(&self) -> [ClientId; N] {
        std::array::from_fn(|_| QualifiedE2eiClientId::generate().into())
    }

    pub fn basic_client_ids<const N: usize>(&self) -> [ClientId; N] {
        std::array::from_fn(|_| WireQualifiedClientId::generate().into())
    }

    pub fn x509_client_ids_for_user<const N: usize>(&self, user: &uuid::Uuid) -> [ClientId; N] {
        std::array::from_fn(|_| QualifiedE2eiClientId::generate_from_user_id(user).into())
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
        let chain = init_x509_test_chain(
            self,
            &str_triples,
            &revoked_display_names,
            cert_params.unwrap_or_default(),
        );
        let mut guard = self.chain.write_arc().await;
        *guard = Some(chain.clone());
        chain
    }

    async fn x509_identifiers<const N: usize>(
        &self,
        client_ids: [ClientId; N],
        chain: &X509TestChain,
    ) -> [ClientIdentifier; N] {
        let mut x509_identifiers = Vec::with_capacity(N);
        let signature_scheme = self.signature_scheme();
        for client_id in &client_ids {
            x509_identifiers.push(SessionContext::x509_client_id(client_id, signature_scheme, chain))
        }
        x509_identifiers.try_into().expect("Vector should be of length N.")
    }

    fn basic_identifiers<const N: usize>(client_ids: [ClientId; N]) -> [ClientIdentifier; N] {
        client_ids
            .iter()
            .map(|id| ClientIdentifier::Basic(id.clone()))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Vector should be of length N")
    }

    /// Generate a single client identifier of a type matching the credential type.
    ///
    /// This operation is _not_ idempotent; it generates a new identifier each time.
    ///
    /// If a test chain is provided, it is used only in the x509 case. If the case is x509,
    /// a test chain must be provided.
    pub(crate) async fn generate_identifier(&self, chain: Option<&X509TestChain>) -> ClientIdentifier {
        let [identifier] = match self.credential_type {
            CredentialType::Basic => {
                let client_ids = self.basic_client_ids::<1>();
                Self::basic_identifiers(client_ids)
            }
            CredentialType::X509 => {
                let client_ids = self.x509_client_ids::<1>();
                let chain = chain.expect("a test chain must be provided in the x509 case");
                self.x509_identifiers(client_ids, chain).await
            }
        };
        identifier
    }

    pub async fn sessions<const N: usize>(&self) -> [SessionContext; N] {
        if self.is_basic() {
            return self.sessions_basic().await;
        }
        self.sessions_x509().await
    }

    pub async fn sessions_with_pki_env<const N: usize>(&self) -> [SessionContext; N] {
        if self.is_basic() {
            return self.sessions_basic_with_pki_env().await;
        }
        self.sessions_x509().await
    }

    pub async fn sessions_basic<const N: usize>(&self) -> [SessionContext; N] {
        let client_ids = self.basic_client_ids::<N>();
        return self.sessions_inner(client_ids, None, CredentialType::Basic).await;
    }

    pub async fn sessions_basic_with_pki_env<const N: usize>(&self) -> [SessionContext; N] {
        let client_ids = self.basic_client_ids::<N>();
        let test_chain = X509TestChain::init_empty(self.signature_scheme());
        return self
            .sessions_inner(client_ids, Some(&test_chain), CredentialType::Basic)
            .await;
    }

    /// Use this to create sessions with both x509 and basic credential types.
    /// The first tuple element contains the x509 sessions, the second contains the basic sessions.
    pub async fn sessions_mixed_credential_types<const N: usize, const M: usize>(
        &self,
    ) -> ([SessionContext; N], [SessionContext; M]) {
        let x509_sessions = self.sessions_x509().await;
        let chain = x509_sessions[0].x509_chain_unchecked();
        let basic_ids = self.basic_client_ids();
        let basic_sessions = self.sessions_inner(basic_ids, Some(chain), CredentialType::Basic).await;
        (x509_sessions, basic_sessions)
    }

    pub async fn sessions_x509_with_client_ids<const N: usize>(
        &self,
        client_ids: [ClientId; N],
    ) -> [SessionContext; N] {
        let test_chain = self.test_chain(&client_ids, &[], None).await;
        self.sessions_inner(client_ids, Some(&test_chain), CredentialType::X509)
            .await
    }

    pub async fn sessions_x509_with_client_ids_and_revocation<const N: usize>(
        &self,
        client_ids: [ClientId; N],
        revoked_display_names: &[String],
    ) -> [SessionContext; N] {
        let test_chain = self.test_chain(&client_ids, revoked_display_names, None).await;
        self.sessions_inner(client_ids, Some(&test_chain), CredentialType::X509)
            .await
    }

    pub async fn sessions_x509<const N: usize>(&self) -> [SessionContext; N] {
        let client_ids = self.x509_client_ids();
        self.sessions_x509_with_client_ids(client_ids).await
    }

    async fn sessions_inner<const N: usize>(
        &self,
        client_ids: [ClientId; N],
        chain: Option<&X509TestChain>,
        credential_type: CredentialType,
    ) -> [SessionContext; N] {
        let identifiers = if credential_type == CredentialType::X509 {
            self.x509_identifiers(client_ids, chain.expect("must instantiate an x509 chain in x509 tests"))
                .await
        } else {
            Self::basic_identifiers(client_ids)
        };
        let mut sessions = Vec::with_capacity(N);
        for client_id in identifiers {
            sessions.push(
                SessionContext::new_with_identifier(self, client_id, chain)
                    .await
                    .unwrap(),
            );
        }
        sessions.try_into().expect("Vector should be of length N.")
    }

    /// Create a test conversation.
    ///
    /// The first member is required, and is the conversation's creator.
    pub async fn create_conversation<'a, S>(&'a self, members: S) -> TestConversation<'a>
    where
        S: IntoIterator<Item = &'a SessionContext>,
        <S as IntoIterator>::IntoIter: Clone,
    {
        let members_with_credentials = members.into_iter().map(|member| (member, &member.initial_credential));
        self.create_conversation_with_credentials(members_with_credentials)
            .await
    }

    /// Create a test conversation.
    ///
    /// The first member is required, and is the conversation's creator.
    pub async fn create_conversation_with_external_sender<'a, S>(
        &'a mut self,
        external_sender: &SessionContext,
        members: S,
    ) -> TestConversation<'a>
    where
        S: IntoIterator<Item = &'a SessionContext>,
        <S as IntoIterator>::IntoIter: Clone,
    {
        let mut members = members.into_iter().peekable();
        let creator = members.peek().unwrap();
        let signature_key = external_sender
            .initial_credential
            .load(&external_sender.database().await)
            .await
            .unwrap()
            .signature_key()
            .to_public_vec();
        self.cfg
            .set_raw_external_senders(&creator.session().await.crypto_provider, vec![signature_key])
            .await
            .unwrap();
        self.create_conversation(members).await
    }

    /// Create a test conversation with the specified credential type.
    ///
    /// The first member is required, and is the conversation's creator.
    pub async fn create_conversation_with_credentials<'a, SC>(
        &'a self,
        members_with_credentials: SC,
    ) -> TestConversation<'a>
    where
        SC: IntoIterator<Item = (&'a SessionContext, &'a CredentialRef)>,
        <SC as IntoIterator>::IntoIter: Clone,
    {
        let mut members_with_credentials = members_with_credentials.into_iter();
        let (creator, credential_ref) = members_with_credentials
            .next()
            .expect("each conversation needs at least 1 member, the creator");

        let conversation = TestConversation::new_with_credential(self, creator, credential_ref).await;

        // if members are empty, return early here
        let mut members_with_credentials = members_with_credentials.peekable();
        if members_with_credentials.peek().is_none() {
            return conversation;
        }

        conversation
            .invite_with_credential_notify(members_with_credentials)
            .await
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            credential_type: CredentialType::Basic,
            cfg: MlsConversationConfiguration::default(),
            transport: Arc::<CoreCryptoTransportSuccessProvider>::default(),
            db: None,
            chain: Arc::default(),
        }
    }
}
