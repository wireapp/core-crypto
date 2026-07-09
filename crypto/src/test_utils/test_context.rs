use std::sync::Arc;

use async_lock::RwLock;
pub use openmls_traits::types::SignatureScheme;
pub use rstest::*;
pub use rstest_reuse::{self, *};

use super::{
    CoreCryptoTransportSuccessProvider, MlsTransportTestExt, TestConversation, init_x509_test_chain, tmp_db_file,
    x509::{CertificateParams, X509TestChain, qualified_e2ei_cid, qualified_e2ei_cid_from_user_id},
};
use crate::{
    CertificateBundle, ClientId, ConnectionType, Credential, CredentialRef, Database, DatabaseKey, ExternalSender,
    test_utils::SessionContext,
};
pub use crate::{CipherSuite, ConversationConfiguration, CredentialType, CustomConfiguration, WirePolicy};

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
    pub cfg: ConversationConfiguration,
    pub transport: Arc<dyn MlsTransportTestExt>,
    pub db: Option<(Arc<Database>, Option<Arc<tempfile::TempDir>>)>,
    pub chain: Arc<RwLock<Option<X509TestChain>>>,
}

impl TestContext {
    pub fn new(credential_type: CredentialType, cs: openmls::prelude::Ciphersuite) -> Self {
        Self {
            credential_type,
            cfg: ConversationConfiguration {
                cipher_suite: cs.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.cfg.cipher_suite
    }

    pub fn signature_scheme(&self) -> SignatureScheme {
        self.cfg.cipher_suite.signature_algorithm()
    }

    pub fn custom_cfg(&self) -> CustomConfiguration {
        self.cfg.custom.clone()
    }

    pub async fn create_in_memory_database(&mut self) -> Arc<Database> {
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
            cfg: ConversationConfiguration::default(),
            transport: Arc::<CoreCryptoTransportSuccessProvider>::default(),
            ..Default::default()
        }
    }

    pub fn default_cipher() -> Self {
        let mut default = Self::default();
        default.cfg.custom.wire_policy = WirePolicy::Ciphertext;
        default
    }

    pub fn is_x509(&self) -> bool {
        matches!(self.credential_type, CredentialType::X509)
    }

    pub fn is_basic(&self) -> bool {
        matches!(self.credential_type, CredentialType::Basic)
    }

    pub fn is_pure_ciphertext(&self) -> bool {
        matches!(self.cfg.custom.wire_policy, WirePolicy::Ciphertext)
    }

    /// Create a new temporary directory and open a db there. Will be deleted on drop of [TestContext].
    /// Use this only if you're not instantiating a [SessionContext] in your test.
    pub async fn create_persistent_db(&mut self) -> Arc<Database> {
        let (db_dir_string, db_dir) = tmp_db_file();
        let db = Database::open(ConnectionType::Persistent(&db_dir_string), &DatabaseKey::generate())
            .await
            .unwrap();
        let out = db.clone();
        self.db = Some((db, Some(db_dir.into())));
        out
    }

    pub fn client_ids<const N: usize>(&self) -> [ClientId; N] {
        match self.credential_type {
            CredentialType::Basic => self.basic_client_ids(),
            CredentialType::X509 => self.x509_client_ids(),
        }
    }

    pub fn x509_client_ids<const N: usize>(&self) -> [ClientId; N] {
        std::array::from_fn(|_| qualified_e2ei_cid())
    }

    pub fn basic_client_ids<const N: usize>(&self) -> [ClientId; N] {
        fn generate() -> ClientId {
            let user_id = uuid::Uuid::new_v4();
            let device_id = rand::random::<u64>();
            ClientId::new(user_id, device_id, "wire.com")
        }
        std::array::from_fn(|_| generate())
    }

    pub fn x509_client_ids_for_user<const N: usize>(&self, user: uuid::Uuid) -> [ClientId; N] {
        std::array::from_fn(|_| qualified_e2ei_cid_from_user_id(user))
    }

    pub(crate) async fn set_test_chain(
        &self,
        client_ids: &[ClientId],
        revoked_display_names: &[String],
        cert_params: Option<CertificateParams>,
    ) -> X509TestChain {
        let client_ids_with_user_ids = client_ids.iter().map(|id| id.with_user()).collect::<Vec<_>>();
        let revoked_display_names = revoked_display_names
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<&str>>();
        let chain = init_x509_test_chain(
            self,
            &client_ids_with_user_ids,
            &revoked_display_names,
            cert_params.unwrap_or_default(),
        );
        let mut guard = self.chain.write_arc().await;
        *guard = Some(chain.clone());
        chain
    }

    pub async fn x509_credentials<const N: usize>(&self, client_ids: [ClientId; N]) -> [Credential; N] {
        if self.chain.read().await.is_none() {
            self.set_test_chain(&client_ids, &[], None).await;
        }

        let test_chain = self.chain.read().await;
        let test_chain = test_chain.as_ref().unwrap();
        let mut credentials = Vec::with_capacity(N);
        let x509_intermediate = test_chain.find_local_intermediate_ca();
        for client_id in &client_ids {
            let certificate = test_chain
                .actors
                .iter()
                .find(|actor| &actor.client_id == client_id)
                .map(|actor| CertificateBundle::from_certificate_and_issuer(&actor.certificate, x509_intermediate))
                .unwrap_or_else(|| CertificateBundle::new_with_exact_client_id(client_id, x509_intermediate));
            let credential = Credential::x509(self.cipher_suite(), certificate).unwrap();
            credentials.push(credential)
        }
        credentials.try_into().expect("Vector should be of length N.")
    }

    pub(crate) fn basic_credentials<const N: usize>(&self, client_ids: [ClientId; N]) -> [Credential; N] {
        client_ids
            .into_iter()
            .map(|id| Credential::basic(self.cipher_suite(), id).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .expect("Vector should be of length N")
    }

    /// Generate a single credential of a type matching the credential type.
    ///
    /// This operation is _not_ idempotent; it generates a new credential each time.
    pub(crate) async fn generate_credential(&self) -> Credential {
        let [client_id] = self.client_ids();
        self.generate_credential_wtih_client_id(client_id).await
    }

    pub(crate) async fn generate_credential_wtih_client_id(&self, client_id: ClientId) -> Credential {
        let [credential] = match self.credential_type {
            CredentialType::Basic => self.basic_credentials([client_id]),
            CredentialType::X509 => self.x509_credentials([client_id]).await,
        };
        credential
    }

    pub async fn sessions<const N: usize>(&self) -> [SessionContext; N] {
        if self.is_basic() {
            return self.sessions_basic().await;
        }
        self.sessions_x509().await
    }

    pub async fn sessions_basic<const N: usize>(&self) -> [SessionContext; N] {
        let client_ids = self.basic_client_ids::<N>();
        return self
            .sessions_with_credential_type(client_ids, CredentialType::Basic)
            .await;
    }

    /// Use this to create sessions with both x509 and basic credential types.
    /// The first tuple element contains the x509 sessions, the second contains the basic sessions.
    pub async fn sessions_mixed_credential_types<const N: usize, const M: usize>(
        &self,
    ) -> ([SessionContext; N], [SessionContext; M]) {
        let x509_sessions = self.sessions_x509().await;
        let basic_sessions = self.sessions_basic().await;
        (x509_sessions, basic_sessions)
    }

    pub async fn sessions_x509_with_client_ids<const N: usize>(
        &self,
        client_ids: [ClientId; N],
    ) -> [SessionContext; N] {
        self.sessions_with_credential_type(client_ids, CredentialType::X509)
            .await
    }

    pub async fn sessions_x509_with_client_ids_and_revocation<const N: usize>(
        &self,
        client_ids: [ClientId; N],
        revoked_display_names: &[String],
    ) -> [SessionContext; N] {
        self.set_test_chain(&client_ids, revoked_display_names, None).await;
        self.sessions_with_credential_type(client_ids, CredentialType::X509)
            .await
    }

    pub async fn sessions_x509<const N: usize>(&self) -> [SessionContext; N] {
        let client_ids = self.x509_client_ids();
        self.sessions_x509_with_client_ids(client_ids).await
    }

    async fn sessions_with_credential_type<const N: usize>(
        &self,
        client_ids: [ClientId; N],
        credential_type: CredentialType,
    ) -> [SessionContext; N] {
        let credentials = if credential_type == CredentialType::X509 {
            self.x509_credentials(client_ids).await
        } else {
            self.basic_credentials(client_ids)
        };
        let mut sessions = Vec::with_capacity(N);
        for credential in credentials {
            sessions.push(SessionContext::new_with_credential(self, credential).await.unwrap());
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
        let signature_key = external_sender
            .initial_credential
            .load(&*external_sender.database().await)
            .await
            .unwrap()
            .signature_key()
            .to_public_vec();
        let external_sender =
            ExternalSender::parse_public_key(&signature_key, external_sender.initial_credential.signature_scheme())
                .unwrap();

        self.cfg.set_external_senders([external_sender]).await.unwrap();
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
            cfg: ConversationConfiguration::default(),
            transport: Arc::<CoreCryptoTransportSuccessProvider>::default(),
            db: None,
            chain: Arc::default(),
        }
    }
}
