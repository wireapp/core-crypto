use async_lock::RwLock;
use criterion::BenchmarkId;
use rand::distributions::{Alphanumeric, DistString};
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use core_crypto::prelude::{
    CertificateBundle, ClientId, ConversationId, MlsCentral, MlsCentralConfiguration, MlsCiphersuite, MlsCommitBundle,
    MlsConversationConfiguration, MlsCredentialType, MlsCustomConfiguration, MlsGroupInfoBundle,
};
use core_crypto::{CoreCrypto, MlsTransport, MlsTransportResponse};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::framing::MlsMessageOut;
use openmls::{
    framing::MlsMessageInBody,
    prelude::{
        Credential, CredentialWithKey, CryptoConfig, KeyPackage, SignaturePublicKey, group_info::VerifiableGroupInfo,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsCryptoProvider, random::OpenMlsRand, types::Ciphersuite};
use tls_codec::Deserialize;

#[derive(Copy, Clone, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum MlsTestCase {
    Basic_Ciphersuite1,
    #[cfg(feature = "test-all-cipher")]
    Basic_Ciphersuite2,
    #[cfg(feature = "test-all-cipher")]
    Basic_Ciphersuite3,
    #[cfg(feature = "test-all-cipher")]
    Basic_Ciphersuite7,
}

impl MlsTestCase {
    pub fn get(&self) -> (Self, MlsCiphersuite, Option<CertificateBundle>) {
        match self {
            MlsTestCase::Basic_Ciphersuite1 => (
                *self,
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.into(),
                None,
            ),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite2 => {
                (*self, Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.into(), None)
            }
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite3 => (
                *self,
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519.into(),
                None,
            ),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite7 => {
                (*self, Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384.into(), None)
            }
        }
    }

    pub fn values() -> impl Iterator<Item = (Self, MlsCiphersuite, Option<CertificateBundle>, bool)> {
        [
            MlsTestCase::Basic_Ciphersuite1,
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite2,
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite3,
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite7,
        ]
        .into_iter()
        .map(|v| v.get())
        .flat_map(|(case, cipher, cert)| {
            let in_memory = (case, cipher, cert.clone(), true);
            let in_db = (case, cipher, cert, false);
            if cfg!(feature = "bench-in-db") {
                vec![in_memory, in_db]
            } else {
                vec![in_memory]
            }
        })
    }

    pub fn benchmark_id(&self, i: usize, in_memory: bool) -> BenchmarkId {
        BenchmarkId::new(self.ciphersuite_name(in_memory), i)
    }

    pub const fn ciphersuite_name(&self, in_memory: bool) -> &'static str {
        match (self, in_memory) {
            (MlsTestCase::Basic_Ciphersuite1, true) => "cs1/mem",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite2, true) => "cs2/mem",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite3, true) => "cs3/mem",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite7, true) => "cs7/mem",
            (MlsTestCase::Basic_Ciphersuite1, false) => "cs1/db",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite2, false) => "cs2/db",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite3, false) => "cs3/db",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite7, false) => "cs7/db",
        }
    }
}

impl Display for MlsTestCase {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsTestCase::Basic_Ciphersuite1 => write!(f, "cs1"),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite2 => write!(f, "cs2"),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite3 => write!(f, "cs3"),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite7 => write!(f, "cs7"),
        }
    }
}

pub async fn setup_mls(
    ciphersuite: MlsCiphersuite,
    credential: Option<&CertificateBundle>,
    in_memory: bool,
) -> (CoreCrypto, ConversationId, Arc<dyn MlsTransportTestExt>) {
    let (central, _, delivery_service) = new_central(ciphersuite, credential, in_memory).await;
    let core_crypto = central;
    let context = core_crypto.new_transaction().await.unwrap();
    let id = conversation_id();
    context
        .new_conversation(
            &id,
            MlsCredentialType::Basic,
            MlsConversationConfiguration {
                ciphersuite,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    context.finish().await.unwrap();
    (core_crypto, id, delivery_service)
}

pub async fn new_central(
    ciphersuite: MlsCiphersuite,
    // TODO: always None for the moment. Need to update the benches with some realistic certificates. Tracking issue: WPB-9589
    _credential: Option<&CertificateBundle>,
    in_memory: bool,
) -> (CoreCrypto, tempfile::TempDir, Arc<dyn MlsTransportTestExt>) {
    let (path, tmp_file) = tmp_db_file();
    let client_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
    let ciphersuites = vec![ciphersuite];
    let cfg = MlsCentralConfiguration::try_new(
        path,
        secret,
        Some(client_id.as_bytes().into()),
        ciphersuites,
        None,
        Some(100),
    )
    .unwrap();
    let central = if in_memory {
        MlsCentral::try_new_in_memory(cfg).await.unwrap()
    } else {
        MlsCentral::try_new(cfg).await.unwrap()
    };
    let cc = CoreCrypto::from(central);
    let delivery_service = Arc::<CoreCryptoTransportSuccessProvider>::default();
    cc.provide_transport(delivery_service.clone()).await;
    (cc, tmp_file, delivery_service.clone())
}

pub(crate) fn tmp_db_file() -> (String, tempfile::TempDir) {
    let tmp_dir = tempfile::tempdir().unwrap();
    let path = tmp_dir.path().join("store.edb");
    std::fs::File::create(&path).unwrap();
    let path = path.to_str().unwrap().to_string();
    (path, tmp_dir)
}

pub fn conversation_id() -> ConversationId {
    let uuid = uuid::Uuid::new_v4();
    ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()))
}

pub async fn add_clients(
    central: &mut MlsCentral,
    id: &ConversationId,
    ciphersuite: MlsCiphersuite,
    nb_clients: usize,
    main_client_delivery_service: Arc<dyn MlsTransportTestExt>,
) -> (Vec<ClientId>, VerifiableGroupInfo) {
    let mut client_ids = vec![];

    let mut key_packages = vec![];
    for _ in 0..nb_clients {
        let (kp, id) = rand_key_package(ciphersuite).await;
        client_ids.push(id.as_slice().into());
        key_packages.push(kp.into())
    }

    let core_crypto = CoreCrypto::from(central.clone());
    let context = core_crypto.new_transaction().await.unwrap();
    context
        .conversation_guard(id)
        .await
        .unwrap()
        .add_members(key_packages)
        .await
        .unwrap();
    let commit_bundle = main_client_delivery_service.latest_commit_bundle().await;

    let group_info = commit_bundle.group_info.payload.bytes();
    let group_info = openmls::prelude::MlsMessageIn::tls_deserialize(&mut group_info.as_slice()).unwrap();
    let MlsMessageInBody::GroupInfo(group_info) = group_info.extract() else {
        panic!("error")
    };

    context.finish().await.unwrap();
    (client_ids, group_info)
}

pub async fn setup_mls_and_add_clients(
    cipher_suite: MlsCiphersuite,
    credential: Option<&CertificateBundle>,
    in_memory: bool,
    client_count: usize,
) -> (
    CoreCrypto,
    ConversationId,
    Vec<ClientId>,
    VerifiableGroupInfo,
    Arc<dyn MlsTransportTestExt>,
) {
    let (core_crypto, id, delivery_service) = setup_mls(cipher_suite, credential, in_memory).await;
    let (client_ids, group_info) = add_clients(
        &mut core_crypto.clone(),
        &id,
        cipher_suite,
        client_count,
        delivery_service.clone(),
    )
    .await;
    (core_crypto, id, client_ids, group_info, delivery_service)
}

pub async fn rand_key_package(ciphersuite: MlsCiphersuite) -> (KeyPackage, ClientId) {
    let client_id = Alphanumeric
        .sample_string(&mut rand::thread_rng(), 16)
        .as_bytes()
        .to_vec();
    let backend = MlsCryptoProvider::try_new_in_memory("secret").await.unwrap();
    let cs: Ciphersuite = ciphersuite.into();

    let mut rng = backend.rand().borrow_rand().unwrap();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm(), &mut *rng).unwrap();
    drop(rng);

    let cred = Credential::new_basic(client_id.clone());
    let signature_key = SignaturePublicKey::from(signer.public());
    let credential = CredentialWithKey {
        credential: cred,
        signature_key,
    };

    let cfg = CryptoConfig::with_default_version(cs);
    backend.key_store().new_transaction().await.unwrap();
    let kp = KeyPackage::builder()
        .leaf_node_capabilities(MlsConversationConfiguration::default_leaf_capabilities())
        .build(cfg, &backend, &signer, credential)
        .await
        .unwrap();
    backend.key_store().commit_transaction().await.unwrap();
    (kp, client_id.into())
}

pub async fn invite(
    from: &mut MlsCentral,
    other: &mut MlsCentral,
    id: &ConversationId,
    ciphersuite: MlsCiphersuite,
    delivery_service: Arc<dyn MlsTransportTestExt>,
) {
    let core_crypto = CoreCrypto::from(from.clone());
    let from_context = core_crypto.new_transaction().await.unwrap();
    let core_crypto = CoreCrypto::from(other.clone());
    let other_context = core_crypto.new_transaction().await.unwrap();
    let other_kps = other_context
        .get_or_create_client_keypackages(ciphersuite, MlsCredentialType::Basic, 1)
        .await
        .unwrap();
    let other_kp = other_kps.first().unwrap().clone();
    from_context
        .conversation_guard(id)
        .await
        .unwrap()
        .add_members(vec![other_kp.into()])
        .await
        .unwrap();
    let welcome = delivery_service.latest_welcome_message().await;
    other_context
        .process_welcome_message(welcome.into(), MlsCustomConfiguration::default())
        .await
        .unwrap();
    from_context.finish().await.unwrap();
    other_context.finish().await.unwrap();
}

#[async_trait::async_trait]
pub trait MlsTransportTestExt: MlsTransport {
    async fn latest_commit_bundle(&self) -> MlsCommitBundle;
    async fn latest_welcome_message(&self) -> MlsMessageOut {
        self.latest_commit_bundle().await.welcome.unwrap().clone()
    }

    async fn latest_commit(&self) -> MlsMessageOut {
        self.latest_commit_bundle().await.commit.clone()
    }

    async fn latest_group_info(&self) -> MlsGroupInfoBundle {
        self.latest_commit_bundle().await.group_info.clone()
    }

    async fn latest_message(&self) -> Vec<u8>;
}

#[derive(Debug, Default)]
pub struct CoreCryptoTransportSuccessProvider {
    latest_commit_bundle: RwLock<Option<MlsCommitBundle>>,
    latest_message: RwLock<Option<Vec<u8>>>,
}

#[async_trait::async_trait]
impl MlsTransport for CoreCryptoTransportSuccessProvider {
    async fn send_commit_bundle(&self, commit_bundle: MlsCommitBundle) -> core_crypto::Result<MlsTransportResponse> {
        self.latest_commit_bundle.write().await.replace(commit_bundle);
        Ok(MlsTransportResponse::Success)
    }

    async fn send_message(&self, mls_message: Vec<u8>) -> core_crypto::Result<MlsTransportResponse> {
        self.latest_message.write().await.replace(mls_message);
        Ok(MlsTransportResponse::Success)
    }
}

#[async_trait::async_trait]
impl MlsTransportTestExt for CoreCryptoTransportSuccessProvider {
    async fn latest_commit_bundle(&self) -> MlsCommitBundle {
        self.latest_commit_bundle
            .read()
            .await
            .clone()
            .expect("latest_commit_bundle")
    }

    async fn latest_message(&self) -> Vec<u8> {
        self.latest_message.read().await.clone().expect("latest_message")
    }
}
