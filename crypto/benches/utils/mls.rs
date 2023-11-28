use rand::distributions::{Alphanumeric, DistString};
use std::fmt::{Display, Formatter};

use criterion::BenchmarkId;

use openmls::{
    framing::MlsMessageInBody,
    prelude::{
        group_info::VerifiableGroupInfo, Credential, CredentialWithKey, CryptoConfig, KeyPackage, SignaturePublicKey,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{random::OpenMlsRand, types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::Deserialize;

use core_crypto::prelude::{
    CertificateBundle, ClientId, ConversationId, ConversationMember, MlsCentral, MlsCentralConfiguration,
    MlsCiphersuite, MlsConversationConfiguration, MlsCredentialType, MlsCustomConfiguration,
};
use mls_crypto_provider::MlsCryptoProvider;

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
    #[cfg(any(feature = "test-all-cipher", feature = "test-pq-cipher"))]
    Basic_PostQuantum,
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
            #[cfg(any(feature = "test-all-cipher", feature = "test-pq-cipher"))]
            MlsTestCase::Basic_PostQuantum => (
                *self,
                Ciphersuite::MLS_128_X25519KYBER768DRAFT00_AES128GCM_SHA256_Ed25519.into(),
                None,
            ),
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
            #[cfg(any(feature = "test-all-cipher", feature = "test-pq-cipher"))]
            MlsTestCase::Basic_PostQuantum,
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
            #[cfg(any(feature = "test-all-cipher", feature = "test-pq-cipher"))]
            (MlsTestCase::Basic_PostQuantum, true) => "pq/mem",
            #[cfg(any(feature = "test-all-cipher", feature = "test-pq-cipher"))]
            (MlsTestCase::Basic_PostQuantum, false) => "pq/db",
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
            #[cfg(any(feature = "test-all-cipher", feature = "test-pq-cipher"))]
            MlsTestCase::Basic_PostQuantum => write!(f, "pq"),
        }
    }
}

pub async fn setup_mls(
    ciphersuite: MlsCiphersuite,
    credential: Option<&CertificateBundle>,
    in_memory: bool,
) -> (MlsCentral, ConversationId) {
    let (mut central, _) = new_central(ciphersuite, credential, in_memory).await;
    let id = conversation_id();
    central
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

    (central, id)
}

pub async fn new_central(
    ciphersuite: MlsCiphersuite,
    // TODO: always None for the moment. Need to update the benches with some realistic certificates
    _credential: Option<&CertificateBundle>,
    in_memory: bool,
) -> (MlsCentral, tempfile::TempDir) {
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
    (central, tmp_file)
}

pub fn tmp_db_file() -> (String, tempfile::TempDir) {
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
) -> (Vec<ClientId>, VerifiableGroupInfo) {
    let mut client_ids = vec![];

    let mut members = vec![];
    for _ in 0..nb_clients {
        let member = rand_member(ciphersuite).await;
        client_ids.push(member.id().as_slice().into());
        members.push(member)
    }

    let commit_bundle = central
        .add_members_to_conversation(id, members.as_mut_slice())
        .await
        .unwrap();

    let group_info = commit_bundle.group_info.payload.bytes();
    let group_info = openmls::prelude::MlsMessageIn::tls_deserialize(&group_info[..]).unwrap();
    let MlsMessageInBody::GroupInfo(group_info) = group_info.extract() else {
        panic!("error")
    };

    central.commit_accepted(id).await.unwrap();
    (client_ids, group_info)
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
    let kp = KeyPackage::builder()
        .leaf_node_capabilities(MlsConversationConfiguration::default_leaf_capabilities())
        .build(cfg, &backend, &signer, credential)
        .await
        .unwrap();
    (kp, client_id.into())
}

pub async fn rand_member(ciphersuite: MlsCiphersuite) -> ConversationMember {
    let (kp, client_id) = rand_key_package(ciphersuite).await;
    ConversationMember::new(client_id, kp)
}

pub async fn invite(from: &mut MlsCentral, other: &mut MlsCentral, id: &ConversationId, ciphersuite: MlsCiphersuite) {
    let other_kps = other
        .get_or_create_client_keypackages(ciphersuite, MlsCredentialType::Basic, 1)
        .await
        .unwrap();
    let other_kp = other_kps.first().unwrap().clone();
    let other_member = ConversationMember::new(other.client_id().unwrap(), other_kp);
    let welcome = from
        .add_members_to_conversation(id, &mut [other_member])
        .await
        .unwrap()
        .welcome;
    other
        .process_welcome_message(welcome.into(), MlsCustomConfiguration::default())
        .await
        .unwrap();
    from.commit_accepted(id).await.unwrap();
}
