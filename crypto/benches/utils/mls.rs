use rand::distributions::{Alphanumeric, DistString};
use std::fmt::{Display, Formatter};

use criterion::BenchmarkId;

use futures_lite::future::block_on;
use openmls::prelude::{Credential, CredentialWithKey, CryptoConfig, KeyPackage, SignaturePublicKey};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::Ciphersuite;
use openmls_traits::OpenMlsCryptoProvider;

use core_crypto::prelude::MlsCredentialType;
use core_crypto::{
    mls::{MlsCentral, MlsCiphersuite},
    prelude::{
        CertificateBundle, ClientId, ConversationId, ConversationMember, MlsCentralConfiguration,
        MlsConversationConfiguration, MlsCustomConfiguration,
    },
};
use mls_crypto_provider::MlsCryptoProvider;

#[derive(Copy, Clone, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum MlsTestCase {
    #[cfg(feature = "test-all-cipher")]
    Basic_Ciphersuite1,
    #[cfg(feature = "test-all-cipher")]
    Basic_Ciphersuite2,
    Basic_Ciphersuite3,
    #[cfg(feature = "test-all-cipher")]
    Basic_Ciphersuite7,
}

impl MlsTestCase {
    pub fn get(&self) -> (Self, MlsCiphersuite, Option<CertificateBundle>) {
        match self {
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite1 => (
                self.clone(),
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.into(),
                None,
            ),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite2 => (
                self.clone(),
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.into(),
                None,
            ),
            MlsTestCase::Basic_Ciphersuite3 => (
                self.clone(),
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519.into(),
                None,
            ),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite7 => (
                self.clone(),
                Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384.into(),
                None,
            ),
        }
    }

    pub fn values() -> impl Iterator<Item = (Self, MlsCiphersuite, Option<CertificateBundle>, bool)> {
        [
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite1,
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite2,
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
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite1, true) => "cs1/mem",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite2, true) => "cs2/mem",
            (MlsTestCase::Basic_Ciphersuite3, true) => "cs3/mem",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite7, true) => "cs7/mem",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite1, false) => "cs1/db",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite2, false) => "cs2/db",
            (MlsTestCase::Basic_Ciphersuite3, false) => "cs3/db",
            #[cfg(feature = "test-all-cipher")]
            (MlsTestCase::Basic_Ciphersuite7, false) => "cs7/db",
        }
    }
}

impl Display for MlsTestCase {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite1 => write!(f, "cs1"),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite2 => write!(f, "cs2"),
            MlsTestCase::Basic_Ciphersuite3 => write!(f, "cs3"),
            #[cfg(feature = "test-all-cipher")]
            MlsTestCase::Basic_Ciphersuite7 => write!(f, "cs7"),
        }
    }
}

pub fn setup_mls(
    ciphersuite: MlsCiphersuite,
    credential: &Option<CertificateBundle>,
    in_memory: bool,
) -> (MlsCentral, ConversationId) {
    let (mut central, _) = new_central(ciphersuite, credential, in_memory);
    let id = conversation_id();
    block_on(async {
        central
            .new_conversation(
                id.clone(),
                MlsCredentialType::Basic,
                MlsConversationConfiguration {
                    ciphersuite: ciphersuite.clone(),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    });
    (central, id)
}

pub fn new_central(
    ciphersuite: MlsCiphersuite,
    // TODO: always None for the moment. Need to update the benches with some realistic certificates
    _credential: &Option<CertificateBundle>,
    in_memory: bool,
) -> (MlsCentral, tempfile::TempDir) {
    let (path, tmp_file) = tmp_db_file();
    let client_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
    let ciphersuites = vec![ciphersuite];
    let cfg =
        MlsCentralConfiguration::try_new(path, secret, Some(client_id.as_bytes().into()), ciphersuites, None).unwrap();
    let central = if in_memory {
        block_on(async { MlsCentral::try_new_in_memory(cfg).await.unwrap() })
    } else {
        block_on(async { MlsCentral::try_new(cfg).await.unwrap() })
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

pub fn add_clients(
    central: &mut MlsCentral,
    id: &ConversationId,
    ciphersuite: MlsCiphersuite,
    nb_clients: usize,
) -> Vec<ClientId> {
    block_on(async {
        let mut client_ids = vec![];

        let mut members = (0..nb_clients)
            .map(|_| {
                let member = block_on(async { rand_member(ciphersuite).await });
                client_ids.push(member.id().as_slice().into());
                member
            })
            .collect::<Vec<_>>();

        central
            .add_members_to_conversation(&id, members.as_mut_slice())
            .await
            .unwrap();

        central.commit_accepted(&id).await.unwrap();
        client_ids
    })
}

pub async fn rand_key_package(ciphersuite: MlsCiphersuite) -> (KeyPackage, ClientId) {
    let client_id = Alphanumeric
        .sample_string(&mut rand::thread_rng(), 16)
        .as_bytes()
        .to_vec();
    let backend = block_on(async { MlsCryptoProvider::try_new_in_memory("secret").await.unwrap() });
    let cs: Ciphersuite = ciphersuite.clone().into();

    let mut rng = &mut *backend.rand().borrow_rand().unwrap();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm(), &mut rng).unwrap();

    let cred = Credential::new_basic(client_id.clone());
    let signature_key = SignaturePublicKey::from(signer.public());
    let credential = CredentialWithKey {
        credential: cred,
        signature_key,
    };

    let cfg = CryptoConfig::with_default_version(cs);
    let kp = KeyPackage::builder()
        .build(cfg, &backend, &signer, credential)
        .await
        .unwrap();
    (kp, client_id.into())
}

pub async fn rand_member(ciphersuite: MlsCiphersuite) -> ConversationMember {
    let (kp, client_id) = rand_key_package(ciphersuite).await;
    ConversationMember::new(client_id, kp)
}

pub fn invite(from: &mut MlsCentral, other: &mut MlsCentral, id: &ConversationId, ciphersuite: MlsCiphersuite) {
    block_on(async {
        let other_kps = other.get_or_create_client_keypackages(ciphersuite, 1).await.unwrap();
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
    })
}
