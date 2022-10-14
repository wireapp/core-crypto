#![allow(dead_code)]
use rand::distributions::{Alphanumeric, DistString};

use std::fmt::{Display, Formatter};

use futures_lite::future::block_on;
use openmls::prelude::{CredentialBundle, Extension, KeyPackage, KeyPackageBundle, LifetimeExtension};
use openmls_traits::types::Ciphersuite;

use core_crypto::prelude::{
    CertificateBundle, ClientId, ConversationId, ConversationMember, MlsConversationConfiguration,
};
use core_crypto::{mls::MlsCentral, mls::MlsCiphersuite, prelude::MlsCentralConfiguration};
use mls_crypto_provider::MlsCryptoProvider;

// number of criterion sample
pub const SAMPLE_SIZE: usize = 50;

// number of clients in a group
pub const GROUP_MAX: usize = 101;
pub const GROUP_MIN: usize = 1;
pub const GROUP_STEP: usize = 20;

#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum MlsTestCase {
    Basic_Ciphersuite1,
    Basic_Ciphersuite2,
    Basic_Ciphersuite3,
    Basic_Ciphersuite7,
}

impl MlsTestCase {
    pub fn get(&self) -> (Self, MlsCiphersuite, Option<CertificateBundle>) {
        match self {
            MlsTestCase::Basic_Ciphersuite1 => (
                self.clone(),
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.into(),
                None,
            ),
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
            MlsTestCase::Basic_Ciphersuite7 => (
                self.clone(),
                Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384.into(),
                None,
            ),
        }
    }

    pub fn values() -> impl Iterator<Item = (Self, MlsCiphersuite, Option<CertificateBundle>)> {
        const VALUES: [MlsTestCase; 4] = [
            MlsTestCase::Basic_Ciphersuite1,
            MlsTestCase::Basic_Ciphersuite2,
            MlsTestCase::Basic_Ciphersuite3,
            MlsTestCase::Basic_Ciphersuite7,
        ];
        VALUES.map(|v| v.get()).into_iter()
    }
}

impl Display for MlsTestCase {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsTestCase::Basic_Ciphersuite1 => write!(f, "B-1"),
            MlsTestCase::Basic_Ciphersuite2 => write!(f, "B-2"),
            MlsTestCase::Basic_Ciphersuite3 => write!(f, "B-3"),
            MlsTestCase::Basic_Ciphersuite7 => write!(f, "B-7"),
        }
    }
}

pub fn new_central(credential: &Option<CertificateBundle>) -> (MlsCentral, tempfile::TempDir) {
    let (path, tmp_file) = tmp_db_file();
    let client_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
    let ciphersuites = vec![MlsCiphersuite::default()];
    let cfg = MlsCentralConfiguration::try_new(path, secret, client_id, ciphersuites).unwrap();
    let central = block_on(async { MlsCentral::try_new(cfg, credential.clone()).await.unwrap() });
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

pub fn setup(ciphersuite: &MlsCiphersuite, credential: &Option<CertificateBundle>) -> (MlsCentral, ConversationId) {
    let (mut central, _) = new_central(credential);
    let id = conversation_id();
    block_on(async {
        central
            .new_conversation(
                id.clone(),
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

pub fn add_clients(
    central: &mut MlsCentral,
    id: &ConversationId,
    ciphersuite: &MlsCiphersuite,
    nb_clients: usize,
) -> Vec<ClientId> {
    block_on(async {
        let mut client_ids = vec![];

        let mut members = (0..nb_clients)
            .map(|_| {
                let member = rand_member(ciphersuite);
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

pub fn rand_key_package(ciphersuite: &MlsCiphersuite) -> (KeyPackage, ClientId) {
    let client_id = Alphanumeric
        .sample_string(&mut rand::thread_rng(), 16)
        .as_bytes()
        .to_vec();
    let backend = block_on(async { MlsCryptoProvider::try_new_in_memory("secret").await.unwrap() });
    let ciphersuite: Ciphersuite = ciphersuite.clone().into();
    let cred = CredentialBundle::new_basic(client_id.clone(), ciphersuite.signature_algorithm(), &backend).unwrap();
    let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(3600));
    let kpb = KeyPackageBundle::new(&[ciphersuite], &cred, &backend, vec![lifetime_extension]).unwrap();
    (kpb.key_package().clone(), client_id.into())
}

pub fn rand_member(ciphersuite: &MlsCiphersuite) -> ConversationMember {
    let (kp, client_id) = rand_key_package(ciphersuite);
    ConversationMember::new(client_id, kp)
}

pub fn invite(from: &mut MlsCentral, other: &mut MlsCentral, id: &ConversationId, ciphersuite: &MlsCiphersuite) {
    block_on(async {
        let other_kp = other
            .client_keypackages(1)
            .await
            .unwrap()
            .first()
            .unwrap()
            .key_package()
            .clone();
        let other_member = ConversationMember::new(other.client_id(), other_kp);
        let welcome = from
            .add_members_to_conversation(id, &mut [other_member])
            .await
            .unwrap()
            .welcome;
        other
            .process_welcome_message(
                welcome,
                MlsConversationConfiguration {
                    ciphersuite: ciphersuite.clone(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        from.commit_accepted(id).await.unwrap();
    })
}
