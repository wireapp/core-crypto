#![cfg(test)]

use std::collections::HashMap;

use openmls::{
    key_packages::KeyPackage,
    prelude::{QueuedProposal, StagedCommit},
};
pub use rstest::*;
pub use rstest_reuse::{self, *};

use mls_crypto_provider::MlsCryptoProvider;

use crate::{
    config::MlsCentralConfiguration, credential::CredentialSupplier, member::ConversationMember, ConversationId,
    CryptoResult, MlsCentral, MlsConversation,
};

#[template]
#[export]
#[rstest(
    credential,
    case::credential_basic(crate::credential::CertificateBundle::rnd_basic()),
    case::credential_x509(crate::credential::CertificateBundle::rnd_certificate_bundle())
)]
#[allow(non_snake_case)]
pub fn all_credential_types(credential: crate::credential::CredentialSupplier) {}

pub async fn run_test_with_central(
    credential: CredentialSupplier,
    test: impl FnOnce([MlsCentral; 1]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_client_ids(credential, ["alice"], test).await
}

pub async fn run_test_with_client_ids<const N: usize>(
    credential: CredentialSupplier,
    client_id: [&'static str; N],
    test: impl FnOnce([MlsCentral; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_tests(move |paths: [String; N]| {
        Box::pin(async move {
            let stream = paths.into_iter().enumerate().map(|(i, p)| async move {
                let client_id = client_id[i].to_string();
                let configuration = MlsCentralConfiguration::try_new(p, "test".into(), client_id).unwrap();
                MlsCentral::try_new(configuration, credential()).await.unwrap()
            });
            let centrals: [MlsCentral; N] = futures_util::future::join_all(stream).await.try_into().unwrap();
            test(centrals).await;
        })
    })
    .await
}

#[cfg(not(target_family = "wasm"))]
pub async fn run_tests<const N: usize>(
    test: impl FnOnce([String; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    let dirs = (0..N)
        .map(|_| tempfile::tempdir().unwrap())
        .collect::<Vec<tempfile::TempDir>>();
    let paths: [String; N] = dirs
        .iter()
        .map(MlsCentralConfiguration::tmp_store_path)
        .collect::<Vec<String>>()
        .try_into()
        .unwrap();
    test(paths).await;
}

#[cfg(target_family = "wasm")]
pub async fn run_tests<const N: usize>(
    test: impl FnOnce([String; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    use rand::distributions::{Alphanumeric, DistString};
    let paths = [0; N].map(|_| format!("{}.idb", Alphanumeric.sample_string(&mut rand::thread_rng(), 16)));
    test(paths).await;
}

pub fn conversation_id() -> ConversationId {
    let uuid = uuid::Uuid::new_v4();
    ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()))
}

/// Typically client creating a conversation
pub async fn alice(credential: CredentialSupplier) -> CryptoResult<(MlsCryptoProvider, ConversationMember)> {
    new_client("alice", credential).await
}

/// Typically client joining the conversation initiated by [alice]
pub async fn bob(credential: CredentialSupplier) -> CryptoResult<(MlsCryptoProvider, ConversationMember)> {
    new_client("bob", credential).await
}

/// A third client
pub async fn charlie(credential: CredentialSupplier) -> CryptoResult<(MlsCryptoProvider, ConversationMember)> {
    new_client("charlie", credential).await
}

pub async fn new_client(
    name: &str,
    credential: CredentialSupplier,
) -> CryptoResult<(MlsCryptoProvider, ConversationMember)> {
    let backend = init_keystore(name).await;
    let (member, _) = ConversationMember::random_generate(&backend, credential).await?;
    Ok((backend, member))
}

#[inline(always)]
pub async fn init_keystore(identifier: &str) -> MlsCryptoProvider {
    MlsCryptoProvider::try_new_in_memory(identifier).await.unwrap()
}

impl MlsCentral {
    pub async fn get_one_key_package(&self) -> CryptoResult<KeyPackage> {
        Ok(self
            .client_keypackages(1)
            .await?
            .get(0)
            .unwrap()
            .key_package()
            .to_owned())
    }

    pub async fn rnd_member(&self) -> ConversationMember {
        let id = self.mls_client.id();
        self.mls_client.gen_keypackage(&self.mls_backend).await.unwrap();
        let clients = HashMap::from([(
            id.clone(),
            self.mls_client.keypackages(&self.mls_backend).await.unwrap(),
        )]);
        ConversationMember {
            id: id.to_vec(),
            clients,
            local_client: Some(self.mls_client.clone()),
        }
    }

    pub fn pending_proposals(&self, id: &ConversationId) -> Vec<QueuedProposal> {
        self[id].group.pending_proposals().cloned().collect::<Vec<_>>()
    }

    pub fn pending_commit(&self, id: &ConversationId) -> Option<&StagedCommit> {
        self[id].group.pending_commit()
    }

    pub async fn can_talk_to(&mut self, id: &ConversationId, other: &mut MlsCentral) -> CryptoResult<()> {
        // self --> other
        let msg = b"Hello other";
        let encrypted = self.encrypt_message(id, msg).await?;
        let decrypted = other.decrypt_message(id, encrypted).await?.app_msg.unwrap();
        assert_eq!(&msg[..], &decrypted[..]);
        // other --> self
        let msg = b"Hello self";
        let encrypted = other.encrypt_message(id, msg).await?;
        let decrypted = self.decrypt_message(id, encrypted).await?.app_msg.unwrap();
        assert_eq!(&msg[..], &decrypted[..]);
        Ok(())
    }
}

impl std::ops::Index<&ConversationId> for MlsCentral {
    type Output = MlsConversation;

    fn index(&self, index: &ConversationId) -> &Self::Output {
        self.get_conversation(index).unwrap()
    }
}

impl std::ops::IndexMut<&ConversationId> for MlsCentral {
    fn index_mut(&mut self, index: &ConversationId) -> &mut Self::Output {
        self.mls_groups.get_mut(index).unwrap()
    }
}
