#![cfg(test)]

use std::{
    collections::HashMap,
    ops::{Index, IndexMut},
};

use openmls::prelude::{
    KeyPackage, KeyPackageBundle, PublicGroupState, QueuedProposal, StagedCommit, VerifiablePublicGroupState,
};
pub use rstest::*;
pub use rstest_reuse::{self, *};

use crate::{
    config::MlsCentralConfiguration, credential::CredentialSupplier, member::ConversationMember, ConversationId,
    CoreCryptoCallbacks, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsConversationConfiguration,
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

pub async fn run_tests<const N: usize>(
    test: impl FnOnce([String; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    let paths: [(String, _); N] = (0..N).map(|_| tmp_db_file()).collect::<Vec<_>>().try_into().unwrap();
    // We need to store TempDir because they impl Drop which would delete the file before test begins
    let cloned_paths = paths
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    test(cloned_paths).await;
}

#[cfg(not(target_family = "wasm"))]
pub fn tmp_db_file() -> (String, tempfile::TempDir) {
    let file = tempfile::tempdir().unwrap();
    (MlsCentralConfiguration::tmp_store_path(&file), file)
}

#[cfg(target_family = "wasm")]
pub fn tmp_db_file() -> (String, ()) {
    use rand::distributions::{Alphanumeric, DistString};
    let path = format!("{}.idb", Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
    (path, ())
}

pub fn conversation_id() -> ConversationId {
    let uuid = uuid::Uuid::new_v4();
    ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()))
}

impl MlsCentral {
    pub async fn get_one_key_package(&self) -> KeyPackage {
        self.get_one_key_package_bundle().await.key_package().clone()
    }

    pub async fn get_one_key_package_bundle(&self) -> KeyPackageBundle {
        self.client_keypackages(1).await.unwrap().first().unwrap().clone()
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

    pub async fn talk_to(&mut self, id: &ConversationId, other: &mut MlsCentral) -> CryptoResult<()> {
        // self --> other
        let msg = b"Hello other";
        let encrypted = self.encrypt_message(id, msg).await?;
        let decrypted = other
            .decrypt_message(id, encrypted)
            .await?
            .app_msg
            .ok_or(CryptoError::ImplementationError)?;
        assert_eq!(&msg[..], &decrypted[..]);
        // other --> self
        let msg = b"Hello self";
        let encrypted = other.encrypt_message(id, msg).await?;
        let decrypted = self
            .decrypt_message(id, encrypted)
            .await?
            .app_msg
            .ok_or(CryptoError::ImplementationError)?;
        assert_eq!(&msg[..], &decrypted[..]);
        Ok(())
    }

    /// Streamlines the ceremony of adding a client and process its welcome message
    pub async fn invite(&mut self, id: &ConversationId, other: &mut MlsCentral) -> CryptoResult<()> {
        let size_before = self[id].members().len();
        let welcome = self
            .add_members_to_conversation(id, &mut [other.rnd_member().await])
            .await?
            .welcome;
        other
            .process_welcome_message(welcome, MlsConversationConfiguration::default())
            .await?;
        self.commit_accepted(id).await?;
        assert_eq!(self[id].members().len(), size_before + 1);
        assert_eq!(other[id].members().len(), size_before + 1);
        self.talk_to(id, other).await?;
        Ok(())
    }

    pub async fn group_info(&self, id: &ConversationId) -> PublicGroupState {
        self.get_conversation(id)
            .unwrap()
            .group
            .export_public_group_state(&self.mls_backend)
            .await
            .unwrap()
    }

    pub async fn verifiable_group_info(&self, id: &ConversationId) -> VerifiablePublicGroupState {
        use tls_codec::{Deserialize as _, Serialize as _};
        let group_info = self.group_info(id).await.tls_serialize_detached().unwrap();
        VerifiablePublicGroupState::tls_deserialize(&mut group_info.as_slice()).unwrap()
    }

    /// Finds the [KeyPackage] of a [Client] within a [MlsGroup]
    pub fn key_package_of(&self, conv_id: &ConversationId, client_id: &str) -> KeyPackage {
        self[conv_id]
            .group
            .members()
            .into_iter()
            .find(|k| k.credential().identity() == client_id.as_bytes())
            .unwrap()
            .clone()
    }
}

impl Index<&ConversationId> for MlsCentral {
    type Output = MlsConversation;

    fn index(&self, index: &ConversationId) -> &Self::Output {
        self.get_conversation(index).unwrap()
    }
}

impl IndexMut<&ConversationId> for MlsCentral {
    fn index_mut(&mut self, index: &ConversationId) -> &mut Self::Output {
        self.mls_groups.get_mut(index).unwrap()
    }
}

#[derive(Debug)]
pub struct FailValidationCallbacks;
impl CoreCryptoCallbacks for FailValidationCallbacks {
    fn authorize(&self, _: crate::prelude::ConversationId, _: String) -> bool {
        false
    }

    fn is_user_in_group(&self, _: Vec<u8>, _: Vec<Vec<u8>>) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct SuccessValidationCallbacks;
impl CoreCryptoCallbacks for SuccessValidationCallbacks {
    fn authorize(&self, _: crate::prelude::ConversationId, _: String) -> bool {
        true
    }

    fn is_user_in_group(&self, _: Vec<u8>, _: Vec<Vec<u8>>) -> bool {
        true
    }
}
