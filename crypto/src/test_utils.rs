#![cfg(test)]

use std::{
    collections::HashMap,
    ops::{Index, IndexMut},
};

use openmls::prelude::{
    KeyPackage, KeyPackageBundle, PublicGroupState, QueuedProposal, StagedCommit, VerifiablePublicGroupState, Welcome,
};
pub use rstest::*;
pub use rstest_reuse::{self, *};

use crate::{
    config::MlsCentralConfiguration, credential::CredentialSupplier, member::ConversationMember, ConversationId,
    CoreCryptoCallbacks, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsConversationConfiguration,
    MlsError,
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

#[cfg(debug_assertions)]
pub const GROUP_SAMPLE_SIZE: usize = 9;
#[cfg(not(debug_assertions))]
pub const GROUP_SAMPLE_SIZE: usize = 99;

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

    pub async fn try_join_from_public_group_state(
        &mut self,
        id: &ConversationId,
        public_group_state: VerifiablePublicGroupState,
        others: Vec<&mut Self>,
    ) -> CryptoResult<()> {
        use tls_codec::{Deserialize as _, Serialize as _};
        let public_group_state = public_group_state.tls_serialize_detached().map_err(MlsError::from)?;
        let public_group_state =
            VerifiablePublicGroupState::tls_deserialize(&mut public_group_state.as_slice()).map_err(MlsError::from)?;
        let (group_id, commit) = self.join_by_external_commit(public_group_state).await?;
        self.merge_pending_group_from_external_commit(group_id.as_slice(), MlsConversationConfiguration::default())
            .await?;
        assert_eq!(group_id.as_slice(), id.as_slice());
        for other in others {
            let commit = commit.to_bytes().map_err(MlsError::from)?;
            other.decrypt_message(id, commit).await?;
            self.talk_to(id, other).await?;
        }
        Ok(())
    }

    pub async fn try_join_from_welcome(
        &mut self,
        id: &ConversationId,
        welcome: Welcome,
        others: Vec<&mut Self>,
    ) -> CryptoResult<()> {
        self.process_welcome_message(welcome, MlsConversationConfiguration::default())
            .await?;
        for other in others {
            self.talk_to(id, other).await?;
        }
        Ok(())
    }

    pub async fn verifiable_public_group_state(&self, id: &ConversationId) -> VerifiablePublicGroupState {
        use tls_codec::{Deserialize as _, Serialize as _};
        let public_group_state = self.public_group_state(id).await.tls_serialize_detached().unwrap();
        VerifiablePublicGroupState::tls_deserialize(&mut public_group_state.as_slice()).unwrap()
    }

    pub async fn public_group_state(&self, id: &ConversationId) -> PublicGroupState {
        self.get_conversation(id)
            .unwrap()
            .group
            .export_public_group_state(&self.mls_backend)
            .await
            .unwrap()
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
pub struct ValidationCallbacks {
    authorize: bool,
    is_user_in_group: bool,
}

impl Default for ValidationCallbacks {
    fn default() -> Self {
        Self {
            authorize: true,
            is_user_in_group: true,
        }
    }
}

impl ValidationCallbacks {
    pub fn new(authorize: bool, is_user_in_group: bool) -> Self {
        Self {
            authorize,
            is_user_in_group,
        }
    }
}

impl CoreCryptoCallbacks for ValidationCallbacks {
    fn authorize(&self, _: crate::prelude::ConversationId, _: String) -> bool {
        self.authorize
    }

    fn is_user_in_group(&self, _: Vec<u8>, _: Vec<Vec<u8>>) -> bool {
        self.is_user_in_group
    }
}
