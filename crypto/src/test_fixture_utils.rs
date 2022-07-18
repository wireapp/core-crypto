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
    credential::CredentialSupplier, member::ConversationMember, ConversationId, CryptoResult, MlsCentral,
    MlsConversation,
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
