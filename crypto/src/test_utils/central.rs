// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::prelude::{
    ConversationId, ConversationMember, CryptoError, CryptoResult, MlsCentral, MlsConversation,
    MlsConversationInitBundle, MlsCustomConfiguration, MlsError,
};
use openmls::prelude::{
    KeyPackage, KeyPackageBundle, PublicGroupState, QueuedProposal, SignaturePublicKey, StagedCommit,
    VerifiablePublicGroupState, Welcome,
};

impl MlsCentral {
    pub async fn get_one_key_package(&self) -> KeyPackage {
        self.get_one_key_package_bundle().await.key_package().clone()
    }

    pub async fn get_one_key_package_bundle(&self) -> KeyPackageBundle {
        self.client_keypackages(1).await.unwrap().first().unwrap().clone()
    }

    pub async fn rnd_member(&self) -> ConversationMember {
        let id = self.mls_client.as_ref().unwrap().id();
        self.mls_client
            .as_ref()
            .unwrap()
            .gen_keypackage(&self.mls_backend)
            .await
            .unwrap();
        let clients = std::collections::HashMap::from([(
            id.clone(),
            self.mls_client
                .as_ref()
                .unwrap()
                .keypackages(&self.mls_backend)
                .await
                .unwrap(),
        )]);
        ConversationMember {
            id: id.to_vec(),
            clients,
            local_client: Some(self.mls_client.as_ref().unwrap().clone()),
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
    pub async fn invite(
        &mut self,
        id: &ConversationId,
        other: &mut MlsCentral,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<()> {
        let size_before = self[id].members().len();
        let welcome = self
            .add_members_to_conversation(id, &mut [other.rnd_member().await])
            .await?
            .welcome;
        other.process_welcome_message(welcome, custom_cfg).await?;
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
        custom_cfg: MlsCustomConfiguration,
        others: Vec<&mut Self>,
    ) -> CryptoResult<()> {
        use tls_codec::{Deserialize as _, Serialize as _};
        let public_group_state = public_group_state.tls_serialize_detached().map_err(MlsError::from)?;
        let public_group_state =
            VerifiablePublicGroupState::tls_deserialize(&mut public_group_state.as_slice()).map_err(MlsError::from)?;
        let MlsConversationInitBundle {
            conversation_id,
            commit,
            ..
        } = self.join_by_external_commit(public_group_state, custom_cfg).await?;
        self.merge_pending_group_from_external_commit(&conversation_id).await?;
        assert_eq!(conversation_id.as_slice(), id.as_slice());
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
        custom_cfg: MlsCustomConfiguration,
        others: Vec<&mut Self>,
    ) -> CryptoResult<()> {
        self.process_welcome_message(welcome, custom_cfg).await?;
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

    pub fn client_signature_key(&self) -> &SignaturePublicKey {
        self.mls_client
            .as_ref()
            .unwrap()
            .credentials()
            .credential()
            .signature_key()
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
