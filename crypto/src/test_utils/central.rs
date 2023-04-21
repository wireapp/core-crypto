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

use crate::{
    prelude::{
        ClientId, ConversationId, ConversationMember, CryptoError, CryptoResult, MlsCentral, MlsConversation,
        MlsConversationDecryptMessage, MlsConversationInitBundle, MlsCustomConfiguration, MlsError,
    },
    test_utils::TestCase,
};
use openmls::prelude::{
    KeyPackage, MlsCredentialType, PublicGroupState, QueuedProposal, SignaturePublicKey, StagedCommit,
    VerifiablePublicGroupState, Welcome,
};
use wire_e2e_identity::prelude::WireIdentityReader;

impl MlsCentral {
    pub async fn get_one_key_package(&self, case: &TestCase) -> KeyPackage {
        let kps = self
            .get_or_create_client_keypackages(case.ciphersuite(), 1)
            .await
            .unwrap();
        kps.first().unwrap().clone()
    }

    pub async fn rand_member(&self) -> ConversationMember {
        let client = self.mls_client.as_ref().unwrap();
        let id = client.id();
        client.generate_keypackages(&self.mls_backend).await.unwrap();
        let clients =
            std::collections::HashMap::from([(id.clone(), client.find_keypackages(&self.mls_backend).await.unwrap())]);
        ConversationMember {
            id: id.to_vec(),
            clients,
            local_client: Some(client.clone()),
        }
    }

    pub async fn pending_proposals(&mut self, id: &ConversationId) -> Vec<QueuedProposal> {
        self.get_conversation_unchecked(id)
            .await
            .group
            .pending_proposals()
            .cloned()
            .collect::<Vec<_>>()
    }

    pub async fn pending_commit(&mut self, id: &ConversationId) -> Option<StagedCommit> {
        self.get_conversation_unchecked(id)
            .await
            .group
            .pending_commit()
            .cloned()
    }

    pub async fn try_talk_to(&mut self, id: &ConversationId, other: &mut MlsCentral) -> CryptoResult<()> {
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
        let size_before = self.get_conversation_unchecked(id).await.members().len();
        let welcome = self
            .add_members_to_conversation(id, &mut [other.rand_member().await])
            .await?
            .welcome;
        other.process_welcome_message(welcome, custom_cfg).await?;
        self.commit_accepted(id).await?;
        assert_eq!(
            self.get_conversation_unchecked(id).await.members().len(),
            size_before + 1
        );
        assert_eq!(
            other.get_conversation_unchecked(id).await.members().len(),
            size_before + 1
        );
        self.try_talk_to(id, other).await?;
        Ok(())
    }

    pub async fn try_join_from_public_group_state(
        &mut self,
        case: &crate::test_utils::TestCase,
        id: &ConversationId,
        public_group_state: VerifiablePublicGroupState,
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
        } = self
            .join_by_external_commit(public_group_state, case.custom_cfg(), case.credential_type)
            .await?;
        self.merge_pending_group_from_external_commit(&conversation_id).await?;
        assert_eq!(conversation_id.as_slice(), id.as_slice());
        for other in others {
            let commit = commit.to_bytes().map_err(MlsError::from)?;
            other.decrypt_message(id, commit).await?;
            self.try_talk_to(id, other).await?;
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
            self.try_talk_to(id, other).await?;
        }
        Ok(())
    }

    pub async fn verifiable_public_group_state(&mut self, id: &ConversationId) -> VerifiablePublicGroupState {
        use tls_codec::{Deserialize as _, Serialize as _};
        let public_group_state = self.public_group_state(id).await.tls_serialize_detached().unwrap();
        VerifiablePublicGroupState::tls_deserialize(&mut public_group_state.as_slice()).unwrap()
    }

    pub async fn public_group_state(&mut self, id: &ConversationId) -> PublicGroupState {
        self.get_conversation(id)
            .await
            .unwrap()
            .write()
            .await
            .group
            .export_public_group_state(&self.mls_backend)
            .await
            .unwrap()
    }

    /// Finds the [KeyPackage] of a [Client] within a [MlsGroup]
    pub async fn key_package_of(&mut self, conv_id: &ConversationId, client_id: ClientId) -> KeyPackage {
        self.mls_groups
            .get_fetch(conv_id, self.mls_backend.borrow_keystore_mut(), None)
            .await
            .unwrap()
            .unwrap()
            .read()
            .await
            .group
            .members()
            .into_iter()
            .find(|k| k.credential().identity() == client_id.0.as_slice())
            .unwrap()
            .clone()
    }

    pub fn client_signature_key(&self, case: &TestCase) -> &SignaturePublicKey {
        let mls_client = self.mls_client.as_ref().unwrap();
        let (cs, ct) = (case.ciphersuite(), case.credential_type);
        let cb = mls_client.find_credential_bundle(cs, ct).unwrap();
        cb.credential().signature_key()
    }

    pub async fn get_conversation_unchecked(
        &mut self,
        conv_id: &ConversationId,
    ) -> async_lock::RwLockWriteGuard<'_, MlsConversation> {
        let group_lock = self.mls_groups.get(conv_id).unwrap();
        group_lock.write().await
    }

    pub fn read_client_id(&self) -> ClientId {
        self.mls_client.as_ref().unwrap().id().clone()
    }

    pub fn verify_sender_identity(&self, case: &TestCase, decrypted: &MlsConversationDecryptMessage) {
        let mls_client = self.mls_client.as_ref().unwrap();
        let (cs, ct) = (case.ciphersuite(), case.credential_type);
        let cb = mls_client.find_credential_bundle(cs, ct).unwrap();
        let sender_credential = cb.credential();

        if let MlsCredentialType::X509(openmls::prelude::MlsCertificate {
            identity: dup_client_id,
            cert_chain,
        }) = &sender_credential.credential
        {
            let leaf = cert_chain.get(0).map(|c| c.clone().into_vec()).unwrap();
            let identity = leaf.extract_identity().unwrap();
            let decr_identity = decrypted.identity.as_ref().unwrap();
            assert_eq!(decr_identity.client_id, identity.client_id);
            assert_eq!(decr_identity.client_id.as_bytes(), dup_client_id.as_slice());
            assert_eq!(decr_identity.handle, identity.handle);
            assert_eq!(decr_identity.display_name, identity.display_name);
            assert_eq!(decr_identity.domain, identity.domain);
        }
    }
}
