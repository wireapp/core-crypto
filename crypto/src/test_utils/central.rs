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

use openmls::credentials::MlsCredentialType;

use crate::{
    prelude::{
        ClientId, ConversationId, ConversationMember, CryptoError, CryptoResult, MlsCentral, MlsConversation,
        MlsConversationDecryptMessage, MlsConversationInitBundle, MlsCustomConfiguration, MlsError,
    },
    test_utils::TestCase,
};

use openmls::prelude::{
    KeyPackage, LeafNodeIndex, MlsMessageIn, MlsMessageOut, QueuedProposal, SignaturePublicKey, StagedCommit,
};

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
        other.process_welcome_message(welcome.into(), custom_cfg).await?;
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

    pub async fn try_join_from_group_info(
        &mut self,
        case: &TestCase,
        id: &ConversationId,
        group_info: MlsMessageIn,
        others: Vec<&mut Self>,
    ) -> CryptoResult<()> {
        use tls_codec::Serialize as _;

        let MlsConversationInitBundle {
            conversation_id,
            commit,
            ..
        } = self
            .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
            .await?;
        self.merge_pending_group_from_external_commit(&conversation_id).await?;
        assert_eq!(conversation_id.as_slice(), id.as_slice());
        for other in others {
            let commit = commit.tls_serialize_detached().map_err(MlsError::from)?;
            other.decrypt_message(id, commit).await?;
            self.try_talk_to(id, other).await?;
        }
        Ok(())
    }

    pub async fn try_join_from_welcome(
        &mut self,
        id: &ConversationId,
        welcome: MlsMessageIn,
        custom_cfg: MlsCustomConfiguration,
        others: Vec<&mut Self>,
    ) -> CryptoResult<()> {
        self.process_welcome_message(welcome, custom_cfg).await?;
        for other in others {
            self.try_talk_to(id, other).await?;
        }
        Ok(())
    }

    pub async fn get_group_info(&mut self, id: &ConversationId) -> MlsMessageOut {
        let conversation_arc = self.get_conversation(id).await.unwrap();
        let mut conversation = conversation_arc.write().await;
        let group = &mut conversation.group;
        let ct = group.credential().unwrap().credential_type();
        let cs = group.ciphersuite();
        let cb = self
            .mls_client
            .as_ref()
            .unwrap()
            .find_credential_bundle(cs.into(), ct.into())
            .unwrap();

        group
            .export_group_info(&self.mls_backend, &cb.signature_key, true)
            .unwrap()
    }

    /// Finds the [SignaturePublicKey] of a [Client] within a [MlsGroup]
    pub async fn signature_key_of(&mut self, conv_id: &ConversationId, client_id: ClientId) -> SignaturePublicKey {
        let sign_key = self
            .mls_groups
            .get_fetch(conv_id, self.mls_backend.borrow_keystore_mut(), None)
            .await
            .unwrap()
            .unwrap()
            .read()
            .await
            .group
            .members()
            .into_iter()
            .find(|k| k.credential.identity() == client_id.0.as_slice())
            .unwrap()
            .signature_key
            .clone();

        SignaturePublicKey::from(sign_key)
    }

    /// Finds the HPKE Public key of a [Client] within a [MlsGroup]
    pub async fn encryption_key_of(&mut self, conv_id: &ConversationId, client_id: ClientId) -> Vec<u8> {
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
            .find(|k| k.credential.identity() == client_id.0.as_slice())
            .unwrap()
            .encryption_key
            .clone()
    }

    /// Finds the [LeafNodeIndex] of a [Client] within a [MlsGroup]
    pub async fn index_of(&mut self, conv_id: &ConversationId, client_id: ClientId) -> LeafNodeIndex {
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
            .find(|k| k.credential.identity() == client_id.as_slice())
            .unwrap()
            .index
    }

    pub fn client_signature_key(&self, case: &TestCase) -> SignaturePublicKey {
        let mls_client = self.mls_client.as_ref().unwrap();
        let (cs, ct) = (case.ciphersuite(), case.credential_type);
        let cb = mls_client.find_credential_bundle(cs, ct).unwrap();
        SignaturePublicKey::from(cb.signature_key.public())
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

    pub fn verify_sender_identity(&self, case: &TestCase, _decrypted: &MlsConversationDecryptMessage) {
        let mls_client = self.mls_client.as_ref().unwrap();
        let (cs, ct) = (case.ciphersuite(), case.credential_type);
        let cb = mls_client.find_credential_bundle(cs, ct).unwrap();
        let sender_credential = cb.credential();

        if let MlsCredentialType::X509(openmls::prelude::Certificate {
            identity: _dup_client_id,
            cert_data: _cert_chain,
        }) = &sender_credential.mls_credential()
        {
            // TODO
            /*
            let leaf: Vec<u8> = cert_chain.get(0).map(|c| c.clone().into()).unwrap();
            let identity = leaf.extract_identity().unwrap();
            let decr_identity = decrypted.identity.as_ref().unwrap();
            assert_eq!(decr_identity.client_id, identity.client_id);
            assert_eq!(decr_identity.client_id.as_bytes(), dup_client_id.as_slice());
            assert_eq!(decr_identity.handle, identity.handle);
            assert_eq!(decr_identity.display_name, identity.display_name);
            assert_eq!(decr_identity.domain, identity.domain);
            */
        }
    }
}

impl MlsConversation {
    pub fn signature_keys(&self) -> impl Iterator<Item = SignaturePublicKey> + '_ {
        self.group
            .members()
            .map(|m| m.signature_key)
            .map(|mpk| SignaturePublicKey::from(mpk.as_slice()))
    }

    pub fn encryption_keys(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.group.members().map(|m| m.encryption_key)
    }
}
