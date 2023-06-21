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
    mls::credential::{ext::CredentialExt, trust_anchor::PerDomainTrustAnchor, CredentialBundle},
    prelude::{
        CertificateBundle, Client, ClientId, ConversationId, ConversationMember, CryptoError, CryptoResult, MlsCentral,
        MlsCiphersuite, MlsConversation, MlsConversationDecryptMessage, MlsConversationInitBundle, MlsCredentialType,
        MlsCustomConfiguration, MlsError,
    },
    test_utils::{MessageExt, TestCase},
};
use openmls::prelude::{
    group_info::VerifiableGroupInfo, Credential, HpkePublicKey, KeyPackage, LeafNodeIndex, MlsMessageIn, MlsMessageOut,
    QueuedProposal, SignaturePublicKey, StagedCommit,
};
use openmls_traits::{types::SignatureScheme, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use core_crypto_keystore::entities::{
    EntityFindParams, MlsCredential, MlsEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage, MlsSignatureKeyPair,
};
use mls_crypto_provider::MlsCryptoProvider;
use wire_e2e_identity::prelude::WireIdentityReader;

impl MlsCentral {
    pub async fn get_one_key_package(&self, case: &TestCase) -> KeyPackage {
        let kps = self
            .get_or_create_client_keypackages(case.ciphersuite(), case.credential_type, 1)
            .await
            .unwrap();
        kps.first().unwrap().clone()
    }

    pub async fn key_package_count(&self, cs: MlsCiphersuite, ct: Option<MlsCredentialType>) -> usize {
        self.mls_backend
            .key_store()
            .find_all::<MlsKeyPackage>(EntityFindParams::default())
            .await
            .unwrap()
            .into_iter()
            .map(|kp| core_crypto_keystore::deser::<KeyPackage>(&kp.keypackage).unwrap())
            .filter(|kp| kp.ciphersuite() == *cs)
            .filter(|kp| {
                ct.map(|ct| kp.leaf_node().credential().credential_type() == ct.into())
                    .unwrap_or(true)
            })
            .count()
    }

    pub async fn rand_member(&self, case: &TestCase) -> ConversationMember {
        self.rand_member_of_type(case, case.credential_type).await
    }

    pub async fn rand_member_of_type(&self, case: &TestCase, ct: MlsCredentialType) -> ConversationMember {
        let client = self.mls_client.as_ref().unwrap();
        let id = client.id();

        client
            .generate_one_keypackage(&self.mls_backend, case.ciphersuite(), ct)
            .await
            .unwrap();

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
    pub async fn invite_all<const N: usize>(
        &mut self,
        case: &TestCase,
        id: &ConversationId,
        others: [&mut MlsCentral; N],
    ) -> CryptoResult<()> {
        let mut members = vec![];
        for cc in others {
            let member = cc.rand_member(case).await;
            members.push((cc, member));
        }
        self.invite_all_members::<N>(case, id, members.try_into().unwrap())
            .await
    }

    /// Streamlines the ceremony of adding a client and process its welcome message
    pub async fn invite_all_members<const N: usize>(
        &mut self,
        case: &TestCase,
        id: &ConversationId,
        mut others: [(&mut MlsCentral, ConversationMember); N],
    ) -> CryptoResult<()> {
        let size_before = self.get_conversation_unchecked(id).await.members().len();

        let mut members = others.iter().map(|(_, m)| m).cloned().collect::<Vec<_>>();
        let welcome = self.add_members_to_conversation(id, &mut members[..]).await?.welcome;

        for (other, ..) in others.as_mut() {
            other
                .process_welcome_message(welcome.clone().into(), case.custom_cfg())
                .await?;
        }

        self.commit_accepted(id).await?;
        assert_eq!(
            self.get_conversation_unchecked(id).await.members().len(),
            size_before + N
        );

        for (other, ..) in others.as_mut() {
            assert_eq!(
                other.get_conversation_unchecked(id).await.members().len(),
                size_before + N
            );
            self.try_talk_to(id, other).await?;
        }

        Ok(())
    }

    pub async fn try_join_from_group_info(
        &mut self,
        case: &TestCase,
        id: &ConversationId,
        group_info: VerifiableGroupInfo,
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

    pub async fn get_group_info(&mut self, id: &ConversationId) -> VerifiableGroupInfo {
        let conversation_arc = self.get_conversation(id).await.unwrap();
        let mut conversation = conversation_arc.write().await;
        let group = &mut conversation.group;
        let ct = group.credential().unwrap().credential_type();
        let cs = group.ciphersuite();
        let cb = self
            .mls_client
            .as_ref()
            .unwrap()
            .find_most_recent_credential_bundle(cs.into(), ct.into())
            .unwrap();

        let gi = group
            .export_group_info(&self.mls_backend, &cb.signature_key, true)
            .unwrap();
        gi.group_info().unwrap()
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
            .find(|k| k.credential.identity() == client_id.0.as_slice())
            .unwrap()
            .signature_key;

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
            .find(|k| k.credential.identity() == client_id.0.as_slice())
            .unwrap()
            .encryption_key
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
            .find(|k| k.credential.identity() == client_id.as_slice())
            .unwrap()
            .index
    }

    pub fn client_signature_key(&self, case: &TestCase) -> SignaturePublicKey {
        let mls_client = self.mls_client.as_ref().unwrap();
        let (sc, ct) = (case.signature_scheme(), case.credential_type);
        let cb = mls_client.find_most_recent_credential_bundle(sc, ct).unwrap();
        SignaturePublicKey::from(cb.signature_key.public())
    }

    pub async fn get_conversation_unchecked(
        &mut self,
        conv_id: &ConversationId,
    ) -> async_lock::RwLockWriteGuard<'_, MlsConversation> {
        let group_lock = self.mls_groups.get(conv_id).unwrap();
        group_lock.write().await
    }

    pub fn get_client_id(&self) -> ClientId {
        self.mls_client.as_ref().unwrap().id().clone()
    }

    pub async fn new_credential_bundle(&mut self, case: &TestCase) -> CredentialBundle {
        let client = self.mls_client.as_mut().unwrap();

        match case.credential_type {
            MlsCredentialType::Basic => {
                let cb = Client::new_basic_credential_bundle(client.id(), case.signature_scheme(), &self.mls_backend)
                    .unwrap();
                client
                    .save_identity(&self.mls_backend, None, case.signature_scheme(), cb)
                    .await
                    .unwrap()
            }
            MlsCredentialType::X509 => {
                let cert_bundle = CertificateBundle::rand(client.id(), case.cfg.ciphersuite.signature_algorithm());
                client
                    .save_new_x509_credential_bundle(&self.mls_backend, case.signature_scheme(), cert_bundle)
                    .await
                    .unwrap()
            }
        }
    }

    pub async fn find_most_recent_credential_bundle_for_conversation(
        &mut self,
        id: &ConversationId,
    ) -> Option<&CredentialBundle> {
        self.get_conversation(id)
            .await
            .unwrap()
            .read()
            .await
            .find_most_recent_credential_bundle(self.mls_client.as_ref().unwrap())
            .unwrap()
    }

    pub async fn find_most_recent_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Option<&CredentialBundle> {
        self.mls_client
            .as_ref()
            .unwrap()
            .identities
            .find_most_recent_credential_bundle(sc, ct)
    }

    pub async fn find_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
        pk: &SignaturePublicKey,
    ) -> Option<&CredentialBundle> {
        self.mls_client
            .as_ref()
            .unwrap()
            .identities
            .find_credential_bundle_by_public_key(sc, ct, pk)
    }

    pub async fn find_signature_keypair_from_keystore(&self, id: &[u8]) -> Option<MlsSignatureKeyPair> {
        self.mls_backend
            .key_store()
            .find::<MlsSignatureKeyPair>(id)
            .await
            .unwrap()
    }

    pub async fn find_hpke_private_key_from_keystore(&self, skp: &HpkePublicKey) -> Option<MlsHpkePrivateKey> {
        self.mls_backend
            .key_store()
            .find::<MlsHpkePrivateKey>(&skp.tls_serialize_detached().unwrap())
            .await
            .unwrap()
    }

    pub async fn find_credential_from_keystore(&self, cb: &CredentialBundle) -> Option<MlsCredential> {
        let credential = cb.credential.tls_serialize_detached().unwrap();
        self.mls_backend
            .key_store()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.credential[..] == credential)
    }

    pub async fn count_hpke_private_key(&self) -> usize {
        self.mls_backend.key_store().count::<MlsHpkePrivateKey>().await.unwrap()
    }

    pub async fn count_encryption_keypairs(&self) -> usize {
        self.mls_backend
            .key_store()
            .count::<MlsEncryptionKeyPair>()
            .await
            .unwrap()
    }

    pub async fn count_credentials_in_keystore(&self) -> usize {
        self.mls_backend.key_store().count::<MlsCredential>().await.unwrap()
    }

    pub async fn rotate_credential(&mut self, case: &TestCase, handle: &str, display_name: &str) -> CredentialBundle {
        let cid = &self.get_client_id();
        let new_cert = CertificateBundle::new(case.signature_scheme(), handle, display_name, Some(cid), None);
        let client = self.mls_client.as_mut().unwrap();
        client
            .save_new_x509_credential_bundle(&self.mls_backend, case.signature_scheme(), new_cert)
            .await
            .unwrap()
    }

    pub fn get_e2ei_client_id(&self) -> wire_e2e_identity::prelude::E2eiClientId {
        let cid = self.mls_client.as_ref().unwrap().id().clone();
        let cid = std::str::from_utf8(&cid.0).unwrap();
        wire_e2e_identity::prelude::E2eiClientId::try_from_qualified(cid).unwrap()
    }

    pub async fn verify_local_credential_rotated(
        &mut self,
        id: &ConversationId,
        new_handle: &str,
        new_display_name: &str,
    ) {
        let cid = &self.get_client_id();
        let group_identities = self.get_user_identities(id, &[cid]).await.unwrap();
        let group_identity = group_identities.first().unwrap();
        assert_eq!(&group_identity.client_id.as_bytes(), &cid.0);
        assert_eq!(group_identity.display_name, new_display_name);
        assert_eq!(group_identity.handle, new_handle);

        let cb = self
            .find_most_recent_credential_bundle_for_conversation(id)
            .await
            .unwrap()
            .clone();
        let local_identity = cb.credential().extract_identity().unwrap().unwrap();
        assert_eq!(&local_identity.client_id.as_bytes(), &cid.0);
        assert_eq!(local_identity.display_name, new_display_name);
        assert_eq!(local_identity.handle, new_handle);

        let credential = self.find_credential_from_keystore(&cb).await.unwrap();
        let credential = Credential::tls_deserialize_bytes(credential.credential.as_slice()).unwrap();
        assert_eq!(credential.identity(), &cid.0);
        let keystore_identity = credential.extract_identity().unwrap().unwrap();
        assert_eq!(keystore_identity.display_name, new_display_name);
        assert_eq!(keystore_identity.handle, new_handle);
    }

    pub fn verify_sender_identity(&self, case: &TestCase, decrypted: &MlsConversationDecryptMessage) {
        let mls_client = self.mls_client.as_ref().unwrap();
        let (sc, ct) = (case.signature_scheme(), case.credential_type);
        let cb = mls_client.find_most_recent_credential_bundle(sc, ct).unwrap();
        let sender_credential = cb.credential();

        if let openmls::prelude::MlsCredentialType::X509(openmls::prelude::Certificate {
            identity: dup_client_id,
            cert_data: cert_chain,
        }) = &sender_credential.mls_credential()
        {
            let leaf: Vec<u8> = cert_chain.get(0).map(|c| c.clone().into()).unwrap();
            let identity = leaf.as_slice().extract_identity().unwrap();
            let decr_identity = decrypted.identity.as_ref().unwrap();
            assert_eq!(decr_identity.client_id, identity.client_id);
            assert_eq!(decr_identity.client_id.as_bytes(), dup_client_id.as_slice());
            assert_eq!(decr_identity.handle, identity.handle);
            assert_eq!(decr_identity.display_name, identity.display_name);
            assert_eq!(decr_identity.domain, identity.domain);
        }
    }

    pub async fn add_per_domain_trust_anchor_unchecked(
        &mut self,
        id: &ConversationId,
        trust_anchor: PerDomainTrustAnchor,
    ) -> MlsMessageOut {
        self.get_conversation(id)
            .await
            .unwrap()
            .write()
            .await
            .add_per_domain_trust_anchor_unchecked(trust_anchor, self.mls_client().unwrap(), &self.mls_backend)
            .await
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

    pub fn extensions(&self) -> &openmls::prelude::Extensions {
        self.group.export_group_context().extensions()
    }

    pub fn per_domain_trust_anchors(&self) -> Vec<PerDomainTrustAnchor> {
        self.extensions()
            .per_domain_trust_anchors()
            .unwrap()
            .iter()
            .map(|a| PerDomainTrustAnchor::try_from(a).unwrap())
            .collect()
    }

    pub async fn add_per_domain_trust_anchor_unchecked(
        &mut self,
        trust_anchor: PerDomainTrustAnchor,
        client: &Client,
        backend: &MlsCryptoProvider,
    ) -> MlsMessageOut {
        let context = self.group.export_group_context();
        let mut extensions = context.extensions().clone();
        let mls_trust_anchor = trust_anchor.into_mls_unchecked();
        extensions.add_or_replace(openmls::prelude::Extension::PerDomainTrustAnchor(vec![
            mls_trust_anchor,
        ]));
        let cs = self.ciphersuite();
        let ct = self.own_credential_type().unwrap();
        let signer = &client
            .find_most_recent_credential_bundle(cs.signature_algorithm(), ct)
            .unwrap()
            .signature_key;
        let (commit, _, _) = self.group.update_extensions(backend, signer, extensions).await.unwrap();
        self.persist_group_when_changed(backend, false).await.unwrap();
        commit
    }
}

impl Client {
    pub(crate) async fn init_x509_credential_bundle_if_missing(
        &mut self,
        backend: &MlsCryptoProvider,
        sc: SignatureScheme,
        cb: CertificateBundle,
    ) -> CryptoResult<()> {
        let existing_cb = self
            .identities
            .find_most_recent_credential_bundle(sc, MlsCredentialType::X509)
            .is_none();
        if existing_cb {
            self.save_new_x509_credential_bundle(backend, sc, cb).await.unwrap();
        }
        Ok(())
    }

    pub(crate) async fn generate_one_keypackage(
        &self,
        backend: &MlsCryptoProvider,
        cs: MlsCiphersuite,
        ct: MlsCredentialType,
    ) -> CryptoResult<KeyPackage> {
        let cb = self
            .find_most_recent_credential_bundle(cs.signature_algorithm(), ct)
            .ok_or(CryptoError::MlsNotInitialized)?;
        self.generate_one_keypackage_from_credential_bundle(backend, cs, cb)
            .await
    }
}
