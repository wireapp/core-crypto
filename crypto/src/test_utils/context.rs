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

use core_crypto_keystore::connection::FetchFromDatabase;
use core_crypto_keystore::entities::{
    EntityFindParams, MlsCredential, MlsEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage, MlsSignatureKeyPair,
};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{
    group_info::VerifiableGroupInfo, Credential, CredentialWithKey, CryptoConfig, ExternalSender, HpkePublicKey,
    KeyPackage, KeyPackageIn, LeafNodeIndex, Lifetime, MlsMessageIn, QueuedProposal, SignaturePublicKey, StagedCommit,
};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::{types::SignatureScheme, OpenMlsCryptoProvider};
use std::sync::Arc;
use tls_codec::{Deserialize, Serialize};
use wire_e2e_identity::prelude::WireIdentityReader;
use x509_cert::der::Encode;

use crate::group_store::GroupStore;
use crate::test_utils::ClientContext;
use crate::{
    e2e_identity::{
        device_status::DeviceStatus,
        id::{QualifiedE2eiClientId, WireQualifiedClientId},
    },
    mls::credential::{ext::CredentialExt, CredentialBundle},
    prelude::{
        CertificateBundle, Client, ClientId, ConversationId, CryptoError, CryptoResult, MlsCiphersuite,
        MlsConversation, MlsConversationConfiguration, MlsConversationDecryptMessage, MlsConversationInitBundle,
        MlsCredentialType, MlsCustomConfiguration, MlsError, WireIdentity,
    },
    test_utils::{x509::X509Certificate, MessageExt, TestCase},
};

#[allow(clippy::redundant_static_lifetimes)]
pub const TEAM: &'static str = "world";

impl ClientContext {
    pub async fn get_one_key_package(&self, case: &TestCase) -> KeyPackage {
        let kps = self
            .context
            .get_or_create_client_keypackages(case.ciphersuite(), case.credential_type, 1)
            .await
            .unwrap();
        kps.first().unwrap().clone()
    }

    pub async fn new_keypackage(&self, case: &TestCase, lifetime: Lifetime) -> KeyPackage {
        let cb = self
            .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
            .await
            .unwrap();
        KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .leaf_node_capabilities(MlsConversationConfiguration::default_leaf_capabilities())
            .build(
                CryptoConfig {
                    ciphersuite: case.ciphersuite().into(),
                    version: openmls::versions::ProtocolVersion::default(),
                },
                &self.context.mls_provider().await.unwrap(),
                &cb.signature_key,
                CredentialWithKey {
                    credential: cb.credential.clone(),
                    signature_key: cb.signature_key.public().into(),
                },
            )
            .await
            .unwrap()
    }

    pub async fn count_key_package(&self, cs: MlsCiphersuite, ct: Option<MlsCredentialType>) -> usize {
        self.context
            .mls_provider()
            .await
            .unwrap()
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

    pub async fn rand_key_package(&self, case: &TestCase) -> KeyPackageIn {
        self.rand_key_package_of_type(case, case.credential_type).await
    }

    pub async fn rand_key_package_of_type(&self, case: &TestCase, ct: MlsCredentialType) -> KeyPackageIn {
        let client = self.context.mls_client().await.unwrap();
        client
            .generate_one_keypackage(&self.context.mls_provider().await.unwrap(), case.ciphersuite(), ct)
            .await
            .unwrap()
            .into()
    }

    pub async fn pending_proposals(&mut self, id: &ConversationId) -> Vec<QueuedProposal> {
        self.get_conversation_unchecked(id)
            .await
            .group
            .pending_proposals()
            .cloned()
            .collect::<Vec<_>>()
    }

    pub async fn pending_commit(&self, id: &ConversationId) -> Option<StagedCommit> {
        self.get_conversation_unchecked(id)
            .await
            .group
            .pending_commit()
            .cloned()
    }

    pub async fn try_talk_to(&self, id: &ConversationId, other: &Self) -> CryptoResult<()> {
        let msg = b"Hello other";
        let encrypted = self.context.encrypt_message(id, msg).await?;
        let decrypted = other
            .context
            .decrypt_message(id, encrypted)
            .await?
            .app_msg
            .ok_or(CryptoError::ImplementationError)?;
        assert_eq!(&msg[..], &decrypted[..]);
        // other --> self
        let msg = b"Hello self";
        let encrypted = other.context.encrypt_message(id, msg).await?;
        let decrypted = self
            .context
            .decrypt_message(id, encrypted)
            .await?
            .app_msg
            .ok_or(CryptoError::ImplementationError)?;
        assert_eq!(&msg[..], &decrypted[..]);
        Ok(())
    }

    /// Streamlines the ceremony of adding a client and process its welcome message
    pub async fn invite_all<const N: usize>(
        &self,
        case: &TestCase,
        id: &ConversationId,
        others: [&Self; N],
    ) -> CryptoResult<()> {
        let mut kps = vec![];
        for cc in others {
            let kp = cc.rand_key_package(case).await;
            kps.push((cc, kp));
        }
        self.invite_all_members::<N>(case, id, kps.try_into().unwrap()).await
    }

    /// Streamlines the ceremony of adding a client and process its welcome message
    pub async fn invite_all_members<const N: usize>(
        &self,
        case: &TestCase,
        id: &ConversationId,
        others: [(&Self, KeyPackageIn); N],
    ) -> CryptoResult<()> {
        let size_before = self.get_conversation_unchecked(id).await.members().len();

        let kps = others.iter().map(|(_, kp)| kp).cloned().collect::<Vec<_>>();
        let welcome = self.context.add_members_to_conversation(id, kps).await?.welcome;

        for (other, ..) in &others {
            other
                .context
                .process_welcome_message(welcome.clone().into(), case.custom_cfg())
                .await?;
        }

        self.context.commit_accepted(id).await?;
        assert_eq!(
            self.get_conversation_unchecked(id).await.members().len(),
            size_before + N
        );

        for (other, ..) in &others {
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
        others: Vec<&Self>,
    ) -> CryptoResult<()> {
        use tls_codec::Serialize as _;

        let MlsConversationInitBundle {
            conversation_id,
            commit,
            ..
        } = self
            .context
            .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
            .await?;
        self.context
            .merge_pending_group_from_external_commit(&conversation_id)
            .await?;
        assert_eq!(conversation_id.as_slice(), id.as_slice());
        for other in others {
            let commit = commit.tls_serialize_detached().map_err(MlsError::from)?;
            other.context.decrypt_message(id, commit).await.unwrap();
            self.try_talk_to(id, other).await?;
        }
        Ok(())
    }

    pub async fn try_join_from_welcome(
        &mut self,
        id: &ConversationId,
        welcome: MlsMessageIn,
        custom_cfg: MlsCustomConfiguration,
        others: Vec<&Self>,
    ) -> CryptoResult<()> {
        self.context.process_welcome_message(welcome, custom_cfg).await?;
        for other in others {
            self.try_talk_to(id, other).await?;
        }
        Ok(())
    }

    pub async fn get_group_info(&self, id: &ConversationId) -> VerifiableGroupInfo {
        let conversation_arc = self.context.get_conversation(id).await.unwrap();
        let mut conversation = conversation_arc.write().await;
        let group = &mut conversation.group;
        let ct = group.credential().unwrap().credential_type();
        let cs = group.ciphersuite();
        let client = self.client().await;
        let cb = client
            .find_most_recent_credential_bundle(cs.into(), ct.into())
            .await
            .unwrap();

        let gi = group
            .export_group_info(&self.context.mls_provider().await.unwrap(), &cb.signature_key, true)
            .unwrap();
        gi.group_info().unwrap()
    }

    /// Finds the [SignaturePublicKey] of a [Client] within a [MlsGroup]
    pub async fn signature_key_of(&self, conv_id: &ConversationId, client_id: ClientId) -> SignaturePublicKey {
        let sign_key = self
            .context
            .mls_groups()
            .await
            .unwrap()
            .get_fetch(conv_id, &self.context.keystore().await.unwrap(), None)
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
    pub async fn encryption_key_of(&self, conv_id: &ConversationId, client_id: ClientId) -> Vec<u8> {
        self.context
            .mls_groups()
            .await
            .unwrap()
            .get_fetch(conv_id, &self.context.keystore().await.unwrap(), None)
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
    pub async fn index_of(&self, conv_id: &ConversationId, client_id: ClientId) -> LeafNodeIndex {
        self.context
            .mls_groups()
            .await
            .unwrap()
            .get_fetch(conv_id, &self.context.keystore().await.unwrap(), None)
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

    pub async fn client_signature_key(&self, case: &TestCase) -> SignaturePublicKey {
        let (sc, ct) = (case.signature_scheme(), case.credential_type);
        let client = self.client().await;
        let cb = client.find_most_recent_credential_bundle(sc, ct).await.unwrap();
        SignaturePublicKey::from(cb.signature_key.public())
    }

    pub async fn get_conversation_unchecked(&self, conv_id: &ConversationId) -> MlsConversation {
        GroupStore::fetch_from_keystore(conv_id, &self.context.keystore().await.unwrap(), None)
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn get_user_id(&self) -> String {
        WireQualifiedClientId::from(self.get_client_id().await).get_user_id()
    }

    pub async fn new_credential_bundle(
        &mut self,
        case: &TestCase,
        signer: Option<&X509Certificate>,
    ) -> CredentialBundle {
        let backend = &self.context.mls_provider().await.unwrap();
        let transaction = &self.context.keystore().await.unwrap();
        let client = self.client().await;
        let client_id = client.id().await.unwrap();

        match case.credential_type {
            MlsCredentialType::Basic => {
                let cb = Client::new_basic_credential_bundle(&client_id, case.signature_scheme(), backend).unwrap();
                client
                    .save_identity(&backend.keystore(), None, case.signature_scheme(), cb)
                    .await
                    .unwrap()
            }
            MlsCredentialType::X509 => {
                let cert_bundle = CertificateBundle::rand(&client_id, signer.unwrap());
                client
                    .save_new_x509_credential_bundle(transaction, case.signature_scheme(), cert_bundle)
                    .await
                    .unwrap()
            }
        }
    }

    pub async fn find_most_recent_credential_bundle_for_conversation(
        &self,
        id: &ConversationId,
    ) -> Option<Arc<CredentialBundle>> {
        self.context
            .get_conversation(id)
            .await
            .unwrap()
            .read()
            .await
            .find_most_recent_credential_bundle(&self.client().await)
            .await
            .ok()
    }

    pub async fn find_most_recent_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Option<Arc<CredentialBundle>> {
        self.client()
            .await
            .find_most_recent_credential_bundle(sc, ct)
            .await
            .ok()
    }

    pub async fn find_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
        pk: &SignaturePublicKey,
    ) -> Option<Arc<CredentialBundle>> {
        self.client()
            .await
            .find_credential_bundle_by_public_key(sc, ct, pk)
            .await
            .ok()
    }

    pub async fn find_signature_keypair_from_keystore(&self, id: &[u8]) -> Option<MlsSignatureKeyPair> {
        self.context
            .keystore()
            .await
            .unwrap()
            .find::<MlsSignatureKeyPair>(id)
            .await
            .unwrap()
    }

    pub async fn find_hpke_private_key_from_keystore(&self, skp: &HpkePublicKey) -> Option<MlsHpkePrivateKey> {
        self.context
            .keystore()
            .await
            .unwrap()
            .find::<MlsHpkePrivateKey>(&skp.tls_serialize_detached().unwrap())
            .await
            .unwrap()
    }

    pub async fn find_credential_from_keystore(&self, cb: &CredentialBundle) -> Option<MlsCredential> {
        let credential = cb.credential.tls_serialize_detached().unwrap();
        self.context
            .keystore()
            .await
            .unwrap()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.credential[..] == credential)
    }

    pub async fn count_hpke_private_key(&self) -> usize {
        self.context
            .keystore()
            .await
            .unwrap()
            .count::<MlsHpkePrivateKey>()
            .await
            .unwrap()
    }

    pub async fn count_encryption_keypairs(&self) -> usize {
        self.context
            .keystore()
            .await
            .unwrap()
            .count::<MlsEncryptionKeyPair>()
            .await
            .unwrap()
    }

    pub async fn count_credentials_in_keystore(&self) -> usize {
        self.context
            .keystore()
            .await
            .unwrap()
            .count::<MlsCredential>()
            .await
            .unwrap()
    }

    pub async fn rotate_credential(
        &self,
        case: &TestCase,
        handle: &str,
        display_name: &str,
        existing_cert: &X509Certificate,
        signer: &X509Certificate,
    ) -> CredentialBundle {
        let cid = QualifiedE2eiClientId::try_from(self.get_client_id().await.as_slice()).unwrap();
        let new_cert = CertificateBundle::new(
            handle,
            display_name,
            Some(&cid),
            Some(existing_cert.pki_keypair.clone()),
            signer,
        );
        let client = self.client().await;
        client
            .save_new_x509_credential_bundle(
                &self.context.keystore().await.unwrap(),
                case.signature_scheme(),
                new_cert,
            )
            .await
            .unwrap()
    }

    pub async fn get_e2ei_client_id(&self) -> wire_e2e_identity::prelude::E2eiClientId {
        let cid = self.get_client_id().await;
        let cid = std::str::from_utf8(&cid.0).unwrap();
        let cid: String = cid.parse::<QualifiedE2eiClientId>().unwrap().try_into().unwrap();
        wire_e2e_identity::prelude::E2eiClientId::try_from_qualified(&cid).unwrap()
    }

    pub fn get_intermediate_ca(&self) -> Option<&X509Certificate> {
        self.x509_test_chain
            .as_ref()
            .as_ref()
            .map(|chain| chain.find_local_intermediate_ca())
    }

    pub async fn verify_local_credential_rotated(&self, id: &ConversationId, new_handle: &str, new_display_name: &str) {
        let new_handle = format!("wireapp://%40{new_handle}@world.com");
        // verify the identity in..
        // the MLS group
        let cid = self.get_client_id().await;
        let group_identities = self.context.get_device_identities(id, &[cid.clone()]).await.unwrap();
        let group_identity = group_identities.first().unwrap();
        assert_eq!(group_identity.client_id.as_bytes(), cid.0.as_slice());
        assert_eq!(
            group_identity.x509_identity.as_ref().unwrap().display_name,
            new_display_name
        );
        assert_eq!(group_identity.x509_identity.as_ref().unwrap().handle, new_handle);
        assert_eq!(group_identity.status, DeviceStatus::Valid);
        assert!(!group_identity.thumbprint.is_empty());

        // the in-memory mapping
        let cb = self
            .find_most_recent_credential_bundle_for_conversation(id)
            .await
            .unwrap()
            .clone();
        let cs = self.get_conversation_unchecked(id).await.ciphersuite();
        let local_identity = cb.to_mls_credential_with_key().extract_identity(cs, None).unwrap();
        assert_eq!(&local_identity.client_id.as_bytes(), &cid.0);
        assert_eq!(
            local_identity.x509_identity.as_ref().unwrap().display_name,
            new_display_name
        );
        assert_eq!(local_identity.x509_identity.as_ref().unwrap().handle, new_handle);
        assert_eq!(local_identity.status, DeviceStatus::Valid);
        assert!(!local_identity.thumbprint.is_empty());

        // the keystore
        let signature_key = self
            .find_signature_keypair_from_keystore(cb.signature_key.public())
            .await
            .unwrap();
        let signature_key = SignaturePublicKey::from(signature_key.pk.as_slice());
        let credential = self.find_credential_from_keystore(&cb).await.unwrap();
        let credential = Credential::tls_deserialize(&mut credential.credential.as_slice()).unwrap();
        let credential = CredentialWithKey {
            credential,
            signature_key,
        };

        assert_eq!(credential.credential.identity(), &cid.0);
        let keystore_identity = credential.extract_identity(cs, None).unwrap();
        assert_eq!(
            keystore_identity.x509_identity.as_ref().unwrap().display_name,
            new_display_name
        );
        assert_eq!(keystore_identity.x509_identity.as_ref().unwrap().handle, new_handle);
        assert_eq!(keystore_identity.status, DeviceStatus::Valid);
        assert!(!keystore_identity.thumbprint.is_empty());
    }

    pub async fn verify_sender_identity(&self, case: &TestCase, decrypted: &MlsConversationDecryptMessage) {
        let (sc, ct) = (case.signature_scheme(), case.credential_type);
        let client = self.client().await;
        let sender_cb = client.find_most_recent_credential_bundle(sc, ct).await.unwrap();

        if let openmls::prelude::MlsCredentialType::X509(certificate) = &sender_cb.credential().mls_credential() {
            let mls_identity = certificate.extract_identity(case.ciphersuite(), None).unwrap();
            let mls_client_id = mls_identity.client_id.as_bytes();

            let decrypted_identity = &decrypted.identity;

            let leaf: Vec<u8> = certificate.certificates.first().unwrap().clone().into();
            let identity = leaf
                .as_slice()
                .extract_identity(None, case.ciphersuite().e2ei_hash_alg())
                .unwrap();
            let identity = WireIdentity::try_from((identity, leaf.as_slice())).unwrap();

            assert_eq!(decrypted_identity.client_id, identity.client_id);
            assert_eq!(decrypted_identity.client_id.as_bytes(), mls_client_id);
            let decrypted_x509_identity = decrypted_identity.x509_identity.as_ref().unwrap();
            let x509_identity = identity.x509_identity.as_ref().unwrap();
            assert_eq!(&decrypted_x509_identity.handle, x509_identity.handle.as_str());
            assert_eq!(decrypted_x509_identity.display_name, x509_identity.display_name);
            assert_eq!(decrypted_x509_identity.domain, x509_identity.domain);
            assert_eq!(decrypted_identity.status, identity.status);
            assert_eq!(decrypted_identity.thumbprint, identity.thumbprint);
            assert!(decrypted_x509_identity
                .certificate
                .starts_with("-----BEGIN CERTIFICATE-----"));
            assert!(decrypted_x509_identity
                .certificate
                .ends_with("-----END CERTIFICATE-----\n"));
            let chain = x509_cert::Certificate::load_pem_chain(decrypted_x509_identity.certificate.as_bytes()).unwrap();
            let leaf = chain.first().unwrap();
            let cert_identity = leaf.extract_identity(None, case.ciphersuite().e2ei_hash_alg()).unwrap();

            let cert_identity = WireIdentity::try_from((cert_identity, leaf.to_der().unwrap().as_slice())).unwrap();
            assert_eq!(cert_identity.client_id, identity.client_id);
            assert_eq!(
                cert_identity.x509_identity.as_ref().unwrap().handle.as_str(),
                x509_identity.handle.as_str()
            );
            assert_eq!(
                cert_identity.x509_identity.as_ref().unwrap().display_name,
                x509_identity.display_name
            );
            assert_eq!(
                cert_identity.x509_identity.as_ref().unwrap().domain,
                x509_identity.domain
            );
            assert_eq!(cert_identity.status, identity.status);
            assert_eq!(cert_identity.thumbprint, identity.thumbprint);
            assert_eq!(identity.status, DeviceStatus::Valid);
            assert!(!identity.thumbprint.is_empty());
        }
    }

    pub async fn members_count(&mut self, id: &ConversationId) -> u32 {
        self.get_conversation_unchecked(id).await.members().len() as u32
    }

    pub async fn rand_external_sender(&self, case: &TestCase) -> ExternalSender {
        let sc = case.signature_scheme();

        let provider = self.context.mls_provider().await.unwrap();
        let crypto = provider.crypto();
        let (_, pk) = crypto.signature_key_gen(sc).unwrap();

        let signature_key = SignaturePublicKey::from(pk);

        let credential = Credential::new_basic(b"server".to_vec());

        ExternalSender::new(signature_key, credential)
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
}

impl Client {
    pub(crate) async fn init_x509_credential_bundle_if_missing(
        &self,
        backend: &MlsCryptoProvider,
        sc: SignatureScheme,
        cb: CertificateBundle,
    ) -> CryptoResult<()> {
        let existing_cb = self
            .find_most_recent_credential_bundle(sc, MlsCredentialType::X509)
            .await
            .is_err();
        if existing_cb {
            self.save_new_x509_credential_bundle(&backend.keystore(), sc, cb)
                .await?;
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
            .await?;
        self.generate_one_keypackage_from_credential_bundle(backend, cs, &cb)
            .await
            .map_err(Into::into)
    }
}
