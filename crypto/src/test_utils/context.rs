use super::test_conversation::operation_guard::{Commit, OperationGuard};
use super::{Result, TestConversation};
use crate::CoreCrypto;
use crate::test_utils::SessionContext;
use crate::{
    RecursiveError,
    e2e_identity::{
        device_status::DeviceStatus,
        id::{QualifiedE2eiClientId, WireQualifiedClientId},
    },
    mls::credential::{CredentialBundle, ext::CredentialExt},
    prelude::{
        CertificateBundle, MlsCiphersuite, MlsConversationConfiguration, MlsConversationDecryptMessage,
        MlsCredentialType, Session, WireIdentity,
    },
    test_utils::{TestContext, x509::X509Certificate},
};
use core_crypto_keystore::connection::FetchFromDatabase;
use core_crypto_keystore::entities::{
    EntityFindParams, MlsCredential, MlsEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage, MlsSignatureKeyPair,
};
use openmls::prelude::{
    Credential, CredentialWithKey, CryptoConfig, ExternalSender, HpkePublicKey, KeyPackage, KeyPackageIn, Lifetime,
    SignaturePublicKey,
};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::{OpenMlsCryptoProvider, types::SignatureScheme};
use std::sync::Arc;
use tls_codec::Serialize;
use wire_e2e_identity::prelude::WireIdentityReader;
use x509_cert::der::Encode;

#[allow(clippy::redundant_static_lifetimes)]
pub const TEAM: &'static str = "world";

pub struct RotateAllResult<'a> {
    pub(crate) commits: Vec<OperationGuard<'a, Commit>>,
    pub(crate) new_key_packages: Vec<KeyPackage>,
}

impl SessionContext {
    pub async fn get_one_key_package(&self, case: &TestContext) -> KeyPackage {
        let kps = self
            .transaction
            .get_or_create_client_keypackages(case.ciphersuite(), case.credential_type, 1)
            .await
            .unwrap();
        kps.first().unwrap().clone()
    }

    pub async fn new_keypackage(&self, case: &TestContext, lifetime: Lifetime) -> KeyPackage {
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
                &self.transaction.mls_provider().await.unwrap(),
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
        self.transaction
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

    pub async fn rand_key_package(&self, case: &TestContext) -> KeyPackageIn {
        self.rand_key_package_of_type(case, case.credential_type).await
    }

    pub async fn rand_key_package_of_type(&self, case: &TestContext, ct: MlsCredentialType) -> KeyPackageIn {
        let client = self.transaction.session().await.unwrap();
        client
            .generate_one_keypackage(&self.transaction.mls_provider().await.unwrap(), case.ciphersuite(), ct)
            .await
            .unwrap()
            .into()
    }

    pub async fn commit_transaction(&mut self) {
        self.transaction.finish().await.unwrap();
        // start new transaction
        let cc = CoreCrypto::from(self.session.clone());
        self.transaction = cc.new_transaction().await.unwrap();
    }

    /// Pretends a crash by aborting the running transaction and starting a new, fresh one.
    pub async fn pretend_crash(&mut self) {
        self.transaction.abort().await.unwrap();
        // start new transaction
        let cc = CoreCrypto::from(self.session.clone());
        self.transaction = cc.new_transaction().await.unwrap();
    }

    pub async fn client_signature_key(&self, case: &TestContext) -> SignaturePublicKey {
        let (sc, ct) = (case.signature_scheme(), case.credential_type);
        let client = self.session().await;
        let cb = client.find_most_recent_credential_bundle(sc, ct).await.unwrap();
        SignaturePublicKey::from(cb.signature_key.public())
    }

    pub async fn get_user_id(&self) -> String {
        WireQualifiedClientId::from(self.get_client_id().await).get_user_id()
    }

    pub async fn new_credential_bundle(
        &mut self,
        case: &TestContext,
        signer: Option<&X509Certificate>,
    ) -> CredentialBundle {
        let backend = &self.transaction.mls_provider().await.unwrap();
        let transaction = &self.transaction.keystore().await.unwrap();
        let client = self.session().await;
        let client_id = client.id().await.unwrap();

        match case.credential_type {
            MlsCredentialType::Basic => {
                let cb = Session::new_basic_credential_bundle(&client_id, case.signature_scheme(), backend).unwrap();
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

    pub async fn find_most_recent_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Option<Arc<CredentialBundle>> {
        self.session.find_most_recent_credential_bundle(sc, ct).await.ok()
    }

    pub async fn find_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
        pk: &SignaturePublicKey,
    ) -> Option<Arc<CredentialBundle>> {
        self.session()
            .await
            .find_credential_bundle_by_public_key(sc, ct, pk)
            .await
            .ok()
    }

    pub async fn find_signature_keypair_from_keystore(&self, id: &[u8]) -> Option<MlsSignatureKeyPair> {
        self.transaction
            .keystore()
            .await
            .unwrap()
            .find::<MlsSignatureKeyPair>(id)
            .await
            .unwrap()
    }

    pub async fn find_hpke_private_key_from_keystore(&self, skp: &HpkePublicKey) -> Option<MlsHpkePrivateKey> {
        self.transaction
            .keystore()
            .await
            .unwrap()
            .find::<MlsHpkePrivateKey>(&skp.tls_serialize_detached().unwrap())
            .await
            .unwrap()
    }

    pub async fn find_credential_from_keystore(&self, cb: &CredentialBundle) -> Option<MlsCredential> {
        let credential = cb.credential.tls_serialize_detached().unwrap();
        self.transaction
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
        self.transaction
            .keystore()
            .await
            .unwrap()
            .count::<MlsHpkePrivateKey>()
            .await
            .unwrap()
    }

    pub async fn count_encryption_keypairs(&self) -> usize {
        self.transaction
            .keystore()
            .await
            .unwrap()
            .count::<MlsEncryptionKeyPair>()
            .await
            .unwrap()
    }

    pub async fn count_credentials_in_keystore(&self) -> usize {
        self.transaction
            .keystore()
            .await
            .unwrap()
            .count::<MlsCredential>()
            .await
            .unwrap()
    }

    pub async fn save_new_credential(
        &self,
        case: &TestContext,
        handle: &str,
        display_name: &str,
        signer: &X509Certificate,
    ) -> CredentialBundle {
        let cid = QualifiedE2eiClientId::try_from(self.get_client_id().await.as_slice()).unwrap();
        let new_cert = CertificateBundle::new(handle, display_name, Some(&cid), None, signer);
        let client = self.session().await;
        client
            .save_new_x509_credential_bundle(
                &self.transaction.keystore().await.unwrap(),
                case.signature_scheme(),
                new_cert,
            )
            .await
            .unwrap()
    }

    pub(crate) async fn create_key_packages_and_update_credential_in_all_conversations<'a>(
        &self,
        all_conversations: Vec<TestConversation<'a>>,
        cb: &CredentialBundle,
        cipher_suite: MlsCiphersuite,
        key_package_count: usize,
    ) -> Result<RotateAllResult<'a>> {
        let mut commits = Vec::with_capacity(all_conversations.len());
        for conv in all_conversations {
            let commit_guard = conv.acting_as(self).await.e2ei_rotate(None).await;
            commits.push(commit_guard);
        }
        let new_key_packages = self
            .session()
            .await
            .generate_new_keypackages(&self.session.crypto_provider, cipher_suite, cb, key_package_count)
            .await
            .map_err(RecursiveError::mls_client("generating new key packages"))?;
        Ok(RotateAllResult {
            commits,
            new_key_packages,
        })
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

    pub async fn verify_sender_identity(&self, case: &TestContext, decrypted: &MlsConversationDecryptMessage) {
        let (sc, ct) = (case.signature_scheme(), case.credential_type);
        let client = self.session().await;
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
            assert!(
                decrypted_x509_identity
                    .certificate
                    .starts_with("-----BEGIN CERTIFICATE-----")
            );
            assert!(
                decrypted_x509_identity
                    .certificate
                    .ends_with("-----END CERTIFICATE-----\n")
            );
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

    pub async fn rand_external_sender(&self, case: &TestContext) -> ExternalSender {
        let sc = case.signature_scheme();

        let provider = self.transaction.mls_provider().await.unwrap();
        let crypto = provider.crypto();
        let (_, pk) = crypto.signature_key_gen(sc).unwrap();

        let signature_key = SignaturePublicKey::from(pk);

        let credential = Credential::new_basic(b"server".to_vec());

        ExternalSender::new(signature_key, credential)
    }
}
