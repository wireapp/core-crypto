use std::sync::Arc;

use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{EntityFindParams, StoredCredential, StoredEncryptionKeyPair, StoredHpkePrivateKey, StoredKeypackage},
};
use openmls::prelude::{
    Credential as MlsCredential, CredentialWithKey, CryptoConfig, ExternalSender, HpkePublicKey, KeyPackage,
    KeyPackageIn, Lifetime, SignaturePublicKey,
};
use openmls_traits::{OpenMlsCryptoProvider, crypto::OpenMlsCrypto, types::SignatureScheme};
use tls_codec::Serialize;
use wire_e2e_identity::prelude::WireIdentityReader;
use x509_cert::der::Encode;

use super::{
    Result, TestConversation,
    test_conversation::operation_guard::{Commit, OperationGuard},
};
use crate::{
    CertificateBundle, Ciphersuite, CoreCrypto, CredentialType, MlsConversationConfiguration,
    MlsConversationDecryptMessage, RecursiveError, WireIdentity,
    e2e_identity::{
        device_status::DeviceStatus,
        id::{QualifiedE2eiClientId, WireQualifiedClientId},
    },
    mls::credential::{Credential, ext::CredentialExt},
    test_utils::{SessionContext, TestContext, x509::X509Certificate},
};

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
            .find_most_recent_credential(case.signature_scheme(), case.credential_type)
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
                &cb.signature_key_pair,
                CredentialWithKey {
                    credential: cb.mls_credential.clone(),
                    signature_key: cb.signature_key_pair.public().into(),
                },
            )
            .await
            .unwrap()
    }

    pub async fn count_key_package(&self, cs: Ciphersuite, ct: Option<CredentialType>) -> usize {
        self.transaction
            .mls_provider()
            .await
            .unwrap()
            .key_store()
            .find_all::<StoredKeypackage>(EntityFindParams::default())
            .await
            .unwrap()
            .into_iter()
            .map(|kp| core_crypto_keystore::deser::<KeyPackage>(&kp.keypackage).unwrap())
            .filter(|kp| kp.ciphersuite() == *cs)
            .filter(|kp| {
                ct.map(|ct| ct == kp.leaf_node().credential().credential_type())
                    .unwrap_or(true)
            })
            .count()
    }

    pub async fn rand_key_package(&self, case: &TestContext) -> KeyPackageIn {
        self.rand_key_package_of_type(case, case.credential_type).await
    }

    pub async fn rand_key_package_of_type(&self, case: &TestContext, ct: CredentialType) -> KeyPackageIn {
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
        let cb = client.find_most_recent_credential(sc, ct).await.unwrap();
        SignaturePublicKey::from(cb.signature_key_pair.public())
    }

    pub async fn get_user_id(&self) -> String {
        WireQualifiedClientId::from(self.get_client_id().await).get_user_id()
    }

    /// Create, save, and add a new credential of the type relevant to this test
    pub async fn new_credential(&mut self, case: &TestContext, signer: Option<&X509Certificate>) -> Arc<Credential> {
        let backend = &self.transaction.mls_provider().await.unwrap();
        let client = self.session().await;
        let client_id = client.id().await.unwrap();

        let credential = match case.credential_type {
            CredentialType::Basic => Credential::basic(case.ciphersuite(), client_id, backend).unwrap(),
            CredentialType::X509 => {
                let cert_bundle = CertificateBundle::rand(&client_id, signer.unwrap());
                Credential::x509(case.ciphersuite(), cert_bundle).unwrap()
            }
        };

        // in the x509 case, `CertificateBundle::rand` just completely invents a new client id in the format that e2ei
        // apparently prefers. We still need to add that credential even so, because this test util code is (meant to be) part of setup,
        // not part of the code under test.
        self.session
            .add_credential_without_clientid_check(credential)
            .await
            .unwrap()
    }

    pub async fn find_most_recent_credential(
        &self,
        sc: SignatureScheme,
        ct: CredentialType,
    ) -> Option<Arc<Credential>> {
        self.session.find_most_recent_credential(sc, ct).await.ok()
    }

    pub async fn find_credential(
        &self,
        sc: SignatureScheme,
        ct: CredentialType,
        pk: &SignaturePublicKey,
    ) -> Option<Arc<Credential>> {
        self.session()
            .await
            .find_credential_by_public_key(sc, ct, pk)
            .await
            .ok()
    }

    pub async fn find_hpke_private_key_from_keystore(&self, skp: &HpkePublicKey) -> Option<StoredHpkePrivateKey> {
        self.transaction
            .keystore()
            .await
            .unwrap()
            .find::<StoredHpkePrivateKey>(&skp.tls_serialize_detached().unwrap())
            .await
            .unwrap()
    }

    pub async fn find_credential_from_keystore(&self, cb: &Credential) -> Option<StoredCredential> {
        let credential = cb.mls_credential.tls_serialize_detached().unwrap();
        self.transaction
            .keystore()
            .await
            .unwrap()
            .find_all::<StoredCredential>(EntityFindParams::default())
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
            .count::<StoredHpkePrivateKey>()
            .await
            .unwrap()
    }

    pub async fn count_encryption_keypairs(&self) -> usize {
        self.transaction
            .keystore()
            .await
            .unwrap()
            .count::<StoredEncryptionKeyPair>()
            .await
            .unwrap()
    }

    pub async fn count_credentials_in_keystore(&self) -> usize {
        self.transaction
            .keystore()
            .await
            .unwrap()
            .count::<StoredCredential>()
            .await
            .unwrap()
    }

    pub async fn save_new_credential(
        &self,
        case: &TestContext,
        handle: &str,
        display_name: &str,
        signer: &X509Certificate,
    ) -> Arc<Credential> {
        let cid = QualifiedE2eiClientId::try_from(self.get_client_id().await.as_slice()).unwrap();
        let new_cert = CertificateBundle::new(handle, display_name, Some(&cid), None, signer);
        let credential = Credential::x509(case.ciphersuite(), new_cert).unwrap();
        let client = self.session().await;
        client.add_credential_producing_arc(credential).await.unwrap()
    }

    pub(crate) async fn create_key_packages_and_update_credential_in_all_conversations<'a>(
        &self,
        all_conversations: Vec<TestConversation<'a>>,
        cb: &Credential,
        cipher_suite: Ciphersuite,
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
        let sender_cb = client.find_most_recent_credential(sc, ct).await.unwrap();

        if let openmls::prelude::MlsCredentialType::X509(certificate) = &sender_cb.mls_credential().mls_credential() {
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

        let credential = MlsCredential::new_basic(b"server".to_vec());

        ExternalSender::new(signature_key, credential)
    }
}
