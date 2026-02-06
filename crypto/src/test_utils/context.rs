use std::sync::Arc;

use core_crypto_keystore::{
    entities::{StoredCredential, StoredEncryptionKeyPair, StoredHpkePrivateKey, StoredKeypackage},
    traits::FetchFromDatabase,
};
use openmls::prelude::{Credential as MlsCredential, ExternalSender, HpkePublicKey, KeyPackage, SignaturePublicKey};
use openmls_traits::{OpenMlsCryptoProvider, crypto::OpenMlsCrypto};
use tls_codec::Serialize;
use wire_e2e_identity::WireIdentityReader;
use x509_cert::der::Encode;

use crate::{
    CertificateBundle, Ciphersuite, CredentialFindFilters, CredentialRef, CredentialType,
    MlsConversationDecryptMessage, WireIdentity,
    e2e_identity::{
        device_status::DeviceStatus,
        id::{QualifiedE2eiClientId, WireQualifiedClientId},
    },
    mls::credential::{Credential, ext::CredentialExt},
    test_utils::{SessionContext, TestContext, x509::X509Certificate},
};

#[allow(clippy::redundant_static_lifetimes)]
pub const TEAM: &'static str = "world";

impl SessionContext {
    pub async fn new_keypackage(&self, case: &TestContext) -> KeyPackage {
        self.new_keypackage_with_lifetime(case, None).await
    }

    pub async fn new_keypackage_with_lifetime(
        &self,
        case: &TestContext,
        lifetime: Option<std::time::Duration>,
    ) -> KeyPackage {
        let credential = self.find_any_credential(case.ciphersuite(), case.credential_type).await;
        let credential_ref = CredentialRef::from_credential(&credential);
        self.transaction
            .generate_keypackage(&credential_ref, lifetime)
            .await
            .unwrap()
    }

    pub async fn count_key_package(&self, cs: Ciphersuite, ct: Option<CredentialType>) -> usize {
        self.transaction
            .database()
            .await
            .unwrap()
            .load_all::<StoredKeypackage>()
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

    pub async fn commit_transaction(&mut self) {
        self.transaction.finish().await.unwrap();
        // start new transaction
        self.transaction = self.core_crypto.new_transaction().await.unwrap();
    }

    /// Pretends a crash by aborting the running transaction and starting a new, fresh one.
    pub async fn pretend_crash(&mut self) {
        self.transaction.abort().await.unwrap();
        // start new transaction
        self.transaction = self.core_crypto.new_transaction().await.unwrap();
    }

    pub async fn get_user_id(&self) -> String {
        WireQualifiedClientId::from(self.get_client_id().await).get_user_id()
    }

    /// Create, save, and add a new credential of the type relevant to this test
    pub async fn new_credential(&mut self, case: &TestContext, signer: Option<&X509Certificate>) -> Arc<Credential> {
        let session = self.session().await;
        let client_id = session.id();

        let credential = match case.credential_type {
            CredentialType::Basic => Credential::basic(case.ciphersuite(), client_id).unwrap(),
            CredentialType::X509 => {
                let cert_bundle = CertificateBundle::rand(&client_id, signer.unwrap());
                Credential::x509(case.ciphersuite(), cert_bundle).unwrap()
            }
        };

        // in the x509 case, `CertificateBundle::rand` just completely invents a new client id in the format that e2ei
        // apparently prefers. We still need to add that credential even so, because this test util code is (meant to
        // be) part of setup, not part of the code under test.
        self.transaction
            .add_credential_without_clientid_check(credential)
            .await
            .unwrap()
    }

    pub async fn find_any_credential(&self, ciphersuite: Ciphersuite, credential_type: CredentialType) -> Credential {
        let find_filters = CredentialFindFilters::builder()
            .credential_type(credential_type)
            .ciphersuite(ciphersuite)
            .build();
        let credentials = self
            .session()
            .await
            .find_credentials(find_filters)
            .await
            .expect("find credentials for ciphersuite and credential type");
        let credential_ref = credentials.first().expect("at least one credential found");

        let database = self.transaction.database().await.unwrap();
        credential_ref.load(&database).await.unwrap()
    }

    pub async fn find_credential(&self, pk: &SignaturePublicKey) -> Option<Arc<Credential>> {
        self.session().await.find_credential_by_public_key(pk).await.ok()
    }

    pub async fn find_hpke_private_key_from_keystore(&self, skp: &HpkePublicKey) -> Option<StoredHpkePrivateKey> {
        self.transaction
            .database()
            .await
            .unwrap()
            .get::<StoredHpkePrivateKey>(&skp.tls_serialize_detached().unwrap())
            .await
            .unwrap()
    }

    pub async fn find_credential_from_keystore(&self, cb: &Credential) -> Option<StoredCredential> {
        let credential = cb.mls_credential.tls_serialize_detached().unwrap();
        self.transaction
            .database()
            .await
            .unwrap()
            .load_all::<StoredCredential>()
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.credential[..] == credential)
    }

    pub async fn count_hpke_private_key(&self) -> u32 {
        self.transaction
            .database()
            .await
            .unwrap()
            .count::<StoredHpkePrivateKey>()
            .await
            .unwrap()
    }

    pub async fn count_encryption_keypairs(&self) -> u32 {
        self.transaction
            .database()
            .await
            .unwrap()
            .count::<StoredEncryptionKeyPair>()
            .await
            .unwrap()
    }

    pub async fn count_credentials_in_keystore(&self) -> u32 {
        self.transaction
            .database()
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
        self.transaction.add_credential_producing_arc(credential).await.unwrap()
    }

    pub async fn get_e2ei_client_id(&self) -> wire_e2e_identity::E2eiClientId {
        let cid = self.get_client_id().await;
        let cid = std::str::from_utf8(&cid.0).unwrap();
        let cid: String = cid.parse::<QualifiedE2eiClientId>().unwrap().try_into().unwrap();
        wire_e2e_identity::E2eiClientId::try_from_qualified(&cid).unwrap()
    }

    pub fn get_intermediate_ca(&self) -> Option<&X509Certificate> {
        self.x509_test_chain
            .as_ref()
            .as_ref()
            .map(|chain| chain.find_local_intermediate_ca())
    }

    pub async fn verify_sender_identity(
        &self,
        case: &TestContext,
        expected_credential_ref: &CredentialRef,
        decrypted: &MlsConversationDecryptMessage,
    ) {
        let database = self.transaction.database().await.unwrap();
        let expected_credential = expected_credential_ref.load(&database).await.unwrap();
        if let openmls::prelude::MlsCredentialType::X509(certificate) =
            &expected_credential.mls_credential().mls_credential()
        {
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
