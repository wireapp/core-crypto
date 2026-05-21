use super::ProteusCentral;
use crate::{CoreCrypto, Error, Result};

impl CoreCrypto {
    /// Proteus session exists
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_session_exists(&self, session_id: &str) -> Result<bool> {
        let mut mutex = self.proteus.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        Ok(proteus.session_exists(session_id, &self.database).await)
    }

    /// Returns the proteus last resort prekey id (u16::MAX = 65535)
    pub fn proteus_last_resort_prekey_id() -> u16 {
        ProteusCentral::last_resort_prekey_id()
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_fingerprint(&self) -> Result<String> {
        let mutex = self.proteus.lock().await;
        let proteus = mutex.as_ref().ok_or(Error::ProteusNotInitialized)?;
        Ok(proteus.fingerprint())
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_fingerprint_local(&self, session_id: &str) -> Result<String> {
        let mut mutex = self.proteus.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        proteus.fingerprint_local(session_id, &self.database).await
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with
    /// [crate::transaction_context::TransactionContext::proteus_init] first or an error will be
    /// returned
    pub async fn proteus_fingerprint_remote(&self, session_id: &str) -> Result<String> {
        let mut mutex = self.proteus.lock().await;
        let proteus = mutex.as_mut().ok_or(Error::ProteusNotInitialized)?;
        proteus.fingerprint_remote(session_id, &self.database).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use core_crypto_keystore::{ConnectionType, Database, DatabaseKey};

    use super::*;
    use crate::{
        CertificateBundle, ClientIdentifier, CredentialType,
        test_utils::{x509::X509TestChain, *},
    };

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn cc_can_init() {
        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();
        let db = Database::open(ConnectionType::Persistent(&path), &DatabaseKey::generate())
            .await
            .unwrap();

        let cc = CoreCrypto::new(db);
        let context = cc.new_transaction().await.unwrap();
        assert!(context.proteus_init().await.is_ok());
        assert!(context.proteus_new_prekey(1).await.is_ok());
        context.finish().await.unwrap();
        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }

    // TODO: ignore this test for now, until we fix the test suite (WPB-25356)
    #[ignore]
    #[apply(all_cred_cipher)]
    async fn cc_can_2_phase_init(case: TestContext) {
        use wire_e2e_identity::pki_env::PkiEnvironment;

        use crate::{ClientId, Credential, test_utils::DummyPkiEnvironmentHooks};

        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();
        let db = Database::open(ConnectionType::Persistent(&path), &DatabaseKey::generate())
            .await
            .unwrap();

        let cc = CoreCrypto::new(db.clone());
        let hooks = Arc::new(DummyPkiEnvironmentHooks);
        let pki_env = PkiEnvironment::new(hooks, db).await.expect("creating pki environment");
        cc.set_pki_environment(Some(Arc::new(pki_env))).await;
        let transaction = cc.new_transaction().await.unwrap();
        let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());
        x509_test_chain.register_with_central(&transaction).await;
        assert!(transaction.proteus_init().await.is_ok());
        // proteus is initialized, prekeys can be generated
        assert!(transaction.proteus_new_prekey(1).await.is_ok());
        // 👇 and so a unique 'client_id' can be fetched from wire-server
        let session_id = ClientId::from("alice");
        let transport = Arc::new(CoreCryptoTransportSuccessProvider::default());
        let identifier = match case.credential_type {
            CredentialType::Basic => ClientIdentifier::Basic(session_id),
            CredentialType::X509 => {
                CertificateBundle::rand_identifier(&session_id, &[x509_test_chain.find_local_intermediate_ca()])
            }
        };
        let pki_env = cc.get_pki_environment().await;
        let session_id = identifier
            .get_id(pki_env.as_deref())
            .await
            .expect("Getting session id from identifier")
            .into_owned();
        transaction.mls_init(session_id, transport).await.unwrap();
        let credential = Credential::from_identifier(&identifier, case.ciphersuite()).unwrap();
        let credential_ref = transaction.add_credential(credential).await.unwrap();

        // expect MLS to work
        assert!(transaction.generate_key_package(&credential_ref, None).await.is_ok());

        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }
}
