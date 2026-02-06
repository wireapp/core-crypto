//! This module contains all behaviour of a transaction context connected to end-to-end identity.

pub(crate) mod conversation_state;
pub mod enabled;
mod error;
mod init_certificates;
mod stash;

use std::{collections::HashSet, sync::Arc};

pub use error::{Error, Result};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsCryptoProvider as _, random::OpenMlsRand as _};
use wire_e2e_identity::x509_check::extract_crl_uris;

use super::TransactionContext;
use crate::{
    CertificateBundle, Ciphersuite, ClientId, Credential, CredentialRef, E2eiEnrollment, MlsError, MlsTransport,
    RecursiveError,
    e2e_identity::{E2eiSignatureKeypair, NewCrlDistributionPoints},
    mls::credential::{crl::get_new_crl_distribution_points, x509::CertificatePrivateKey},
};

impl TransactionContext {
    /// Creates an enrollment instance with private key material you can use in order to fetch
    /// a new x509 certificate from the acme server.
    ///
    /// # Parameters
    /// * `client_id` - client identifier e.g. `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry_sec` - generated x509 certificate expiry in seconds
    pub async fn e2ei_new_enrollment(
        &self,
        client_id: ClientId,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Result<E2eiEnrollment> {
        let signature_keypair = None; // fresh install without a Basic client. Supplying None will generate a new keypair
        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            ciphersuite,
            signature_keypair,
            false, // fresh install so no refresh token registered yet
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    async fn new_sign_keypair(&self, ciphersuite: Ciphersuite) -> Result<E2eiSignatureKeypair> {
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;

        let sign_keypair = &SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *mls_provider
                .rand()
                .borrow_rand()
                .map_err(MlsError::wrap("borrowing rng"))?,
        )
        .map_err(MlsError::wrap("generating new sign keypair"))?;

        sign_keypair
            .try_into()
            .map_err(RecursiveError::e2e_identity("creating E2eiSignatureKeypair"))
            .map_err(Into::into)
    }

    /// Generates an E2EI enrollment instance for a "regular" client (with a Basic credential)
    /// willing to migrate to E2EI. As a consequence, this method does not support changing the
    /// ClientId which should remain the same as the Basic one.
    /// Once the enrollment is finished, use the instance in [TransactionContext::save_x509_credential]
    /// to save the new credential.
    pub async fn e2ei_new_activation_enrollment(
        &self,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Result<E2eiEnrollment> {
        let client_id = self
            .client_id()
            .await
            .map_err(RecursiveError::transaction("getting client id"))?;

        let sign_keypair = self.new_sign_keypair(ciphersuite).await?;

        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            ciphersuite,
            Some(sign_keypair),
            false, // no x509 credential yet at this point so no OIDC authn yet so no refresh token to restore
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    /// Saves a new X509 credential. Requires first having enrolled a new X509 certificate
    /// with [TransactionContext::e2ei_new_activation_enrollment].
    ///
    /// # Expected actions to perform after this function (in this order)
    /// 1. Set the credential to the return value of this function for each conversation via
    ///    [crate::mls::conversation::ConversationGuard::set_credential_by_ref]
    /// 2. Generate new key packages with [Self::generate_keypackage]
    /// 3. Use these to replace the stale ones the in the backend
    /// 4. Delete the old credentials and keypackages locally using [Self::remove_credential]
    pub async fn save_x509_credential(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
    ) -> Result<(CredentialRef, NewCrlDistributionPoints)> {
        let sk = enrollment
            .get_sign_key_for_mls()
            .map_err(RecursiveError::e2e_identity("getting sign key for mls"))?;
        let ciphersuite = *enrollment.ciphersuite();
        let signature_scheme = ciphersuite.signature_algorithm();

        let pki_environment = self
            .pki_environment()
            .await
            .map_err(RecursiveError::transaction("getting pki environment"))?;
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                pki_environment
                    .mls_pki_env_provider()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("getting certificate response"))?;

        let private_key = CertificatePrivateKey::new(sk);

        let crl_new_distribution_points = self.extract_dp_on_init(&certificate_chain[..]).await?;

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
            signature_scheme,
        };

        let credential = Credential::x509(ciphersuite, cert_bundle).map_err(RecursiveError::mls_credential(
            "creating new x509 credential from certificate bundle in save_x509_credential",
        ))?;

        let credential_ref = self
            .add_credential(credential)
            .await
            .map_err(RecursiveError::transaction(
                "saving and adding credential in save_x509_credential",
            ))?;

        Ok((credential_ref, crl_new_distribution_points))
    }
    /// Parses the ACME server response from the endpoint fetching x509 certificates and uses it
    /// to initialize the MLS client with a certificate
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
        transport: Arc<dyn MlsTransport>,
    ) -> Result<(CredentialRef, NewCrlDistributionPoints)> {
        let pki_environment = self
            .pki_environment()
            .await
            .map_err(RecursiveError::transaction("getting pki environment"))?;

        let sk = enrollment
            .get_sign_key_for_mls()
            .map_err(RecursiveError::e2e_identity("creating new enrollment"))?;
        let ciphersuite = *enrollment.ciphersuite();
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                pki_environment
                    .mls_pki_env_provider()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("getting certificate response"))?;

        let crl_new_distribution_points = self.extract_dp_on_init(&certificate_chain[..]).await?;

        let private_key = CertificatePrivateKey::new(sk);

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
            signature_scheme: ciphersuite.signature_algorithm(),
        };

        let mut credential = Credential::x509(ciphersuite, cert_bundle.clone()).map_err(
            RecursiveError::mls_credential("creating credential from certificate bundle in e2ei_mls_init_only"),
        )?;
        let database = &self
            .database()
            .await
            .map_err(RecursiveError::transaction("Getting database from transaction context"))?;
        let credential_ref = credential.save(database).await.map_err(RecursiveError::mls_credential(
            "saving credential in e2ei_mls_init_only",
        ))?;
        let session_id = cert_bundle.get_client_id().map_err(RecursiveError::mls_credential(
            "Getting session id from certificate bundle",
        ))?;
        self.mls_init(session_id, transport)
            .await
            .map_err(RecursiveError::transaction("initializing mls"))?;
        Ok((credential_ref, crl_new_distribution_points))
    }

    /// When x509 new credentials are registered this extracts the new CRL Distribution Point from the end entity
    /// certificate and all the intermediates
    async fn extract_dp_on_init(&self, certificate_chain: &[Vec<u8>]) -> Result<NewCrlDistributionPoints> {
        use x509_cert::der::Decode as _;

        // Own intermediates are not provided by smallstep in the /federation endpoint so we got to intercept them here,
        // at issuance
        let size = certificate_chain.len();
        let mut crl_new_distribution_points = HashSet::new();
        if size > 1 {
            for int in certificate_chain.iter().skip(1).rev() {
                let mut crl_dp = self
                    .e2ei_register_intermediate_ca_der(int)
                    .await
                    .map_err(RecursiveError::transaction("registering intermediate ca der"))?;
                if let Some(crl_dp) = crl_dp.take() {
                    crl_new_distribution_points.extend(crl_dp);
                }
            }
        }

        let ee = certificate_chain.first().ok_or(Error::InvalidCertificateChain)?;
        let ee = x509_cert::Certificate::from_der(ee)
            .map_err(crate::mls::credential::Error::DecodeX509)
            .map_err(RecursiveError::mls_credential("decoding x509 credential"))?;
        let mut ee_crl_dp = extract_crl_uris(&ee).map_err(RecursiveError::e2e_identity("extracting crl urls"))?;
        if let Some(crl_dp) = ee_crl_dp.take() {
            crl_new_distribution_points.extend(crl_dp);
        }

        let database = self
            .database()
            .await
            .map_err(RecursiveError::transaction("getting database"))?;
        get_new_crl_distribution_points(&database, crl_new_distribution_points)
            .await
            .map_err(RecursiveError::mls_credential("getting new crl distribution points"))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::SignaturePublicKey;

    use crate::{
        e2e_identity::enrollment::test_utils as e2ei_utils,
        mls::{conversation::Conversation as _, credential::ext::CredentialExt as _},
        test_utils::{x509::X509TestChain, *},
        *,
    };

    // TODO: This test has to be disabled because of the session rewrite. We have to create a session first right now.
    // It must be enabled and working again with WPB-19579.
    #[ignore]
    #[apply(all_cred_cipher)]
    async fn e2e_identity_should_work(mut case: TestContext) {
        use e2ei_utils::E2EI_CLIENT_ID_URI;

        let db = case.create_in_memory_database().await;
        let cc = CoreCrypto::new(db);
        let tx = cc.new_transaction().await.unwrap();
        Box::pin(async move {
            let chain = X509TestChain::init_empty(case.signature_scheme());

            let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                &tx,
                &case,
                &chain,
                E2EI_CLIENT_ID_URI,
                e2ei_utils::init_enrollment,
                e2ei_utils::noop_restore,
            )
            .await
            .unwrap();
            let transport = Arc::new(CoreCryptoTransportSuccessProvider::default());

            let (credential_ref, _) = tx.e2ei_mls_init_only(&mut enrollment, cert, transport).await.unwrap();

            let session = SessionContext::new_from_cc(&case, cc, Some(&chain)).await;

            // verify the created client can create a conversation
            let conversation = case
                .create_conversation_with_credentials([(&session, &credential_ref)])
                .await;
            conversation
                .guard()
                .await
                .encrypt_message("Hello e2e identity !")
                .await
                .unwrap();
            assert_eq!(
                conversation.guard().await.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::Verified
            );
            assert!(session.transaction.e2ei_is_enabled(case.ciphersuite()).await.unwrap());
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_restore_credentials_in_order(case: TestContext) {
        let [alice] = case.sessions_with_pki_env().await;
        Box::pin(async move {
            let x509_test_chain = alice.x509_chain_unchecked();

            case.create_conversation([&alice]).await;

            let initial_cred_ref = alice.initial_credential.clone();
            let old_cb = initial_cred_ref
                .load(&alice.transaction.database().await.unwrap())
                .await
                .unwrap();

            // simulate a real rotation where both credential are not created within the same second
            // we only have a precision of 1 second for the `created_at` field of the Credential
            smol::Timer::after(core::time::Duration::from_secs(1)).await;

            let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                &alice.transaction,
                &case,
                x509_test_chain,
                &alice.get_e2ei_client_id().await.to_uri(),
                e2ei_utils::init_activation,
                e2ei_utils::noop_restore,
            )
            .await
            .unwrap();

            let (credential_ref, _) = alice
                .transaction
                .save_x509_credential(&mut enrollment, cert)
                .await
                .unwrap();

            // So alice has a new Credential as expected
            let credential = credential_ref
                .load(&alice.transaction.database().await.unwrap())
                .await
                .unwrap();
            let identity = credential
                .to_mls_credential_with_key()
                .extract_identity(case.ciphersuite(), None)
                .unwrap();
            assert_eq!(
                identity.x509_identity.as_ref().unwrap().display_name,
                e2ei_utils::NEW_DISPLAY_NAME
            );
            assert_eq!(
                identity.x509_identity.as_ref().unwrap().handle,
                format!("wireapp://%40{}@world.com", e2ei_utils::NEW_HANDLE)
            );

            // but keeps her old one since it's referenced from some KeyPackages
            let old_spk = SignaturePublicKey::from(initial_cred_ref.public_key());
            let old_cb_found = alice.find_credential(&old_spk).await.unwrap();
            assert_eq!(std::sync::Arc::new(old_cb), old_cb_found);
            let old_nb_identities = {
                // Let's simulate an app crash, client gets deleted and restored from keystore
                let all_credentials = CredentialRef::get_all(&alice.transaction.database().await.unwrap())
                    .await
                    .unwrap();

                assert_eq!(all_credentials.len(), 2);
                all_credentials.len()
            };
            let keystore = &alice.transaction.database().await.unwrap();
            keystore.commit_transaction().await.unwrap();
            keystore.new_transaction().await.unwrap();

            alice.reinit_session(alice.get_client_id().await).await;

            let new_session = alice.session().await;
            // Verify that Alice has the same credentials
            let cb = new_session
                .find_credential_by_public_key(&credential.to_mls_credential_with_key().signature_key)
                .await
                .unwrap();
            let identity = cb
                .to_mls_credential_with_key()
                .extract_identity(case.ciphersuite(), None)
                .unwrap();

            assert_eq!(
                identity.x509_identity.as_ref().unwrap().display_name,
                e2ei_utils::NEW_DISPLAY_NAME
            );
            assert_eq!(
                identity.x509_identity.as_ref().unwrap().handle,
                format!("wireapp://%40{}@world.com", e2ei_utils::NEW_HANDLE)
            );

            assert_eq!(
                CredentialRef::get_all(new_session.database()).await.unwrap().len(),
                old_nb_identities
            );
        })
        .await
    }
}
