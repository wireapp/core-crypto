use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsCryptoProvider as _, random::OpenMlsRand as _};

use super::error::{Error, Result};
use crate::{
    CertificateBundle, Ciphersuite, Credential, CredentialRef, E2eiEnrollment, MlsError, RecursiveError,
    e2e_identity::{E2eiSignatureKeypair, NewCrlDistributionPoints},
    mls::credential::x509::CertificatePrivateKey,
    transaction_context::TransactionContext,
};

impl TransactionContext {
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
}

#[cfg(test)]
mod tests {

    use openmls::prelude::SignaturePublicKey;

    use crate::{
        e2e_identity::enrollment::test_utils as e2ei_utils, mls::credential::ext::CredentialExt, test_utils::*,
    };

    pub(crate) mod all {
        use super::*;
        use crate::CredentialRef;

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
}
