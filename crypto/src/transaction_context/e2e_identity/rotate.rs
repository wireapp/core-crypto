use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsCryptoProvider as _, random::OpenMlsRand as _};

use super::error::{Error, Result};
use crate::{
    CertificateBundle, Ciphersuite, Credential, CredentialRef, E2eiEnrollment, MlsError, RecursiveError,
    e2e_identity::{E2eiSignatureKeypair, NewCrlDistributionPoints},
    mls::credential::x509::CertificatePrivateKey,
    transaction_context::TransactionContext,
};

#[cfg(test)]
mod tests {

    use openmls::prelude::SignaturePublicKey;

    use crate::{
        CredentialRef, e2e_identity::enrollment::test_utils as e2ei_utils, mls::credential::ext::CredentialExt,
        test_utils::*,
    };

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
