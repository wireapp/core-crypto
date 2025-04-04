use super::{error::Error, error::Result};
#[cfg(not(target_family = "wasm"))]
use crate::e2e_identity::refresh_token::RefreshToken;
use crate::{
    KeystoreError, MlsError, RecursiveError,
    e2e_identity::NewCrlDistributionPoints,
    mls::credential::{ext::CredentialExt, x509::CertificatePrivateKey},
    prelude::{CertificateBundle, E2eiEnrollment, MlsCiphersuite, MlsCredentialType},
    transaction_context::TransactionContext,
};
use core_crypto_keystore::{CryptoKeystoreMls, connection::FetchFromDatabase, entities::MlsKeyPackage};
use openmls::prelude::KeyPackage;
use openmls_traits::OpenMlsCryptoProvider;

impl TransactionContext {
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
        ciphersuite: MlsCiphersuite,
    ) -> Result<E2eiEnrollment> {
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        // look for existing credential of type basic. If there isn't, then this method has been misused
        let cb = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), MlsCredentialType::Basic)
            .await
            .map_err(|_| Error::MissingExistingClient(MlsCredentialType::Basic))?;
        let client_id = cb.credential().identity().into();

        let sign_keypair = Some(
            cb.signature_key()
                .try_into()
                .map_err(RecursiveError::e2e_identity("creating E2eiSignatureKeypair"))?,
        );

        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            &mls_provider,
            ciphersuite,
            sign_keypair,
            #[cfg(not(target_family = "wasm"))]
            None, // no x509 credential yet at this point so no OIDC authn yet so no refresh token to restore
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    /// Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)
    /// having to change/rotate their credential, either because the former one is expired or it
    /// has been revoked. As a consequence, this method does not support changing neither ClientId which
    /// should remain the same as the previous one. It lets you change the DisplayName or the handle
    /// if you need to. Once the enrollment is finished, use the instance in [TransactionContext::save_x509_credential] to do the rotation.
    pub async fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: MlsCiphersuite,
    ) -> Result<E2eiEnrollment> {
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        // look for existing credential of type x509. If there isn't, then this method has been misused
        let cb = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), MlsCredentialType::X509)
            .await
            .map_err(|_| Error::MissingExistingClient(MlsCredentialType::X509))?;
        let client_id = cb.credential().identity().into();
        let sign_keypair = Some(
            cb.signature_key()
                .try_into()
                .map_err(RecursiveError::e2e_identity("creating E2eiSignatureKeypair"))?,
        );
        let existing_identity = cb
            .to_mls_credential_with_key()
            .extract_identity(ciphersuite, None)
            .map_err(RecursiveError::mls_credential("extracting identity"))?
            .x509_identity
            .ok_or(Error::ImplementationError)?;

        let display_name = display_name.unwrap_or(existing_identity.display_name);
        let handle = handle.unwrap_or(existing_identity.handle);

        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            &mls_provider,
            ciphersuite,
            sign_keypair,
            #[cfg(not(target_family = "wasm"))]
            Some(
                RefreshToken::find(&mls_provider.keystore())
                    .await
                    .map_err(RecursiveError::e2e_identity("finding refreh token"))?,
            ), // Since we are renewing an e2ei certificate we MUST have already generated one hence we MUST already have done an OIDC authn and gotten a refresh token from it we also MUST have stored in CoreCrypto
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    /// Saves a new X509 credential. Requires first
    /// having enrolled a new X509 certificate with either [TransactionContext::e2ei_new_activation_enrollment]
    /// or [TransactionContext::e2ei_new_rotate_enrollment].
    ///
    /// # Expected actions to perform after this function (in this order)
    /// 1. Rotate credentials for each conversation in [crate::mls::conversation::ConversationGuard::e2ei_rotate]
    /// 2. Generate new key packages with [Client::generate_new_keypackages]
    /// 3. Use these to replace the stale ones the in the backend
    /// 4. Delete the stale ones locally using [Self::delete_stale_key_packages]
    ///     * This is the last step because you might still need the old key packages to avoid
    ///       an orphan welcome message
    pub async fn save_x509_credential(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
    ) -> Result<NewCrlDistributionPoints> {
        let sk = enrollment
            .get_sign_key_for_mls()
            .map_err(RecursiveError::e2e_identity("getting sign key for mls"))?;
        let cs = *enrollment.ciphersuite();
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                self.mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting provider"))?
                    .authentication_service()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("getting certificate response"))?;

        let private_key = CertificatePrivateKey {
            value: sk,
            signature_scheme: cs.signature_algorithm(),
        };

        let crl_new_distribution_points = self
            .extract_dp_on_init(&certificate_chain[..])
            .await
            .map_err(RecursiveError::mls_credential("extracting dp on init"))?;

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
        };
        let client = &self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;

        client
            .save_new_x509_credential_bundle(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting mls provider"))?
                    .keystore(),
                cs.signature_algorithm(),
                cert_bundle,
            )
            .await
            .map_err(RecursiveError::mls_client("saving new x509 credential bundle"))?;

        Ok(crl_new_distribution_points)
    }

    /// Deletes all key packages whose leaf node's credential does not match the most recently
    /// saved x509 credential with the provided signature scheme.
    pub async fn delete_stale_key_packages(&self, cipher_suite: MlsCiphersuite) -> Result<()> {
        let signature_scheme = cipher_suite.signature_algorithm();
        let keystore = self
            .keystore()
            .await
            .map_err(RecursiveError::transaction("getting keystore"))?;
        let nb_kp = keystore
            .count::<MlsKeyPackage>()
            .await
            .map_err(KeystoreError::wrap("counting key packages"))?;
        let kps: Vec<KeyPackage> = keystore
            .mls_fetch_keypackages(nb_kp as u32)
            .await
            .map_err(KeystoreError::wrap("fetching key packages"))?;
        let client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;

        let cb = client
            .find_most_recent_credential_bundle(signature_scheme, MlsCredentialType::X509)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential bundle"))?;

        let mut kp_refs = vec![];

        let provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        for kp in kps {
            let kp_cred = kp.leaf_node().credential().mls_credential();
            let local_cred = cb.credential().mls_credential();
            if kp_cred != local_cred {
                let kpr = kp
                    .hash_ref(provider.crypto())
                    .map_err(MlsError::wrap("computing keypackage hashref"))?;
                kp_refs.push(kpr);
            };
        }
        self.delete_keypackages(&kp_refs)
            .await
            .map_err(RecursiveError::mls_client("deleting keypackages"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        e2e_identity::test_utils as e2ei_utils, mls::credential::ext::CredentialExt,
        prelude::key_package::INITIAL_KEYING_MATERIAL_COUNT, test_utils::*,
    };
    use core_crypto_keystore::entities::{EntityFindParams, MlsCredential};
    use openmls::prelude::SignaturePublicKey;
    use std::collections::HashSet;
    use tls_codec::Deserialize;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub(crate) mod all {
        use e2ei_utils::E2EI_EXPIRY;

        use super::*;
        use crate::test_utils::context::TEAM;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn enrollment_should_rotate_all(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        const N: usize = 50;
                        const NB_KEY_PACKAGE: usize = 50;

                        let mut ids = vec![];

                        let x509_test_chain_arc = e2ei_utils::failsafe_ctx(
                            &mut [&mut alice_central, &mut bob_central, &mut charlie_central],
                            case.signature_scheme(),
                        )
                        .await;

                        let x509_test_chain = x509_test_chain_arc.as_ref().as_ref().unwrap();

                        for _ in 0..N {
                            let id = conversation_id();
                            alice_central
                                .context
                                .new_conversation(&id, case.credential_type, case.cfg.clone())
                                .await
                                .unwrap();
                            alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                            ids.push(id)
                        }

                        // Count the key material before the rotation to compare it later
                        let before_rotate = alice_central.context.count_entities().await;
                        assert_eq!(before_rotate.key_package, INITIAL_KEYING_MATERIAL_COUNT);

                        assert_eq!(before_rotate.hpke_private_key, INITIAL_KEYING_MATERIAL_COUNT);

                        // 1 is created per new KeyPackage
                        assert_eq!(before_rotate.encryption_keypair, INITIAL_KEYING_MATERIAL_COUNT);

                        assert_eq!(before_rotate.credential, 1);
                        let old_credential = alice_central
                            .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
                            .await
                            .unwrap()
                            .clone();

                        let is_renewal = case.credential_type == MlsCredentialType::X509;

                        let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                            &mut alice_central,
                            &case,
                            x509_test_chain,
                            None,
                            is_renewal,
                            e2ei_utils::init_activation_or_rotation,
                            e2ei_utils::noop_restore,
                        )
                        .await
                        .unwrap();

                        alice_central
                            .context
                            .save_x509_credential(&mut enrollment, cert)
                            .await
                            .unwrap();

                        let cb = alice_central
                            .find_most_recent_credential_bundle(case.signature_scheme(), MlsCredentialType::X509)
                            .await
                            .unwrap();

                        let result = alice_central
                            .create_key_packages_and_update_credential_in_all_conversations(
                                &cb,
                                *enrollment.ciphersuite(),
                                NB_KEY_PACKAGE,
                            )
                            .await
                            .unwrap();

                        let after_rotate = alice_central.context.count_entities().await;
                        // verify we have indeed created the right amount of new X509 KeyPackages
                        assert_eq!(after_rotate.key_package - before_rotate.key_package, NB_KEY_PACKAGE);

                        // and a new Credential has been persisted in the keystore
                        assert_eq!(after_rotate.credential - before_rotate.credential, 1);

                        for (id, commit) in result.conversation_ids_and_commits.into_iter() {
                            let decrypted = bob_central
                                .context
                                .conversation(&id)
                                .await
                                .unwrap()
                                .decrypt_message(commit.commit.to_bytes().unwrap())
                                .await
                                .unwrap();
                            alice_central.verify_sender_identity(&case, &decrypted).await;

                            alice_central
                                .verify_local_credential_rotated(
                                    &id,
                                    e2ei_utils::NEW_HANDLE,
                                    e2ei_utils::NEW_DISPLAY_NAME,
                                )
                                .await;
                        }

                        // Verify that all the new KeyPackages contain the new identity
                        let new_credentials = result
                            .new_key_packages
                            .iter()
                            .map(|kp| kp.leaf_node().to_credential_with_key());
                        for c in new_credentials {
                            assert_eq!(c.credential.credential_type(), openmls::prelude::CredentialType::X509);
                            let identity = c.extract_identity(case.ciphersuite(), None).unwrap();
                            assert_eq!(
                                identity.x509_identity.as_ref().unwrap().display_name,
                                e2ei_utils::NEW_DISPLAY_NAME
                            );
                            assert_eq!(
                                identity.x509_identity.as_ref().unwrap().handle,
                                format!("wireapp://%40{}@world.com", e2ei_utils::NEW_HANDLE)
                            );
                        }

                        // Alice has to delete her old KeyPackages

                        // But first let's verify the previous credential material is present
                        assert!(
                            alice_central
                                .find_credential_bundle(
                                    case.signature_scheme(),
                                    case.credential_type,
                                    &old_credential.signature_key.public().into()
                                )
                                .await
                                .is_some()
                        );

                        // we also have generated the right amount of private encryption keys
                        let before_delete = alice_central.context.count_entities().await;
                        assert_eq!(
                            before_delete.hpke_private_key - before_rotate.hpke_private_key,
                            NB_KEY_PACKAGE
                        );

                        // 1 has been created per new KeyPackage created in the rotation
                        assert_eq!(before_delete.key_package - before_rotate.key_package, NB_KEY_PACKAGE);

                        // and the signature keypair is still present
                        assert!(
                            alice_central
                                .find_signature_keypair_from_keystore(old_credential.signature_key.public())
                                .await
                                .is_some()
                        );

                        // Checks are done, now let's delete ALL the deprecated KeyPackages.
                        // This should have the consequence to purge the previous credential material as well.
                        alice_central
                            .context
                            .delete_stale_key_packages(case.ciphersuite())
                            .await
                            .unwrap();

                        // Alice should just have the number of X509 KeyPackages she requested
                        let nb_x509_kp = alice_central
                            .count_key_package(case.ciphersuite(), Some(MlsCredentialType::X509))
                            .await;
                        assert_eq!(nb_x509_kp, NB_KEY_PACKAGE);
                        // in both cases, Alice should not anymore have any Basic KeyPackage
                        let nb_basic_kp = alice_central
                            .count_key_package(case.ciphersuite(), Some(MlsCredentialType::Basic))
                            .await;
                        assert_eq!(nb_basic_kp, 0);

                        // and since all of Alice's unclaimed KeyPackages have been purged, so should be her old Credential

                        // Also the old Credential has been removed from the keystore
                        let after_delete = alice_central.context.count_entities().await;
                        assert_eq!(after_delete.credential, 1);
                        assert!(
                            alice_central
                                .find_credential_from_keystore(&old_credential)
                                .await
                                .is_none()
                        );

                        // and all her Private HPKE keys...
                        assert_eq!(after_delete.hpke_private_key, NB_KEY_PACKAGE);

                        // ...and encryption keypairs
                        assert_eq!(
                            after_rotate.encryption_keypair - after_delete.encryption_keypair,
                            INITIAL_KEYING_MATERIAL_COUNT
                        );

                        // Now charlie tries to add Alice to a conversation with her new KeyPackages
                        let id = conversation_id();
                        charlie_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        // required because now Alice does not anymore have a Basic credential
                        let alice = alice_central
                            .rand_key_package_of_type(&case, MlsCredentialType::X509)
                            .await;
                        charlie_central
                            .invite_all_members(&case, &id, [(&alice_central, alice)])
                            .await
                            .unwrap();
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_restore_credentials_in_order(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let x509_test_chain_arc =
                        e2ei_utils::failsafe_ctx(&mut [&mut alice_central], case.signature_scheme()).await;

                    let x509_test_chain = x509_test_chain_arc.as_ref().as_ref().unwrap();

                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let old_cb = alice_central
                        .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
                        .await
                        .unwrap()
                        .clone();

                    // simulate a real rotation where both credential are not created within the same second
                    // we only have a precision of 1 second for the `created_at` field of the Credential
                    async_std::task::sleep(core::time::Duration::from_secs(1)).await;

                    let is_renewal = case.credential_type == MlsCredentialType::X509;

                    let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                        &mut alice_central,
                        &case,
                        x509_test_chain,
                        None,
                        is_renewal,
                        e2ei_utils::init_activation_or_rotation,
                        e2ei_utils::noop_restore,
                    )
                    .await
                    .unwrap();

                    alice_central
                        .context
                        .save_x509_credential(&mut enrollment, cert)
                        .await
                        .unwrap();

                    // So alice has a new Credential as expected
                    let cb = alice_central
                        .find_most_recent_credential_bundle(case.signature_scheme(), MlsCredentialType::X509)
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

                    // but keeps her old one since it's referenced from some KeyPackages
                    let old_spk = SignaturePublicKey::from(old_cb.signature_key.public());
                    let old_cb_found = alice_central
                        .find_credential_bundle(case.signature_scheme(), case.credential_type, &old_spk)
                        .await
                        .unwrap();
                    assert_eq!(old_cb, old_cb_found);
                    let (cid, all_credentials, scs, old_nb_identities) = {
                        let alice_client = alice_central.session().await;
                        let old_nb_identities = alice_client.identities_count().await.unwrap();

                        // Let's simulate an app crash, client gets deleted and restored from keystore
                        let cid = alice_client.id().await.unwrap();
                        let scs = HashSet::from([case.signature_scheme()]);
                        let all_credentials = alice_central
                            .context
                            .keystore()
                            .await
                            .unwrap()
                            .find_all::<MlsCredential>(EntityFindParams::default())
                            .await
                            .unwrap()
                            .into_iter()
                            .map(|c| {
                                let credential =
                                    openmls::prelude::Credential::tls_deserialize(&mut c.credential.as_slice())
                                        .unwrap();
                                (credential, c.created_at)
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(all_credentials.len(), 2);
                        (cid, all_credentials, scs, old_nb_identities)
                    };
                    let backend = &alice_central.context.mls_provider().await.unwrap();
                    backend.keystore().commit_transaction().await.unwrap();
                    backend.keystore().new_transaction().await.unwrap();

                    let new_client = alice_central.session.clone();
                    new_client.reset().await;

                    new_client.load(backend, &cid, all_credentials, scs).await.unwrap();

                    // Verify that Alice has the same credentials
                    let cb = new_client
                        .find_most_recent_credential_bundle(case.signature_scheme(), MlsCredentialType::X509)
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

                    assert_eq!(new_client.identities_count().await.unwrap(), old_nb_identities);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn rotate_should_roundtrip(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let x509_test_chain_arc = e2ei_utils::failsafe_ctx(
                            &mut [&mut alice_central, &mut bob_central],
                            case.signature_scheme(),
                        )
                        .await;

                        let x509_test_chain = x509_test_chain_arc.as_ref().as_ref().unwrap();

                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                        // Alice's turn
                        const ALICE_NEW_HANDLE: &str = "new_alice_wire";
                        const ALICE_NEW_DISPLAY_NAME: &str = "New Alice Smith";

                        fn init_alice(wrapper: e2ei_utils::E2eiInitWrapper) -> e2ei_utils::InitFnReturn<'_> {
                            Box::pin(async move {
                                let e2ei_utils::E2eiInitWrapper { context: cc, case } = wrapper;
                                let cs = case.ciphersuite();
                                match case.credential_type {
                                    MlsCredentialType::Basic => {
                                        cc.e2ei_new_activation_enrollment(
                                            ALICE_NEW_DISPLAY_NAME.to_string(),
                                            ALICE_NEW_HANDLE.to_string(),
                                            Some(TEAM.to_string()),
                                            e2ei_utils::E2EI_EXPIRY,
                                            cs,
                                        )
                                        .await
                                    }
                                    MlsCredentialType::X509 => {
                                        cc.e2ei_new_rotate_enrollment(
                                            Some(ALICE_NEW_DISPLAY_NAME.to_string()),
                                            Some(ALICE_NEW_HANDLE.to_string()),
                                            Some(TEAM.to_string()),
                                            E2EI_EXPIRY,
                                            cs,
                                        )
                                        .await
                                    }
                                }
                                .map_err(RecursiveError::transaction("creating new enrollment"))
                                .map_err(Into::into)
                            })
                        }

                        let is_renewal = case.credential_type == MlsCredentialType::X509;

                        let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                            &mut alice_central,
                            &case,
                            x509_test_chain,
                            None,
                            is_renewal,
                            init_alice,
                            e2ei_utils::noop_restore,
                        )
                        .await
                        .unwrap();

                        alice_central
                            .context
                            .save_x509_credential(&mut enrollment, cert)
                            .await
                            .unwrap();
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .e2ei_rotate(None)
                            .await
                            .unwrap();

                        let commit = alice_central.mls_transport.latest_commit().await;

                        let decrypted = bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        alice_central.verify_sender_identity(&case, &decrypted).await;

                        alice_central
                            .verify_local_credential_rotated(&id, ALICE_NEW_HANDLE, ALICE_NEW_DISPLAY_NAME)
                            .await;

                        // Bob's turn
                        const BOB_NEW_HANDLE: &str = "new_bob_wire";
                        const BOB_NEW_DISPLAY_NAME: &str = "New Bob Smith";

                        fn init_bob(wrapper: e2ei_utils::E2eiInitWrapper) -> e2ei_utils::InitFnReturn<'_> {
                            Box::pin(async move {
                                let e2ei_utils::E2eiInitWrapper { context: cc, case } = wrapper;
                                let cs = case.ciphersuite();
                                match case.credential_type {
                                    MlsCredentialType::Basic => {
                                        cc.e2ei_new_activation_enrollment(
                                            BOB_NEW_DISPLAY_NAME.to_string(),
                                            BOB_NEW_HANDLE.to_string(),
                                            Some(TEAM.to_string()),
                                            E2EI_EXPIRY,
                                            cs,
                                        )
                                        .await
                                    }
                                    MlsCredentialType::X509 => {
                                        cc.e2ei_new_rotate_enrollment(
                                            Some(BOB_NEW_DISPLAY_NAME.to_string()),
                                            Some(BOB_NEW_HANDLE.to_string()),
                                            Some(TEAM.to_string()),
                                            E2EI_EXPIRY,
                                            cs,
                                        )
                                        .await
                                    }
                                }
                                .map_err(RecursiveError::transaction("creating new enrollment"))
                                .map_err(Into::into)
                            })
                        }
                        let is_renewal = case.credential_type == MlsCredentialType::X509;

                        let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                            &mut bob_central,
                            &case,
                            x509_test_chain,
                            None,
                            is_renewal,
                            init_bob,
                            e2ei_utils::noop_restore,
                        )
                        .await
                        .unwrap();

                        bob_central
                            .context
                            .save_x509_credential(&mut enrollment, cert)
                            .await
                            .unwrap();

                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .e2ei_rotate(None)
                            .await
                            .unwrap();

                        let commit = bob_central.mls_transport.latest_commit().await;

                        let decrypted = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        bob_central.verify_sender_identity(&case, &decrypted).await;

                        bob_central
                            .verify_local_credential_rotated(&id, BOB_NEW_HANDLE, BOB_NEW_DISPLAY_NAME)
                            .await;
                    })
                },
            )
            .await
        }
    }

    mod one {
        use super::*;
        use crate::mls::conversation::Conversation as _;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_rotate_one_conversations_credential(case: TestCase) {
            if case.is_x509() {
                run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let init_count = alice_central.context.count_entities().await;
                        let x509_test_chain = alice_central.x509_test_chain.as_ref().as_ref().unwrap();

                        let intermediate_ca = x509_test_chain.find_local_intermediate_ca();
                        let alice_og_cert = &x509_test_chain
                            .actors
                            .iter()
                            .find(|actor| actor.name == "alice")
                            .unwrap()
                            .certificate;

                        // Alice creates a new Credential, updating her handle/display_name
                        let alice_cid = alice_central.get_client_id().await;
                        let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                        let cb = alice_central
                            .save_new_credential(&case, new_handle, new_display_name, alice_og_cert, intermediate_ca)
                            .await;

                        // Verify old identity is still there in the MLS group
                        let alice_old_identities = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_device_identities(&[alice_cid])
                            .await
                            .unwrap();
                        let alice_old_identity = alice_old_identities.first().unwrap();
                        assert_ne!(
                            alice_old_identity.x509_identity.as_ref().unwrap().display_name,
                            new_display_name
                        );
                        assert_ne!(
                            alice_old_identity.x509_identity.as_ref().unwrap().handle,
                            format!("{new_handle}@world.com")
                        );

                        // Alice issues an Update commit to replace her current identity
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .e2ei_rotate(Some(&cb))
                            .await
                            .unwrap();
                        let commit = alice_central.mls_transport.latest_commit().await;

                        // Bob decrypts the commit...
                        let decrypted = bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // ...and verifies that now Alice is represented with her new identity
                        alice_central.verify_sender_identity(&case, &decrypted).await;

                        // Finally, Alice merges her commit and verifies her new identity gets applied
                        alice_central
                            .verify_local_credential_rotated(&id, new_handle, new_display_name)
                            .await;

                        let final_count = alice_central.context.count_entities().await;
                        assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                        assert_eq!(
                            init_count.epoch_encryption_keypair,
                            final_count.epoch_encryption_keypair
                        );
                        assert_eq!(init_count.key_package, final_count.key_package);
                    })
                })
                .await
            }
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn rotate_should_be_renewable_when_commit_denied(case: TestCase) {
            if !case.is_x509() {
                return;
            }
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let init_count = alice_central.context.count_entities().await;

                    let x509_test_chain = alice_central.x509_test_chain.as_ref().as_ref().unwrap();

                    let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

                    // In this case Alice will try to rotate her credential but her commit will be denied
                    // by the backend (because another commit from Bob had precedence)

                    // Alice creates a new Credential, updating her handle/display_name
                    let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                    let cb = alice_central
                        .save_new_credential(
                            &case,
                            new_handle,
                            new_display_name,
                            x509_test_chain.find_certificate_for_actor("alice").unwrap(),
                            intermediate_ca,
                        )
                        .await;

                    // Alice issues an Update commit to replace her current identity
                    let _rotate_commit = alice_central.create_unmerged_e2ei_rotate_commit(&id, &cb).await;

                    // Meanwhile, Bob creates a simple commit
                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    // accepted by the backend
                    let bob_commit = bob_central.mls_transport.latest_commit().await;

                    // Alice decrypts the commit...
                    let decrypted = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(bob_commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // Alice's previous rotate commit should have been renewed so that she can re-commit it
                    assert_eq!(decrypted.proposals.len(), 1);
                    let renewed_proposal = decrypted.proposals.first().unwrap();
                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(renewed_proposal.proposal.to_bytes().unwrap())
                        .await
                        .unwrap();

                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .commit_pending_proposals()
                        .await
                        .unwrap();

                    // Finally, Alice merges her commit and verifies her new identity gets applied
                    alice_central
                        .verify_local_credential_rotated(&id, new_handle, new_display_name)
                        .await;

                    let rotate_commit = alice_central.mls_transport.latest_commit().await;
                    // Bob verifies that now Alice is represented with her new identity
                    let decrypted = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(rotate_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    alice_central.verify_sender_identity(&case, &decrypted).await;

                    let final_count = alice_central.context.count_entities().await;
                    assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                    // TODO: there is no efficient way to clean a credential when alice merges her pending commit. Tracking issue: WPB-9594
                    // One option would be to fetch all conversations and see if Alice is never represented with the said Credential
                    // but let's be honest this is not very efficient.
                    // The other option would be to get rid of having an implicit KeyPackage for the creator of a conversation
                    // assert_eq!(init_count.credential, final_count.credential);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn rotate_should_replace_existing_basic_credentials(case: TestCase) {
            if case.is_x509() {
                run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, MlsCredentialType::Basic, case.cfg.clone())
                            .await
                            .unwrap();

                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let x509_test_chain = alice_central.x509_test_chain.as_ref().as_ref().unwrap();
                        let intermediate_ca = x509_test_chain.find_local_intermediate_ca();
                        let alice_og_cert = &x509_test_chain
                            .actors
                            .iter()
                            .find(|actor| actor.name == "alice")
                            .unwrap()
                            .certificate;

                        // Alice creates a new Credential, updating her handle/display_name
                        let alice_cid = alice_central.get_client_id().await;
                        let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                        alice_central
                            .save_new_credential(&case, new_handle, new_display_name, alice_og_cert, intermediate_ca)
                            .await;

                        // Verify old identity is a basic identity in the MLS group
                        let alice_old_identities = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .get_device_identities(&[alice_cid])
                            .await
                            .unwrap();
                        let alice_old_identity = alice_old_identities.first().unwrap();
                        assert_eq!(alice_old_identity.credential_type, MlsCredentialType::Basic);
                        assert_eq!(alice_old_identity.x509_identity, None);

                        // Alice issues an Update commit to replace her current identity
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .e2ei_rotate(None)
                            .await
                            .unwrap();
                        let commit = alice_central.mls_transport.latest_commit().await;

                        // Bob decrypts the commit...
                        let decrypted = bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // ...and verifies that now Alice is represented with her new identity
                        alice_central.verify_sender_identity(&case, &decrypted).await;

                        // Finally, Alice merges her commit and verifies her new identity gets applied
                        alice_central
                            .verify_local_credential_rotated(&id, new_handle, new_display_name)
                            .await;
                    })
                })
                .await
            }
        }
    }
}
