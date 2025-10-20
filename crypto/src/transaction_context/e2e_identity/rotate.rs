use core_crypto_keystore::{CryptoKeystoreMls, connection::FetchFromDatabase, entities::StoredKeypackage};
use openmls::prelude::KeyPackage;
use openmls_traits::OpenMlsCryptoProvider;

use super::error::{Error, Result};
use crate::{
    CertificateBundle, Ciphersuite, CredentialType, E2eiEnrollment, KeystoreError, MlsError, RecursiveError,
    e2e_identity::NewCrlDistributionPoints,
    mls::credential::{ext::CredentialExt, x509::CertificatePrivateKey},
    transaction_context::TransactionContext,
};

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
        ciphersuite: Ciphersuite,
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
            .find_most_recent_credential(ciphersuite.signature_algorithm(), CredentialType::Basic)
            .await
            .map_err(|_| Error::MissingExistingClient(CredentialType::Basic))?;
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
            false, // no x509 credential yet at this point so no OIDC authn yet so no refresh token to restore
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
        ciphersuite: Ciphersuite,
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
            .find_most_recent_credential(ciphersuite.signature_algorithm(), CredentialType::X509)
            .await
            .map_err(|_| Error::MissingExistingClient(CredentialType::X509))?;
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
            true, // Since we are renewing an e2ei certificate we MUST have already generated one hence we MUST already have done an OIDC authn and gotten a refresh token from it
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
    /// 2. Generate new key packages with [crate::mls::session::Session::request_key_packages]
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

        let crl_new_distribution_points = self.extract_dp_on_init(&certificate_chain[..]).await?;

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
        };
        let client = &self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;

        client
            .save_new_x509_credential(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting mls provider"))?
                    .keystore(),
                cs.signature_algorithm(),
                cert_bundle,
            )
            .await
            .map_err(RecursiveError::mls_client("saving new x509 credential"))?;

        Ok(crl_new_distribution_points)
    }

    /// Deletes all key packages whose leaf node's credential does not match the most recently
    /// saved x509 credential with the provided signature scheme.
    pub async fn delete_stale_key_packages(&self, cipher_suite: Ciphersuite) -> Result<()> {
        let signature_scheme = cipher_suite.signature_algorithm();
        let keystore = self
            .keystore()
            .await
            .map_err(RecursiveError::transaction("getting keystore"))?;
        let nb_kp = keystore
            .count::<StoredKeypackage>()
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
            .find_most_recent_credential(signature_scheme, CredentialType::X509)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential"))?;

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
        self.delete_keypackages(kp_refs)
            .await
            .map_err(RecursiveError::transaction("deleting keypackages"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use core_crypto_keystore::entities::{EntityFindParams, StoredCredential};
    use openmls::prelude::SignaturePublicKey;
    use tls_codec::Deserialize;

    use super::*;
    use crate::{
        INITIAL_KEYING_MATERIAL_COUNT, e2e_identity::enrollment::test_utils as e2ei_utils,
        mls::credential::ext::CredentialExt, test_utils::*,
    };

    pub(crate) mod all {
        use e2ei_utils::E2EI_EXPIRY;

        use super::*;
        use crate::test_utils::context::TEAM;

        #[apply(all_cred_cipher)]
        async fn enrollment_should_rotate_all(case: TestContext) {
            let [alice, bob, charlie] = case.sessions_with_pki_env().await;
            Box::pin(async move {
                const N: usize = 50;
                const NB_KEY_PACKAGE: usize = 50;

                let mut conversations = vec![];

                let x509_test_chain = bob.x509_chain_unchecked();

                for _ in 0..N {
                    let conversation = case.create_conversation([&alice, &bob]).await;
                    conversations.push(conversation)
                }

                alice
                    .transaction
                    .get_or_create_client_keypackages(
                        case.ciphersuite(),
                        case.credential_type,
                        INITIAL_KEYING_MATERIAL_COUNT,
                    )
                    .await
                    .unwrap();

                // Count the key material before the rotation to compare it later
                let before_rotate = alice.transaction.count_entities().await;
                assert_eq!(before_rotate.key_package, INITIAL_KEYING_MATERIAL_COUNT);

                assert_eq!(before_rotate.hpke_private_key, INITIAL_KEYING_MATERIAL_COUNT);

                // 1 is created per new KeyPackage
                assert_eq!(before_rotate.encryption_keypair, INITIAL_KEYING_MATERIAL_COUNT);

                assert_eq!(before_rotate.credential, 1);
                let old_credential = alice
                    .find_most_recent_credential(case.signature_scheme(), case.credential_type)
                    .await
                    .unwrap()
                    .clone();

                let is_renewal = case.credential_type == CredentialType::X509;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &alice,
                    &case,
                    x509_test_chain,
                    None,
                    is_renewal,
                    e2ei_utils::init_activation_or_rotation,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                alice
                    .transaction
                    .save_x509_credential(&mut enrollment, cert)
                    .await
                    .unwrap();

                let cb = alice
                    .find_most_recent_credential(case.signature_scheme(), CredentialType::X509)
                    .await
                    .unwrap();

                let result = alice
                    .create_key_packages_and_update_credential_in_all_conversations(
                        conversations,
                        &cb,
                        *enrollment.ciphersuite(),
                        NB_KEY_PACKAGE,
                    )
                    .await
                    .unwrap();

                let after_rotate = alice.transaction.count_entities().await;
                // verify we have indeed created the right amount of new X509 KeyPackages
                assert_eq!(after_rotate.key_package - before_rotate.key_package, NB_KEY_PACKAGE);

                // and a new Credential has been persisted in the keystore
                assert_eq!(after_rotate.credential - before_rotate.credential, 1);

                for commit in result.commits {
                    let conversation = commit.notify_members_and_verify_sender().await;

                    conversation
                        .verify_credential_handle_and_name(e2ei_utils::NEW_HANDLE, e2ei_utils::NEW_DISPLAY_NAME)
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
                    alice
                        .find_credential(
                            case.signature_scheme(),
                            case.credential_type,
                            &old_credential.signature_key_pair.public().into()
                        )
                        .await
                        .is_some()
                );

                // we also have generated the right amount of private encryption keys
                let before_delete = alice.transaction.count_entities().await;
                assert_eq!(
                    before_delete.hpke_private_key - before_rotate.hpke_private_key,
                    NB_KEY_PACKAGE
                );

                // 1 has been created per new KeyPackage created in the rotation
                assert_eq!(before_delete.key_package - before_rotate.key_package, NB_KEY_PACKAGE);

                // and the signature keypair is still present
                assert!(
                    alice
                        .find_signature_keypair_from_keystore(old_credential.signature_key_pair.public())
                        .await
                        .is_some()
                );

                // Checks are done, now let's delete ALL the deprecated KeyPackages.
                // This should have the consequence to purge the previous credential material as well.
                alice
                    .transaction
                    .delete_stale_key_packages(case.ciphersuite())
                    .await
                    .unwrap();

                // Alice should just have the number of X509 KeyPackages she requested
                let nb_x509_kp = alice
                    .count_key_package(case.ciphersuite(), Some(CredentialType::X509))
                    .await;
                assert_eq!(nb_x509_kp, NB_KEY_PACKAGE);
                // in both cases, Alice should not anymore have any Basic KeyPackage
                let nb_basic_kp = alice
                    .count_key_package(case.ciphersuite(), Some(CredentialType::Basic))
                    .await;
                assert_eq!(nb_basic_kp, 0);

                // and since all of Alice's unclaimed KeyPackages have been purged, so should be her old Credential

                // Also the old Credential has been removed from the keystore
                let after_delete = alice.transaction.count_entities().await;
                assert_eq!(after_delete.credential, 1);
                assert!(alice.find_credential_from_keystore(&old_credential).await.is_none());

                // and all her Private HPKE keys...
                assert_eq!(after_delete.hpke_private_key, NB_KEY_PACKAGE);

                // ...and encryption keypairs
                assert_eq!(
                    after_rotate.encryption_keypair - after_delete.encryption_keypair,
                    INITIAL_KEYING_MATERIAL_COUNT
                );

                // Now charlie tries to add Alice to a conversation with her new KeyPackages
                let conversation = case
                    .create_conversation([&charlie])
                    .await
                    .invite_with_credential_type_notify(CredentialType::X509, [&alice])
                    .await;
                assert!(conversation.is_functional_and_contains([&alice, &charlie]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_restore_credentials_in_order(case: TestContext) {
            let [alice] = case.sessions_with_pki_env().await;
            Box::pin(async move {
                let x509_test_chain = alice.x509_chain_unchecked();

                case.create_conversation([&alice]).await;

                let old_cb = alice
                    .find_most_recent_credential(case.signature_scheme(), case.credential_type)
                    .await
                    .unwrap()
                    .clone();

                // simulate a real rotation where both credential are not created within the same second
                // we only have a precision of 1 second for the `created_at` field of the Credential
                smol::Timer::after(core::time::Duration::from_secs(1)).await;

                let is_renewal = case.credential_type == CredentialType::X509;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &alice,
                    &case,
                    x509_test_chain,
                    None,
                    is_renewal,
                    e2ei_utils::init_activation_or_rotation,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                alice
                    .transaction
                    .save_x509_credential(&mut enrollment, cert)
                    .await
                    .unwrap();

                // So alice has a new Credential as expected
                let cb = alice
                    .find_most_recent_credential(case.signature_scheme(), CredentialType::X509)
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
                let old_spk = SignaturePublicKey::from(old_cb.signature_key_pair.public());
                let old_cb_found = alice
                    .find_credential(case.signature_scheme(), case.credential_type, &old_spk)
                    .await
                    .unwrap();
                assert_eq!(old_cb, old_cb_found);
                let (cid, all_credentials, scs, old_nb_identities) = {
                    let alice_client = alice.session().await;
                    let old_nb_identities = alice_client.identities_count().await.unwrap();

                    // Let's simulate an app crash, client gets deleted and restored from keystore
                    let cid = alice_client.id().await.unwrap();
                    let scs = HashSet::from([case.signature_scheme()]);
                    let all_credentials = alice
                        .transaction
                        .keystore()
                        .await
                        .unwrap()
                        .find_all::<StoredCredential>(EntityFindParams::default())
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|c| {
                            let credential =
                                openmls::prelude::Credential::tls_deserialize(&mut c.credential.as_slice()).unwrap();
                            (credential, c.created_at)
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(all_credentials.len(), 2);
                    (cid, all_credentials, scs, old_nb_identities)
                };
                let backend = &alice.transaction.mls_provider().await.unwrap();
                backend.keystore().commit_transaction().await.unwrap();
                backend.keystore().new_transaction().await.unwrap();

                let new_client = alice.session.clone();
                new_client.reset().await;

                new_client.load(backend, &cid, all_credentials, scs).await.unwrap();

                // Verify that Alice has the same credentials
                let cb = new_client
                    .find_most_recent_credential(case.signature_scheme(), CredentialType::X509)
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
            .await
        }

        #[apply(all_cred_cipher)]
        async fn rotate_should_roundtrip(case: TestContext) {
            let [alice, bob] = case.sessions_with_pki_env().await;
            Box::pin(async move {
                let x509_test_chain = alice.x509_chain_unchecked();

                let conversation = case.create_conversation([&alice, &bob]).await;
                // Alice's turn
                const ALICE_NEW_HANDLE: &str = "new_alice_wire";
                const ALICE_NEW_DISPLAY_NAME: &str = "New Alice Smith";

                fn init_alice(wrapper: e2ei_utils::E2eiInitWrapper<'_>) -> e2ei_utils::InitFnReturn<'_> {
                    Box::pin(async move {
                        let e2ei_utils::E2eiInitWrapper { context: cc, case } = wrapper;
                        let cs = case.ciphersuite();
                        match case.credential_type {
                            CredentialType::Basic => {
                                cc.e2ei_new_activation_enrollment(
                                    ALICE_NEW_DISPLAY_NAME.to_string(),
                                    ALICE_NEW_HANDLE.to_string(),
                                    Some(TEAM.to_string()),
                                    e2ei_utils::E2EI_EXPIRY,
                                    cs,
                                )
                                .await
                            }
                            CredentialType::X509 => {
                                cc.e2ei_new_rotate_enrollment(
                                    Some(ALICE_NEW_DISPLAY_NAME.to_string()),
                                    Some(ALICE_NEW_HANDLE.to_string()),
                                    Some(TEAM.to_string()),
                                    E2EI_EXPIRY,
                                    cs,
                                )
                                .await
                            }
                            CredentialType::Unknown(_) => panic!("unknown credential types are unsupported"),
                        }
                        .map_err(RecursiveError::transaction("creating new enrollment"))
                        .map_err(Into::into)
                    })
                }

                let is_renewal = case.credential_type == CredentialType::X509;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &alice,
                    &case,
                    x509_test_chain,
                    None,
                    is_renewal,
                    init_alice,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                alice
                    .transaction
                    .save_x509_credential(&mut enrollment, cert)
                    .await
                    .unwrap();
                let conversation = conversation.e2ei_rotate_notify_and_verify_sender(None).await;

                conversation
                    .verify_credential_handle_and_name(ALICE_NEW_HANDLE, ALICE_NEW_DISPLAY_NAME)
                    .await;

                // Bob's turn
                const BOB_NEW_HANDLE: &str = "new_bob_wire";
                const BOB_NEW_DISPLAY_NAME: &str = "New Bob Smith";

                fn init_bob(wrapper: e2ei_utils::E2eiInitWrapper<'_>) -> e2ei_utils::InitFnReturn<'_> {
                    Box::pin(async move {
                        let e2ei_utils::E2eiInitWrapper { context: cc, case } = wrapper;
                        let cs = case.ciphersuite();
                        match case.credential_type {
                            CredentialType::Basic => {
                                cc.e2ei_new_activation_enrollment(
                                    BOB_NEW_DISPLAY_NAME.to_string(),
                                    BOB_NEW_HANDLE.to_string(),
                                    Some(TEAM.to_string()),
                                    E2EI_EXPIRY,
                                    cs,
                                )
                                .await
                            }
                            CredentialType::X509 => {
                                cc.e2ei_new_rotate_enrollment(
                                    Some(BOB_NEW_DISPLAY_NAME.to_string()),
                                    Some(BOB_NEW_HANDLE.to_string()),
                                    Some(TEAM.to_string()),
                                    E2EI_EXPIRY,
                                    cs,
                                )
                                .await
                            }
                            CredentialType::Unknown(_) => panic!("unknown credential types are unsupported"),
                        }
                        .map_err(RecursiveError::transaction("creating new enrollment"))
                        .map_err(Into::into)
                    })
                }
                let is_renewal = case.credential_type == CredentialType::X509;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &bob,
                    &case,
                    x509_test_chain,
                    None,
                    is_renewal,
                    init_bob,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                bob.transaction
                    .save_x509_credential(&mut enrollment, cert)
                    .await
                    .unwrap();

                let conversation = conversation
                    .acting_as(&bob)
                    .await
                    .e2ei_rotate_notify_and_verify_sender(None)
                    .await;

                conversation
                    .acting_as(&bob)
                    .await
                    .verify_credential_handle_and_name(BOB_NEW_HANDLE, BOB_NEW_DISPLAY_NAME)
                    .await;
            })
            .await
        }
    }

    mod one {
        use super::*;
        use crate::mls::conversation::Conversation as _;

        #[apply(all_cred_cipher)]
        pub async fn should_rotate_one_conversations_credential(case: TestContext) {
            if case.is_x509() {
                let [alice, bob] = case.sessions().await;
                Box::pin(async move {
                    let conversation = case.create_conversation([&alice, &bob]).await;
                    let id = conversation.id().clone();

                    let init_count = alice.transaction.count_entities().await;
                    let x509_test_chain = alice.x509_chain_unchecked();

                    let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

                    // Alice creates a new Credential, updating her handle/display_name
                    let alice_cid = alice.get_client_id().await;
                    let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                    let cb = alice
                        .save_new_credential(&case, new_handle, new_display_name, intermediate_ca)
                        .await;

                    // Verify old identity is still there in the MLS group
                    let alice_old_identities = alice
                        .transaction
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
                    let conversation = conversation.e2ei_rotate_notify_and_verify_sender(Some(&cb)).await;

                    // Finally, Alice merges her commit and verifies her new identity gets applied
                    conversation
                        .verify_credential_handle_and_name(new_handle, new_display_name)
                        .await;

                    let final_count = alice.transaction.count_entities().await;
                    assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                    assert_eq!(
                        init_count.epoch_encryption_keypair,
                        final_count.epoch_encryption_keypair
                    );
                    assert_eq!(init_count.key_package, final_count.key_package);
                })
                .await
            }
        }

        #[apply(all_cred_cipher)]
        pub async fn rotate_should_be_renewable_when_commit_denied(case: TestContext) {
            if !case.is_x509() {
                return;
            }

            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let init_count = alice.transaction.count_entities().await;

                let x509_test_chain = alice.x509_chain_unchecked();

                let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

                // In this case Alice will try to rotate her credential but her commit will be denied
                // by the backend (because another commit from Bob had precedence)

                // Alice creates a new Credential, updating her handle/display_name
                let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                let cb = alice
                    .save_new_credential(&case, new_handle, new_display_name, intermediate_ca)
                    .await;

                // Alice issues an Update commit to replace her current identity
                let conversation = conversation.e2ei_rotate_unmerged(&cb).await.finish();

                // Meanwhile, Bob creates a simple commit
                // accepted by the backend
                // Alice decrypts the commit...
                let (commit, decrypted) = conversation
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let decrypted = decrypted.unwrap();

                // Alice's previous rotate commit should have been renewed so that she can re-commit it
                assert_eq!(decrypted.proposals.len(), 1);

                // Bob verifies that now Alice is represented with her new identity
                let conversation = commit
                    .finish()
                    .commit_pending_proposals()
                    .await
                    .notify_members_and_verify_sender()
                    .await;

                // Finally, Alice merges her commit and verifies her new identity gets applied
                conversation
                    .verify_credential_handle_and_name(new_handle, new_display_name)
                    .await;

                let final_count = alice.transaction.count_entities().await;
                assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                // TODO: there is no efficient way to clean a credential when alice merges her pending commit. Tracking issue: WPB-9594
                // One option would be to fetch all conversations and see if Alice is never represented with the said Credential
                // but let's be honest this is not very efficient.
                // The other option would be to get rid of having an implicit KeyPackage for the creator of a conversation
                // assert_eq!(init_count.credential, final_count.credential);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn rotate_should_replace_existing_basic_credentials(case: TestContext) {
            if !case.is_x509() {
                return;
            }

            let [alice, bob] = case.sessions_basic_with_pki_env().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation_with_credential_type(CredentialType::Basic, [&alice, &bob])
                    .await;
                let id = conversation.id().clone();

                let x509_test_chain = alice.x509_chain_unchecked();
                let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

                // Alice creates a new Credential, updating her handle/display_name
                let alice_cid = alice.get_client_id().await;
                let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                alice
                    .save_new_credential(&case, new_handle, new_display_name, intermediate_ca)
                    .await;

                // Verify old identity is a basic identity in the MLS group
                let alice_old_identities = alice
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .get_device_identities(&[alice_cid])
                    .await
                    .unwrap();
                let alice_old_identity = alice_old_identities.first().unwrap();
                assert_eq!(alice_old_identity.credential_type, CredentialType::Basic);
                assert_eq!(alice_old_identity.x509_identity, None);

                // Alice issues an Update commit to replace her current identity
                // Bob decrypts the commit...
                // ...and verifies that now Alice is represented with her new identity
                let conversation = conversation.e2ei_rotate_notify_and_verify_sender(None).await;

                // Finally, Alice merges her commit and verifies her new identity gets applied
                conversation
                    .verify_credential_handle_and_name(new_handle, new_display_name)
                    .await;
            })
            .await
        }
    }
}
