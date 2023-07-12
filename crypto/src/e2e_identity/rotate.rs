use crate::{
    mls::credential::{ext::CredentialExt, x509::CertificatePrivateKey, CredentialBundle},
    prelude::{
        CertificateBundle, Client, CryptoError, CryptoResult, E2eIdentityError, E2eIdentityResult, E2eiEnrollment,
        MlsCentral, MlsCiphersuite, MlsCommitBundle, MlsConversation, MlsCredentialType,
    },
    MlsError,
};
use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{KeyPackage, KeyPackageRef, MlsCredentialType as OpenMlsCredential};
use openmls_traits::OpenMlsCryptoProvider;

/// Result returned after rotating the Credential of the current client in all the local conversations
pub struct MlsRotateBundle {
    /// An Update commit for each conversation
    pub commits: Vec<MlsCommitBundle>,
    /// Fresh KeyPackages with the new Credential
    pub new_key_packages: Vec<KeyPackage>,
    /// All the now deprecated KeyPackages. Once deleted remotely, delete them locally with [MlsCentral::delete_keypackages]
    pub key_package_refs_to_remove: Vec<KeyPackageRef>,
}

impl MlsRotateBundle {
    /// Lower through the FFI
    #[allow(clippy::type_complexity)]
    pub fn to_bytes(self) -> CryptoResult<(Vec<MlsCommitBundle>, Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        use openmls::prelude::TlsSerializeTrait as _;

        let kp_size = self.new_key_packages.len();
        let new_key_packages =
            self.new_key_packages
                .into_iter()
                .try_fold(Vec::with_capacity(kp_size), |mut acc, kp| {
                    acc.push(kp.tls_serialize_detached().map_err(MlsError::from)?);
                    CryptoResult::Ok(acc)
                })?;
        let key_package_refs_to_remove = self
            .key_package_refs_to_remove
            .into_iter()
            // TODO: add a method for taking ownership in HashReference
            .map(|r| r.as_slice().to_vec())
            .collect::<Vec<_>>();
        Ok((self.commits, new_key_packages, key_package_refs_to_remove))
    }
}

impl MlsCentral {
    /// Generates an E2EI enrollment instance for a "regular" client (with a Basic credential)
    /// willing to migrate to E2EI. As a consequence, this method does not support changing the
    /// ClientId which should remain the same as the Basic one.
    /// Once the enrollment is finished, use the instance in [MlsCentral::e2ei_rotate_all] to do
    /// the rotation.
    pub fn e2ei_new_activation_enrollment(
        &self,
        display_name: String,
        handle: String,
        expiry_days: u32,
        ciphersuite: MlsCiphersuite,
    ) -> E2eIdentityResult<E2eiEnrollment> {
        let client = self.mls_client()?;
        let client_id = client.id();

        // look for existing credential of type basic. If there isn't, then this method has been misused
        client
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), MlsCredentialType::Basic)
            .ok_or(E2eIdentityError::ImplementationError)?;

        E2eiEnrollment::try_new(
            client_id.clone(),
            display_name,
            handle,
            expiry_days,
            &self.mls_backend,
            ciphersuite,
        )
    }

    /// Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)
    /// having to change/rotate their credential, either because the former one is expired or it
    /// has been revoked. As a consequence, this method does not support changing neither ClientId which
    /// should remain the same as the previous one. It lets you change the DisplayName or the handle
    /// if you need to. Once the enrollment is finished, use the instance in [MlsCentral::e2ei_rotate_all] to do the rotation.
    pub fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        expiry_days: u32,
        ciphersuite: MlsCiphersuite,
    ) -> E2eIdentityResult<E2eiEnrollment> {
        let client = self.mls_client()?;
        let client_id = client.id();

        // look for existing credential of type x509. If there isn't, then this method has been misused
        let cb = client
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), MlsCredentialType::X509)
            .ok_or(E2eIdentityError::ImplementationError)?;
        let existing_identity = cb
            .credential()
            .extract_identity()?
            .ok_or(E2eIdentityError::ImplementationError)?;

        let display_name = display_name.unwrap_or(existing_identity.display_name);
        let handle = handle.unwrap_or(existing_identity.handle);

        E2eiEnrollment::try_new(
            client_id.clone(),
            display_name,
            handle,
            expiry_days,
            &self.mls_backend,
            ciphersuite,
        )
    }

    /// Creates a commit in all local conversations for changing the credential. Requires first
    /// having enrolled a new X509 certificate with either [MlsCentral::e2ei_new_activation_enrollment]
    /// or [MlsCentral::e2ei_new_rotate_enrollment]
    pub async fn e2ei_rotate_all(
        &mut self,
        enrollment: E2eiEnrollment,
        certificate_chain: String,
        new_key_packages_count: usize,
    ) -> E2eIdentityResult<MlsRotateBundle> {
        let sk = enrollment.get_sign_key_for_mls()?;
        let cs = enrollment.ciphersuite;
        let certificate_chain = enrollment.certificate_response(certificate_chain).await?;
        let private_key = CertificatePrivateKey {
            value: sk,
            signature_scheme: cs.signature_algorithm(),
        };

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
        };

        let new_cb = self
            .mls_client
            .as_mut()
            .ok_or(CryptoError::ImplementationError)?
            .save_new_x509_credential_bundle(&self.mls_backend, cs.signature_algorithm(), cert_bundle)
            .await?;

        let commits = self.e2ei_update_all(&new_cb).await?;

        let key_package_refs_to_remove = self.find_key_packages_to_remove(&new_cb).await?;

        let new_key_packages = self
            .mls_client()?
            .generate_new_keypackages(&self.mls_backend, cs, &new_cb, new_key_packages_count)
            .await?;

        Ok(MlsRotateBundle {
            commits,
            new_key_packages,
            key_package_refs_to_remove,
        })
    }

    async fn find_key_packages_to_remove(&self, cb: &CredentialBundle) -> CryptoResult<Vec<KeyPackageRef>> {
        let nb_kp = self.mls_backend.key_store().mls_keypackagebundle_count().await.unwrap();
        let kps: Vec<KeyPackage> = self
            .mls_backend
            .key_store()
            .mls_fetch_keypackages(nb_kp as u32)
            .await
            .unwrap();

        let mut kp_refs = vec![];

        for kp in kps {
            let kp_cred = kp.leaf_node().credential().mls_credential();
            let local_cred = cb.credential().mls_credential();

            let mut push_kpr = || {
                let kpr = kp.hash_ref(self.mls_backend.crypto()).map_err(MlsError::from)?;
                kp_refs.push(kpr);
                CryptoResult::Ok(())
            };

            match (kp_cred, local_cred) {
                (_, OpenMlsCredential::Basic(_)) => return Err(CryptoError::ImplementationError),
                (OpenMlsCredential::X509(kp_cert), OpenMlsCredential::X509(local_cert)) if kp_cert != local_cert => {
                    push_kpr()?
                }
                (OpenMlsCredential::Basic(_), _) => push_kpr()?,
                _ => {}
            }
        }
        Ok(kp_refs)
    }

    async fn e2ei_update_all(&mut self, cb: &CredentialBundle) -> CryptoResult<Vec<MlsCommitBundle>> {
        let all_conversations = self.get_all_conversations().await?;

        let mut commits = vec![];
        for conv in all_conversations {
            let commit = conv
                .write()
                .await
                .e2ei_rotate(&self.mls_backend, self.mls_client()?, cb)
                .await?;
            commits.push(commit);
        }
        Ok(commits)
    }

    #[cfg(test)]
    pub(crate) async fn e2ei_rotate(
        &mut self,
        id: &crate::prelude::ConversationId,
        cb: &CredentialBundle,
    ) -> CryptoResult<MlsCommitBundle> {
        self.get_conversation(id)
            .await?
            .write()
            .await
            .e2ei_rotate(&self.mls_backend, self.mls_client()?, cb)
            .await
    }
}

impl MlsConversation {
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn e2ei_rotate(
        &mut self,
        backend: &MlsCryptoProvider,
        client: &Client,
        cb: &CredentialBundle,
    ) -> CryptoResult<MlsCommitBundle> {
        let mut leaf_node = self.group.own_leaf().ok_or(CryptoError::InternalMlsError)?.clone();
        leaf_node.set_credential_with_key(cb.to_mls_credential_with_key());
        self.update_keying_material(client, backend, Some(cb), Some(leaf_node))
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use tls_codec::Deserialize;

    use crate::{
        e2e_identity::tests::*,
        mls::credential::ext::CredentialExt,
        prelude::{key_package::INITIAL_KEYING_MATERIAL_COUNT, MlsCentral},
        test_utils::*,
    };

    use core_crypto_keystore::entities::{EntityFindParams, MlsCredential};
    use openmls::prelude::SignaturePublicKey;
    use std::collections::HashSet;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod all {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn enrollment_should_rotate_all(case: TestCase) {
            let alice = "MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM:a661e79735dc890f@wire.com";
            run_test_with_client_ids(
                case.clone(),
                [alice, "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        const N: usize = 50;
                        const NB_KEY_PACKAGE: usize = 50;

                        let mut ids = vec![];

                        for _ in 0..N {
                            let id = conversation_id();
                            alice_central
                                .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                                .await
                                .unwrap();
                            alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                            ids.push(id)
                        }

                        assert_eq!(alice_central.count_credentials_in_keystore().await, 1);
                        let old_credential = alice_central
                            .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
                            .await
                            .unwrap()
                            .clone();

                        let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");

                        let init = |cc: &MlsCentral| match case.credential_type {
                            MlsCredentialType::Basic => cc.e2ei_new_activation_enrollment(
                                new_display_name.to_string(),
                                new_handle.to_string(),
                                E2EI_EXPIRY,
                                case.ciphersuite(),
                            ),
                            MlsCredentialType::X509 => cc.e2ei_new_rotate_enrollment(
                                Some(new_display_name.to_string()),
                                Some(new_handle.to_string()),
                                E2EI_EXPIRY,
                                case.ciphersuite(),
                            ),
                        };
                        let (mut alice_central, enrollment, cert) =
                            e2ei_enrollment(alice_central, None, init, move |e, cc| Box::pin(async move { (e, cc) }))
                                .await
                                .unwrap();

                        // Count the key material before the rotation to compare it later
                        let nb_kp_before_rotate = alice_central.key_package_count(case.ciphersuite(), None).await;
                        assert_eq!(nb_kp_before_rotate, INITIAL_KEYING_MATERIAL_COUNT);

                        let nb_hpke_sk_before_rotate = alice_central.count_hpke_private_key().await;
                        assert_eq!(nb_hpke_sk_before_rotate, INITIAL_KEYING_MATERIAL_COUNT);

                        let nb_encryption_kp_before_rotate = alice_central.count_encryption_keypairs().await;
                        // 1 is created per new KeyPackage and 1 per new conversation
                        assert_eq!(nb_encryption_kp_before_rotate, INITIAL_KEYING_MATERIAL_COUNT + N);

                        let rotate_bundle = alice_central
                            .e2ei_rotate_all(enrollment, cert, NB_KEY_PACKAGE)
                            .await
                            .unwrap();

                        let nb_kp_after_rotate = alice_central.key_package_count(case.ciphersuite(), None).await;
                        // verify we have indeed created the right amount of new X509 KeyPackages
                        assert_eq!(nb_kp_after_rotate - nb_kp_before_rotate, NB_KEY_PACKAGE);

                        // and a new Credential has been persisted in the keystore
                        assert_eq!(alice_central.count_credentials_in_keystore().await, 2);

                        for (n, commit) in rotate_bundle.commits.into_iter().enumerate() {
                            let id = ids.get(n).unwrap();
                            let decrypted = bob_central
                                .decrypt_message(id, commit.commit.to_bytes().unwrap())
                                .await
                                .unwrap();
                            alice_central.verify_sender_identity(&case, &decrypted);

                            alice_central.commit_accepted(id).await.unwrap();
                            alice_central
                                .verify_local_credential_rotated(id, new_handle, new_display_name)
                                .await;
                        }

                        // Verify that all the new KeyPackages contain the new identity
                        let new_credentials = rotate_bundle
                            .new_key_packages
                            .iter()
                            .map(|kp| kp.leaf_node().credential());
                        for c in new_credentials {
                            assert_eq!(c.credential_type(), openmls::prelude::CredentialType::X509);
                            let identity = c.extract_identity().unwrap().unwrap();
                            assert_eq!(identity.display_name, new_display_name);
                            assert_eq!(identity.handle, new_handle);
                        }

                        // Alice has to delete her old KeyPackages

                        // But first let's verify the previous credential material is present
                        assert!(alice_central
                            .find_credential_bundle(
                                case.signature_scheme(),
                                case.credential_type,
                                &old_credential.signature_key.public().into()
                            )
                            .await
                            .is_some());

                        // we also have generated the right amount of private encryption keys
                        let nb_hpke_sk = alice_central.count_hpke_private_key().await;
                        assert_eq!(nb_hpke_sk - nb_hpke_sk_before_rotate, NB_KEY_PACKAGE);

                        // and the right amount of encryption keypairs
                        let nb_encryption_kp_after_rotate = alice_central.count_encryption_keypairs().await;

                        // 1 has been created per new KeyPackage created and 1 for the update commit in the rotation
                        assert_eq!(
                            nb_encryption_kp_after_rotate - nb_encryption_kp_before_rotate,
                            NB_KEY_PACKAGE + N
                        );

                        // and the signature keypair is still present
                        assert!(alice_central
                            .find_signature_keypair_from_keystore(old_credential.signature_key.public())
                            .await
                            .is_some());

                        // Checks are done, now let's delete ALL the deprecated KeyPackages.
                        // This should have the consequence to purge the previous credential material as well.
                        alice_central
                            .delete_keypackages(&rotate_bundle.key_package_refs_to_remove[..])
                            .await
                            .unwrap();

                        // Alice should just have the number of X509 KeyPackages she requested
                        let nb_x509_kp = alice_central
                            .key_package_count(case.ciphersuite(), Some(MlsCredentialType::X509))
                            .await;
                        assert_eq!(nb_x509_kp, NB_KEY_PACKAGE);
                        // in both cases, Alice should not anymore have any Basic KeyPackage
                        let nb_basic_kp = alice_central
                            .key_package_count(case.ciphersuite(), Some(MlsCredentialType::Basic))
                            .await;
                        assert_eq!(nb_basic_kp, 0);

                        // and since all of Alice's unclaimed KeyPackages have been purged, so should be her
                        // old Credential and its associated keypair

                        // No more previous CredentialBundle locally
                        assert!(alice_central
                            .find_credential_bundle(
                                case.signature_scheme(),
                                case.credential_type,
                                &old_credential.signature_key.public().into()
                            )
                            .await
                            .is_none());

                        // Also, all the previous SignatureKeyPair should be pruned from the keystore
                        assert!(alice_central
                            .find_signature_keypair_from_keystore(old_credential.signature_key.public())
                            .await
                            .is_none());

                        // Also the old Credential has been removed from the keystore
                        assert_eq!(alice_central.count_credentials_in_keystore().await, 1);
                        assert!(alice_central
                            .find_credential_from_keystore(&old_credential)
                            .await
                            .is_none());

                        // and all her Private HPKE keys...
                        let nb_hpke_sk = alice_central.count_hpke_private_key().await;
                        assert_eq!(nb_hpke_sk, NB_KEY_PACKAGE);

                        // ...and encryption keypairs
                        let nb_encryption_kp = alice_central.count_encryption_keypairs().await;
                        assert_eq!(
                            nb_encryption_kp_after_rotate - nb_encryption_kp,
                            INITIAL_KEYING_MATERIAL_COUNT
                        );

                        // Now charlie tries to add Alice to a conversation with her new KeyPackages
                        let id = conversation_id();
                        charlie_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        // required because now Alice does not anymore have a Basic credential
                        let alice_member = alice_central.rand_member_of_type(&case, MlsCredentialType::X509).await;
                        charlie_central
                            .invite_all_members(&case, &id, [(&mut alice_central, alice_member)])
                            .await
                            .unwrap();
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_restore_credentials_in_order(case: TestCase) {
            let alice = "MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM:a661e79735dc890f@wire.com";
            run_test_with_client_ids(case.clone(), [alice], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let old_cb = alice_central
                        .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
                        .await
                        .unwrap()
                        .clone();

                    // simulate a real rotation where both credential are not created within the same second
                    // we only have a precision of 1 second for the `created_at` field of the SignatureKeypair
                    async_std::task::sleep(core::time::Duration::from_secs(1)).await;

                    let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                    let cb = alice_central
                        .rotate_credential(&case, new_handle, new_display_name)
                        .await;

                    alice_central.e2ei_update_all(&cb).await.unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();

                    // So alice has a new Credential as expected
                    let cb = alice_central
                        .find_most_recent_credential_bundle(case.signature_scheme(), MlsCredentialType::X509)
                        .await
                        .unwrap();
                    let identity = cb.credential().extract_identity().unwrap().unwrap();
                    assert_eq!(identity.display_name, new_display_name);
                    assert_eq!(identity.handle, new_handle);

                    // but keeps her old one since it's referenced from some KeyPackages
                    let old_spk = SignaturePublicKey::from(old_cb.signature_key.public());
                    let old_cb_found = alice_central
                        .find_credential_bundle(case.signature_scheme(), case.credential_type, &old_spk)
                        .await
                        .unwrap();
                    assert_eq!(&old_cb, old_cb_found);
                    let old_nb_identities = alice_central.mls_client.as_ref().unwrap().identities.iter().count();

                    // Let's simulate an app crash, client gets deleted and restored from keystore
                    let cid = alice_central.client_id().unwrap();
                    let scs = HashSet::from([case.signature_scheme()]);
                    let all_credentials = alice_central
                        .mls_backend
                        .key_store()
                        .find_all::<MlsCredential>(EntityFindParams::default())
                        .await
                        .unwrap();
                    let all_credentials = all_credentials
                        .into_iter()
                        .map(|c| openmls::prelude::Credential::tls_deserialize_bytes(c.credential.as_slice()).unwrap())
                        .collect::<Vec<_>>();
                    let client = Client::load(&alice_central.mls_backend, &cid, &all_credentials[..], scs)
                        .await
                        .unwrap();
                    alice_central.mls_client = Some(client);

                    // Verify that Alice has the same credentials
                    let cb = alice_central
                        .find_most_recent_credential_bundle(case.signature_scheme(), MlsCredentialType::X509)
                        .await
                        .unwrap();
                    let identity = cb.credential().extract_identity().unwrap().unwrap();
                    assert_eq!(identity.display_name, new_display_name);
                    assert_eq!(identity.handle, new_handle);
                    let old_spk = SignaturePublicKey::from(old_cb.signature_key.public());
                    let old_cb_found = alice_central
                        .find_credential_bundle(case.signature_scheme(), case.credential_type, &old_spk)
                        .await
                        .unwrap();
                    assert_eq!(&old_cb, old_cb_found);
                    assert_eq!(
                        alice_central.mls_client.as_ref().unwrap().identities.iter().count(),
                        old_nb_identities
                    );
                })
            })
            .await
        }
    }

    pub mod one {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_rotate_one_conversations_credential(case: TestCase) {
            if case.is_x509() {
                run_test_with_client_ids(
                    case.clone(),
                    ["alice", "bob"],
                    move |[mut alice_central, mut bob_central]| {
                        Box::pin(async move {
                            let id = conversation_id();
                            alice_central
                                .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                                .await
                                .unwrap();

                            alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                            // Alice creates a new Credential, updating her handle/display_name
                            let alice_cid = &alice_central.get_client_id();
                            let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                            let cb = alice_central
                                .rotate_credential(&case, new_handle, new_display_name)
                                .await;

                            // Verify old identity is still there in the MLS group
                            let alice_old_identies =
                                alice_central.get_user_identities(&id, &[alice_cid]).await.unwrap();
                            let alice_old_identity = alice_old_identies.first().unwrap();
                            assert_ne!(alice_old_identity.display_name, new_display_name);
                            assert_ne!(alice_old_identity.handle, new_handle);

                            // Alice issues an Update commit to replace her current identity
                            let commit = alice_central.e2ei_rotate(&id, &cb).await.unwrap();

                            // Bob decrypts the commit...
                            let decrypted = bob_central
                                .decrypt_message(&id, commit.commit.to_bytes().unwrap())
                                .await
                                .unwrap();
                            // ...and verifies that now Alice is represented with her new identity
                            alice_central.verify_sender_identity(&case, &decrypted);

                            // Finally, Alice merges her commit and verifies her new identity gets applied
                            alice_central.commit_accepted(&id).await.unwrap();
                            alice_central
                                .verify_local_credential_rotated(&id, new_handle, new_display_name)
                                .await;
                        })
                    },
                )
                .await
            }
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn rotate_should_be_renewable_when_commit_denied(case: TestCase) {
            if case.is_x509() {
                run_test_with_client_ids(
                    case.clone(),
                    ["alice", "bob"],
                    move |[mut alice_central, mut bob_central]| {
                        Box::pin(async move {
                            let id = conversation_id();
                            alice_central
                                .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                                .await
                                .unwrap();

                            alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                            // In this case Alice will try to rotate her credential but her commit will be denied
                            // by the backend (because another commit from Bob had precedence)

                            // Alice creates a new Credential, updating her handle/display_name
                            let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                            let cb = alice_central
                                .rotate_credential(&case, new_handle, new_display_name)
                                .await;

                            // Alice issues an Update commit to replace her current identity
                            let _rotate_commit = alice_central.e2ei_rotate(&id, &cb).await.unwrap();

                            // Meanwhile, Bob creates a simple commit
                            let bob_commit = bob_central.update_keying_material(&id).await.unwrap();
                            // accepted by the backend
                            bob_central.commit_accepted(&id).await.unwrap();

                            // Alice decrypts the commit...
                            let decrypted = alice_central
                                .decrypt_message(&id, bob_commit.commit.to_bytes().unwrap())
                                .await
                                .unwrap();

                            // Alice's previous rotate commit should have been renewed so that she can re-commit it
                            assert_eq!(decrypted.proposals.len(), 1);
                            let renewed_proposal = decrypted.proposals.get(0).unwrap();
                            bob_central
                                .decrypt_message(&id, renewed_proposal.proposal.to_bytes().unwrap())
                                .await
                                .unwrap();

                            let rotate_commit = alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                            alice_central.commit_accepted(&id).await.unwrap();

                            // Finally, Alice merges her commit and verifies her new identity gets applied
                            alice_central.commit_accepted(&id).await.unwrap();
                            alice_central
                                .verify_local_credential_rotated(&id, new_handle, new_display_name)
                                .await;

                            // Bob verifies that now Alice is represented with her new identity
                            let decrypted = bob_central
                                .decrypt_message(&id, rotate_commit.commit.to_bytes().unwrap())
                                .await
                                .unwrap();
                            alice_central.verify_sender_identity(&case, &decrypted);
                        })
                    },
                )
                .await
            }
        }
    }
}