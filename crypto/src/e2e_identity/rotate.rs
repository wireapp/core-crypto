use std::collections::HashMap;

use openmls::prelude::{KeyPackage, KeyPackageRef, MlsCredentialType as OpenMlsCredential};
use openmls_traits::OpenMlsCryptoProvider;

use core_crypto_keystore::{entities::MlsKeyPackage, CryptoKeystoreMls};
use mls_crypto_provider::MlsCryptoProvider;

use crate::{
    mls::credential::{ext::CredentialExt, x509::CertificatePrivateKey, CredentialBundle},
    prelude::{
        CertificateBundle, Client, ConversationId, CryptoError, CryptoResult, E2eIdentityError, E2eiEnrollment,
        MlsCentral, MlsCiphersuite, MlsCommitBundle, MlsConversation, MlsCredentialType,
    },
    MlsError,
};

/// Result returned after rotating the Credential of the current client in all the local conversations
#[derive(Debug, Clone)]
pub struct MlsRotateBundle {
    /// An Update commit for each conversation
    pub commits: HashMap<ConversationId, MlsCommitBundle>,
    /// Fresh KeyPackages with the new Credential
    pub new_key_packages: Vec<KeyPackage>,
    /// All the now deprecated KeyPackages. Once deleted remotely, delete them locally with [MlsCentral::delete_keypackages]
    pub key_package_refs_to_remove: Vec<KeyPackageRef>,
}

impl MlsRotateBundle {
    /// Lower through the FFI
    #[allow(clippy::type_complexity)]
    pub fn to_bytes(self) -> CryptoResult<(HashMap<String, MlsCommitBundle>, Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        use openmls::prelude::TlsSerializeTrait as _;

        let commits_size = self.commits.len();
        let commits = self
            .commits
            .into_iter()
            .try_fold(HashMap::with_capacity(commits_size), |mut acc, (id, c)| {
                // because uniffi ONLY supports HashMap<String, T>
                let id = hex::encode(id);
                let _ = acc.insert(id, c);
                CryptoResult::Ok(acc)
            })?;

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
        Ok((commits, new_key_packages, key_package_refs_to_remove))
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
        team: Option<String>,
        expiry_days: u32,
        ciphersuite: MlsCiphersuite,
    ) -> CryptoResult<E2eiEnrollment> {
        let client = self.mls_client()?;

        // look for existing credential of type basic. If there isn't, then this method has been misused
        let cb = client
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), MlsCredentialType::Basic)
            .ok_or(E2eIdentityError::MissingExistingClient(MlsCredentialType::Basic))?;
        let client_id = cb.credential().identity().into();

        let sign_keypair = Some(cb.signature_key.clone().try_into()?);

        let refresh_token = None; // no x509 credential yet at this point so no OIDC authn yet so no refresh token to restore
        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_days,
            &self.mls_backend,
            ciphersuite,
            sign_keypair,
            refresh_token,
        )
    }

    /// Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)
    /// having to change/rotate their credential, either because the former one is expired or it
    /// has been revoked. As a consequence, this method does not support changing neither ClientId which
    /// should remain the same as the previous one. It lets you change the DisplayName or the handle
    /// if you need to. Once the enrollment is finished, use the instance in [MlsCentral::e2ei_rotate_all] to do the rotation.
    pub async fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        team: Option<String>,
        expiry_days: u32,
        ciphersuite: MlsCiphersuite,
    ) -> CryptoResult<E2eiEnrollment> {
        let client = self.mls_client()?;

        // look for existing credential of type x509. If there isn't, then this method has been misused
        let cb = client
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), MlsCredentialType::X509)
            .ok_or(E2eIdentityError::MissingExistingClient(MlsCredentialType::X509))?;
        let client_id = cb.credential().identity().into();
        let sign_keypair = Some(cb.signature_key.clone().try_into()?);
        let existing_identity = cb
            .credential()
            .extract_identity()?
            .ok_or(E2eIdentityError::InvalidIdentity)?;

        let display_name = display_name.unwrap_or(existing_identity.display_name);
        let handle = handle.unwrap_or(existing_identity.handle);

        // Since we are renewing an e2ei certificate we MUST have already generated one hence we MUST
        // already have done an OIDC authn and gotten a refresh token from it we also MUST have stored
        // in CoreCrypto
        let refresh_token = self.find_refresh_token().await?;

        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_days,
            &self.mls_backend,
            ciphersuite,
            sign_keypair,
            Some(refresh_token),
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
    ) -> CryptoResult<MlsRotateBundle> {
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
            .ok_or(CryptoError::MlsNotInitialized)?
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
        let nb_kp = self.mls_backend.key_store().count::<MlsKeyPackage>().await?;
        let kps: Vec<KeyPackage> = self.mls_backend.key_store().mls_fetch_keypackages(nb_kp as u32).await?;

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

    async fn e2ei_update_all(
        &mut self,
        cb: &CredentialBundle,
    ) -> CryptoResult<HashMap<ConversationId, MlsCommitBundle>> {
        let all_conversations = self.get_all_conversations().await?;

        let mut commits = HashMap::with_capacity(all_conversations.len());
        for conv in all_conversations {
            let mut conv = conv.write().await;
            let id = conv.id().clone();
            let commit = conv.e2ei_rotate(&self.mls_backend, self.mls_client()?, cb).await?;
            let _ = commits.insert(id, commit);
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
    use std::collections::HashSet;

    use openmls::prelude::SignaturePublicKey;
    use tls_codec::Deserialize;
    use wasm_bindgen_test::*;

    use core_crypto_keystore::entities::{EntityFindParams, MlsCredential};

    use crate::{
        e2e_identity::tests::*, mls::credential::ext::CredentialExt,
        prelude::key_package::INITIAL_KEYING_MATERIAL_COUNT, test_utils::*,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod all {
        use crate::test_utils::central::TEAM;

        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn enrollment_should_rotate_all(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        const N: usize = 50;
                        const NB_KEY_PACKAGE: usize = 50;

                        let mut ids = vec![];

                        for _ in 0..N {
                            let id = conversation_id();
                            alice_central
                                .new_conversation(&id, case.credential_type, case.cfg.clone())
                                .await
                                .unwrap();
                            alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                            ids.push(id)
                        }

                        // Count the key material before the rotation to compare it later
                        let before_rotate = alice_central.count_entities().await;
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

                        const NEW_HANDLE: &str = "new_alice_wire";
                        const NEW_DISPLAY_NAME: &str = "New Alice Smith";

                        fn init(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
                            Box::pin(async move {
                                let E2eiInitWrapper { cc, case } = wrapper;
                                let cs = case.ciphersuite();
                                match case.credential_type {
                                    MlsCredentialType::Basic => cc.e2ei_new_activation_enrollment(
                                        NEW_DISPLAY_NAME.to_string(),
                                        NEW_HANDLE.to_string(),
                                        Some(TEAM.to_string()),
                                        E2EI_EXPIRY,
                                        cs,
                                    ),
                                    MlsCredentialType::X509 => {
                                        cc.e2ei_new_rotate_enrollment(
                                            Some(NEW_DISPLAY_NAME.to_string()),
                                            Some(NEW_HANDLE.to_string()),
                                            Some(TEAM.to_string()),
                                            E2EI_EXPIRY,
                                            cs,
                                        )
                                        .await
                                    }
                                }
                            })
                        }

                        let is_renewal = case.credential_type == MlsCredentialType::X509;
                        let (mut alice_central, enrollment, cert) =
                            e2ei_enrollment(alice_central, &case, None, is_renewal, init, noop_restore)
                                .await
                                .unwrap();

                        let rotate_bundle = alice_central
                            .e2ei_rotate_all(enrollment, cert, NB_KEY_PACKAGE)
                            .await
                            .unwrap();

                        let after_rotate = alice_central.count_entities().await;
                        // verify we have indeed created the right amount of new X509 KeyPackages
                        assert_eq!(after_rotate.key_package - before_rotate.key_package, NB_KEY_PACKAGE);

                        // and a new Credential has been persisted in the keystore
                        assert_eq!(after_rotate.credential - before_rotate.credential, 1);

                        for (id, commit) in rotate_bundle.commits.into_iter() {
                            let decrypted = bob_central
                                .decrypt_message(&id, commit.commit.to_bytes().unwrap())
                                .await
                                .unwrap();
                            alice_central.verify_sender_identity(&case, &decrypted);

                            alice_central.commit_accepted(&id).await.unwrap();
                            alice_central
                                .verify_local_credential_rotated(&id, NEW_HANDLE, NEW_DISPLAY_NAME)
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
                            assert_eq!(identity.display_name, NEW_DISPLAY_NAME);
                            assert_eq!(identity.handle, format!("wireapp://%40{NEW_HANDLE}@wire.com"));
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
                        let before_delete = alice_central.count_entities().await;
                        assert_eq!(
                            before_delete.hpke_private_key - before_rotate.hpke_private_key,
                            NB_KEY_PACKAGE
                        );

                        // 1 has been created per new KeyPackage created in the rotation
                        assert_eq!(before_delete.key_package - before_rotate.key_package, NB_KEY_PACKAGE);

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
                        let after_delete = alice_central.count_entities().await;
                        assert_eq!(after_delete.credential, 1);
                        assert!(alice_central
                            .find_credential_from_keystore(&old_credential)
                            .await
                            .is_none());

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
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        // required because now Alice does not anymore have a Basic credential
                        let alice = alice_central
                            .rand_key_package_of_type(&case, MlsCredentialType::X509)
                            .await;
                        charlie_central
                            .invite_all_members(&case, &id, [(&mut alice_central, alice)])
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
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
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

                    const NEW_HANDLE: &str = "new_alice_wire";
                    const NEW_DISPLAY_NAME: &str = "New Alice Smith";

                    fn init(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
                        Box::pin(async move {
                            let E2eiInitWrapper { cc, case } = wrapper;
                            let cs = case.ciphersuite();
                            match case.credential_type {
                                MlsCredentialType::Basic => cc.e2ei_new_activation_enrollment(
                                    NEW_DISPLAY_NAME.to_string(),
                                    NEW_HANDLE.to_string(),
                                    Some(TEAM.to_string()),
                                    E2EI_EXPIRY,
                                    cs,
                                ),
                                MlsCredentialType::X509 => {
                                    cc.e2ei_new_rotate_enrollment(
                                        Some(NEW_DISPLAY_NAME.to_string()),
                                        Some(NEW_HANDLE.to_string()),
                                        Some(TEAM.to_string()),
                                        E2EI_EXPIRY,
                                        cs,
                                    )
                                    .await
                                }
                            }
                        })
                    }

                    let is_renewal = case.credential_type == MlsCredentialType::X509;
                    let (mut alice_central, enrollment, cert) =
                        e2ei_enrollment(alice_central, &case, None, is_renewal, init, noop_restore)
                            .await
                            .unwrap();

                    alice_central.e2ei_rotate_all(enrollment, cert, 10).await.unwrap();

                    alice_central.commit_accepted(&id).await.unwrap();

                    // So alice has a new Credential as expected
                    let cb = alice_central
                        .find_most_recent_credential_bundle(case.signature_scheme(), MlsCredentialType::X509)
                        .await
                        .unwrap();
                    let identity = cb.credential().extract_identity().unwrap().unwrap();
                    assert_eq!(identity.display_name, NEW_DISPLAY_NAME);
                    assert_eq!(identity.handle, format!("wireapp://%40{NEW_HANDLE}@wire.com"));

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
                        .unwrap()
                        .into_iter()
                        .map(|c| {
                            let credential =
                                openmls::prelude::Credential::tls_deserialize(&mut c.credential.as_slice()).unwrap();
                            (credential, c.created_at)
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(all_credentials.len(), 2);

                    let client = Client::load(
                        &alice_central.mls_backend,
                        &cid,
                        all_credentials,
                        scs,
                        matches!(case.credential_type, MlsCredentialType::X509),
                    )
                    .await
                    .unwrap();
                    alice_central.mls_client = Some(client);

                    // Verify that Alice has the same credentials
                    let cb = alice_central
                        .find_most_recent_credential_bundle(case.signature_scheme(), MlsCredentialType::X509)
                        .await
                        .unwrap();
                    let identity = cb.credential().extract_identity().unwrap().unwrap();
                    assert_eq!(identity.display_name, NEW_DISPLAY_NAME);
                    assert_eq!(identity.handle, format!("wireapp://%40{NEW_HANDLE}@wire.com"));

                    assert_eq!(
                        alice_central.mls_client().unwrap().identities.iter().count(),
                        old_nb_identities
                    );
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn rotate_should_roundtrip(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                        // Alice's turn
                        const ALICE_NEW_HANDLE: &str = "new_alice_wire";
                        const ALICE_NEW_DISPLAY_NAME: &str = "New Alice Smith";

                        fn init_alice(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
                            Box::pin(async move {
                                let E2eiInitWrapper { cc, case } = wrapper;
                                let cs = case.ciphersuite();
                                match case.credential_type {
                                    MlsCredentialType::Basic => cc.e2ei_new_activation_enrollment(
                                        ALICE_NEW_DISPLAY_NAME.to_string(),
                                        ALICE_NEW_HANDLE.to_string(),
                                        Some(TEAM.to_string()),
                                        E2EI_EXPIRY,
                                        cs,
                                    ),
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
                            })
                        }

                        let is_renewal = case.credential_type == MlsCredentialType::X509;
                        let (mut alice_central, enrollment, cert) =
                            e2ei_enrollment(alice_central, &case, None, is_renewal, init_alice, noop_restore)
                                .await
                                .unwrap();

                        let rotate_bundle = alice_central.e2ei_rotate_all(enrollment, cert, 10).await.unwrap();

                        let commit = &rotate_bundle.commits.get(&id).unwrap().commit;

                        let decrypted = bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        alice_central.verify_sender_identity(&case, &decrypted);

                        alice_central.commit_accepted(&id).await.unwrap();
                        alice_central
                            .verify_local_credential_rotated(&id, ALICE_NEW_HANDLE, ALICE_NEW_DISPLAY_NAME)
                            .await;

                        // Bob's turn
                        const BOB_NEW_HANDLE: &str = "new_bob_wire";
                        const BOB_NEW_DISPLAY_NAME: &str = "New Bob Smith";

                        fn init_bob(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
                            Box::pin(async move {
                                let E2eiInitWrapper { cc, case } = wrapper;
                                let cs = case.ciphersuite();
                                match case.credential_type {
                                    MlsCredentialType::Basic => cc.e2ei_new_activation_enrollment(
                                        BOB_NEW_DISPLAY_NAME.to_string(),
                                        BOB_NEW_HANDLE.to_string(),
                                        Some(TEAM.to_string()),
                                        E2EI_EXPIRY,
                                        cs,
                                    ),
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
                            })
                        }
                        let is_renewal = case.credential_type == MlsCredentialType::X509;
                        let (mut bob_central, enrollment, cert) =
                            e2ei_enrollment(bob_central, &case, None, is_renewal, init_bob, noop_restore)
                                .await
                                .unwrap();

                        let rotate_bundle = bob_central.e2ei_rotate_all(enrollment, cert, 10).await.unwrap();

                        let commit = &rotate_bundle.commits.get(&id).unwrap().commit;

                        let decrypted = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        bob_central.verify_sender_identity(&case, &decrypted);

                        bob_central.commit_accepted(&id).await.unwrap();
                        bob_central
                            .verify_local_credential_rotated(&id, BOB_NEW_HANDLE, BOB_NEW_DISPLAY_NAME)
                            .await;
                    })
                },
            )
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
                                .new_conversation(&id, case.credential_type, case.cfg.clone())
                                .await
                                .unwrap();

                            alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                            let init_count = alice_central.count_entities().await;

                            // Alice creates a new Credential, updating her handle/display_name
                            let alice_cid = alice_central.get_client_id();
                            let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                            let cb = alice_central
                                .rotate_credential(&case, new_handle, new_display_name, None)
                                .await;

                            // Verify old identity is still there in the MLS group
                            let alice_old_identities =
                                alice_central.get_device_identities(&id, &[alice_cid]).await.unwrap();
                            let alice_old_identity = alice_old_identities.first().unwrap();
                            assert_ne!(alice_old_identity.display_name, new_display_name);
                            assert_ne!(alice_old_identity.handle, format!("{new_handle}@wire.com"));

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

                            let final_count = alice_central.count_entities().await;
                            assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                            assert_eq!(
                                init_count.epoch_encryption_keypair,
                                final_count.epoch_encryption_keypair
                            );
                            assert_eq!(init_count.key_package, final_count.key_package);
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
                                .new_conversation(&id, case.credential_type, case.cfg.clone())
                                .await
                                .unwrap();

                            alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                            let init_count = alice_central.count_entities().await;

                            // In this case Alice will try to rotate her credential but her commit will be denied
                            // by the backend (because another commit from Bob had precedence)

                            // Alice creates a new Credential, updating her handle/display_name
                            let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                            let cb = alice_central
                                .rotate_credential(&case, new_handle, new_display_name, None)
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
                            let renewed_proposal = decrypted.proposals.first().unwrap();
                            bob_central
                                .decrypt_message(&id, renewed_proposal.proposal.to_bytes().unwrap())
                                .await
                                .unwrap();

                            let rotate_commit = alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();

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

                            let final_count = alice_central.count_entities().await;
                            assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                            // TODO: there is no efficient way to clean a credential when alice merges her pending commit.
                            // One option would be to fetch all conversations and see if Alice is never represented with the said Credential
                            // but let's be honest this is not very efficient.
                            // The other option would be to get rid of having an implicit KeyPackage for the creator of a conversation
                            // assert_eq!(init_count.credential, final_count.credential);
                        })
                    },
                )
                .await
            }
        }
    }
}
