use crate::prelude::{MlsCentral, MlsConversation};
use crate::CryptoResult;
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::OpenMlsCryptoProvider;

impl MlsCentral {
    /// [MlsCentral] is supposed to be a singleton. Knowing that, it does some optimizations by
    /// keeping MLS groups in memory. Sometimes, especially on iOS, it is required to use extensions
    /// to perform tasks in the background. Extensions are executed in another process so another
    /// [MlsCentral] instance has to be used. This method has to be used to synchronize instances.
    /// It simply fetches the MLS group from keystore in memory.
    #[cfg_attr(test, crate::idempotent)]
    pub async fn restore_from_disk(&mut self) -> CryptoResult<()> {
        self.mls_groups = Self::restore_groups(&self.mls_backend).await?;
        Ok(())
    }

    /// Restore existing groups from the KeyStore.
    pub(crate) async fn restore_groups(
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<crate::group_store::GroupStore<MlsConversation>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let groups = backend.key_store().mls_groups_restore().await?;

        let mut group_store = crate::group_store::GroupStore::default();

        if groups.is_empty() {
            return Ok(group_store);
        }

        for (group_id, (parent_id, state)) in groups.into_iter() {
            let conversation = MlsConversation::from_serialized_state(state, parent_id)?;
            if group_store.try_insert(group_id, conversation).is_err() {
                break;
            }
        }

        Ok(group_store)
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        prelude::{CertificateBundle, ClientIdentifier, MlsCentral, MlsCentralConfiguration, MlsCredentialType},
        test_utils::*,
    };
    use std::collections::HashMap;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_persist_group_state(case: TestCase) {
        run_tests(move |[store_path]| {
            Box::pin(async move {
                let cid = match case.credential_type {
                    MlsCredentialType::Basic => ClientIdentifier::Basic("potato".into()),
                    MlsCredentialType::X509 => {
                        let cert =
                            CertificateBundle::rand(&"potato".into(), case.cfg.ciphersuite.signature_algorithm());
                        ClientIdentifier::X509(HashMap::from([(case.cfg.ciphersuite.signature_algorithm(), cert)]))
                    }
                };
                let configuration = MlsCentralConfiguration::try_new(
                    store_path,
                    "test".to_string(),
                    None,
                    vec![case.ciphersuite()],
                    None,
                )
                .unwrap();

                let mut central = MlsCentral::try_new(configuration.clone()).await.unwrap();
                central.mls_init(cid.clone(), vec![case.ciphersuite()]).await.unwrap();
                let id = conversation_id();
                let _ = central
                    .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                    .await;

                central.mls_groups.remove(id.as_slice()).unwrap();
                central.close().await.unwrap();

                let mut central = MlsCentral::try_new(configuration).await.unwrap();
                central.mls_init(cid, vec![case.ciphersuite()]).await.unwrap();
                let _ = central.encrypt_message(&id, b"Test").await.unwrap();

                central.mls_backend.destroy_and_reset().await.unwrap();
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_restore_group_from_db(case: TestCase) {
        run_tests(move |[alice_path, bob_path]| {
            Box::pin(async move {
                let id = conversation_id();

                let (alice_cid, bob_cid) = match case.credential_type {
                    MlsCredentialType::Basic => (
                        ClientIdentifier::Basic("alice".into()),
                        ClientIdentifier::Basic("bob".into()),
                    ),
                    MlsCredentialType::X509 => {
                        let cert = CertificateBundle::rand(&"alice".into(), case.cfg.ciphersuite.signature_algorithm());
                        let alice =
                            ClientIdentifier::X509(HashMap::from([(case.cfg.ciphersuite.signature_algorithm(), cert)]));
                        let cert = CertificateBundle::rand(&"bob".into(), case.cfg.ciphersuite.signature_algorithm());
                        let bob =
                            ClientIdentifier::X509(HashMap::from([(case.cfg.ciphersuite.signature_algorithm(), cert)]));
                        (alice, bob)
                    }
                };
                let alice_cfg = MlsCentralConfiguration::try_new(
                    alice_path,
                    "test".to_string(),
                    None,
                    vec![case.ciphersuite()],
                    None,
                )
                .unwrap();
                let mut alice_central = MlsCentral::try_new(alice_cfg.clone()).await.unwrap();
                alice_central
                    .mls_init(alice_cid.clone(), vec![case.ciphersuite()])
                    .await
                    .unwrap();

                let bob_cfg = MlsCentralConfiguration::try_new(
                    bob_path,
                    "test".to_string(),
                    None,
                    vec![case.ciphersuite()],
                    None,
                )
                .unwrap();
                let mut bob_central = MlsCentral::try_new(bob_cfg).await.unwrap();
                bob_central.mls_init(bob_cid, vec![case.ciphersuite()]).await.unwrap();

                alice_central
                    .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                // Create another central which will be desynchronized at some point
                let mut alice_central_mirror = MlsCentral::try_new(alice_cfg).await.unwrap();
                alice_central_mirror
                    .mls_init(alice_cid, vec![case.ciphersuite()])
                    .await
                    .unwrap();
                assert!(alice_central_mirror.try_talk_to(&id, &mut bob_central).await.is_ok());

                // alice original instance will update its key without synchronizing with its mirror
                let commit = alice_central.update_keying_material(&id).await.unwrap().commit;
                alice_central.commit_accepted(&id).await.unwrap();
                // at this point using mirror instance is unsafe since it will erase the other
                // instance state in keystore...
                bob_central
                    .decrypt_message(&id, commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                // so here we cannot test that mirror instance can talk to Bob because it would
                // mess up the test, but trust me, it does !

                // after restoring from disk, mirror instance got the right key material for
                // the current epoch hence can talk to Bob
                alice_central_mirror.restore_from_disk().await.unwrap();
                assert!(alice_central_mirror.try_talk_to(&id, &mut bob_central).await.is_ok());
            })
        })
        .await
    }
}
