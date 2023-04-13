//! Allows getting a new certificate either because
//! * display_name or handle changed
//! * the previous certificate is expired.

use crate::prelude::{E2eIdentityResult, MlsCentral, MlsCommitBundle, WireE2eIdentity};
use crate::{CryptoError, CryptoResult};
use openmls::prelude::{GroupId, KeyPackage};
use std::collections::HashMap;

pub struct MlsRenewBundle {
    pub commits: HashMap<GroupId, MlsCommitBundle>,
    pub key_packages: Vec<KeyPackage>,
}

impl MlsCentral {
    /// TODO
    ///
    /// # Arguments
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry_days` - generated x509 certificate expiry in days
    pub fn new_acme_renew(
        &self,
        display_name: String,
        handle: String,
        expiry_days: u32,
    ) -> E2eIdentityResult<WireE2eIdentity> {
        let client = self.mls_client.as_ref().ok_or(CryptoError::MlsNotInitialized)?;
        WireE2eIdentity::try_new(
            client.id().clone(),
            display_name,
            handle,
            expiry_days,
            &self.mls_backend,
            *client.ciphersuite(),
        )
    }

    /// TODO
    pub async fn e2ei_mls_renew(
        &mut self,
        e2ei: WireE2eIdentity,
        certificate_chain: String,
        amount_requested: usize,
    ) -> E2eIdentityResult<MlsRenewBundle> {
        e2ei.certificate_response(self, certificate_chain, true).await?;
        let commits = self.update_all_conversations().await?;
        let kpbs = self.client_keypackages(amount_requested).await?;
        let key_packages = kpbs.into_iter().map(|kpb| kpb.into_parts().0).collect::<Vec<_>>();
        Ok(MlsRenewBundle { commits, key_packages })
    }

    async fn update_all_conversations(&mut self) -> CryptoResult<HashMap<GroupId, MlsCommitBundle>> {
        let conversations = self.get_all_conversations().await?;

        let backend = &self.mls_backend;

        use futures_util::{StreamExt as _, TryStreamExt as _};
        futures_util::stream::iter(conversations)
            .map(|c| Ok::<_, CryptoError>(c))
            .try_fold(HashMap::new(), |mut acc, c| async move {
                let mut c = c.write().await;
                let id = GroupId::from_slice(c.id().as_slice());
                let commit_bundle = c.update_keying_material(backend).await?;
                acc.insert(id, commit_bundle);
                Ok(acc)
            })
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::test_utils::*;
    use wasm_bindgen_test::*;
    use wire_e2e_identity::prelude::*;

    use crate::e2e_identity::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn e2e_identity_renew_should_work(case: TestCase) {
        let is_x509 = matches!(case.credential_type, openmls::prelude::CredentialType::X509);
        if is_x509 && utils::SUPPORTED_ALG.contains(&case.signature_scheme()) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        // MLS clients should already be initialized in this test
                        assert!(alice_central.mls_client.is_some());
                        assert!(bob_central.mls_client.is_some());

                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, [&mut bob_central], case.custom_cfg())
                            .await
                            .unwrap();

                        // Alice
                        let mut alice_identity = WireIdentityBuilder {
                            display_name: "Alice Smith".to_string(),
                            handle: "alice_wire".to_string(),
                            ..Default::default()
                        };
                        let WireIdentityBuilder {
                            client_id: alice_client_id,
                            display_name: alice_display_name,
                            handle: alice_handle,
                            domain: alice_domain,
                            ..
                        } = alice_identity.clone();

                        let enrollment = alice_central
                            .new_acme_renew(alice_display_name.clone(), alice_handle.clone(), 90)
                            .unwrap();
                        // since creating an enrollment creates a new keypair, we have to get it back in order to sign our fake certificate
                        let alice_kp = enrollment.get_key_pair();
                        alice_identity.options = Some(WireIdentityBuilderOptions::X509(WireIdentityBuilderX509 {
                            cert_kp: Some(alice_kp),
                            ..Default::default()
                        }));
                        // Alice refreshes her x509 credential
                        let (certificates, ..) = alice_identity.build_x509_pem();
                        let MlsRenewBundle { commits, .. } = alice_central
                            .e2ei_mls_renew(enrollment, certificates, 10)
                            .await
                            .unwrap();

                        assert_eq!(commits.len(), 1);
                        let MlsCommitBundle { commit, .. } = commits.get(&GroupId::from_slice(id.as_slice())).unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        // Bob processes Alice's update of credential
                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // Alice's credential is updated and both can communicate
                        alice_central.try_talk_to(&id, &mut bob_central).await.unwrap();
                    })
                },
            )
            .await
        }
    }
}
