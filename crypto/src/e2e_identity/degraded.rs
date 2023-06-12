use crate::{
    mls::credential::ext::CredentialExt,
    prelude::{ConversationId, CryptoResult, MlsCentral, MlsConversation, MlsCredentialType},
};

impl MlsCentral {
    /// Indicates when to mark a conversation as degraded i.e. when not all its members have a X509
    /// Credential generated by Wire's end-to-end identity enrollment
    pub async fn e2ei_is_degraded(&mut self, id: &ConversationId) -> CryptoResult<bool> {
        Ok(self.get_conversation(id).await?.read().await.e2ei_is_degraded())
    }
}

impl MlsConversation {
    fn e2ei_is_degraded(&self) -> bool {
        self.group.members().any(|kp| {
            let is_basic = matches!(kp.credential.get_type(), Ok(MlsCredentialType::Basic));
            let invalid_identity = kp.credential.extract_identity().is_err();
            is_basic || invalid_identity
        })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::prelude::MlsCredentialType;
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    // testing the case where both Bob & Alice have the same Credential type
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn uniform_conversation_should_be_degraded_when_basic(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    // That way the conversation creator (Alice) will have the same credential type as Bob
                    let creator_ct = case.credential_type;
                    alice_central
                        .new_conversation(id.clone(), creator_ct, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                    match case.credential_type {
                        MlsCredentialType::Basic => {
                            assert!(alice_central.e2ei_is_degraded(&id).await.unwrap());
                            assert!(bob_central.e2ei_is_degraded(&id).await.unwrap());
                        }
                        MlsCredentialType::X509 => {
                            assert!(!alice_central.e2ei_is_degraded(&id).await.unwrap());
                            assert!(!bob_central.e2ei_is_degraded(&id).await.unwrap());
                        }
                    }
                })
            },
        )
        .await
    }

    // testing the case where Bob & Alice have different Credential type
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn heterogeneous_conversation_should_be_degraded(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    // That way the conversation creator (Alice) will have a different credential type than Bob
                    let creator_client = alice_central.mls_client.as_mut().unwrap();
                    let creator_ct = match case.credential_type {
                        MlsCredentialType::Basic => {
                            let cert_bundle = crate::prelude::CertificateBundle::rand(
                                creator_client.id(),
                                case.cfg.ciphersuite.signature_algorithm(),
                            );
                            creator_client
                                .init_x509_credential_bundle_if_missing(
                                    &alice_central.mls_backend,
                                    case.signature_scheme(),
                                    cert_bundle,
                                )
                                .await
                                .unwrap();

                            MlsCredentialType::X509
                        }
                        MlsCredentialType::X509 => {
                            creator_client
                                .init_basic_credential_bundle_if_missing(
                                    &alice_central.mls_backend,
                                    case.signature_scheme(),
                                )
                                .await
                                .unwrap();
                            MlsCredentialType::Basic
                        }
                    };

                    alice_central
                        .new_conversation(id.clone(), creator_ct, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                    // since in that case both have a different credential type the conversation is always degraded
                    assert!(alice_central.e2ei_is_degraded(&id).await.unwrap());
                    assert!(bob_central.e2ei_is_degraded(&id).await.unwrap());
                })
            },
        )
        .await
    }
}
