use crate::{
    mls::credential::ext::CredentialExt,
    prelude::{ClientId, ConversationId, CryptoResult, MlsCentral, MlsConversation},
    CryptoError,
};
use x509_cert::der::pem::LineEnding;

/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    pub client_id: String,
    /// user handle e.g. `john_wire`
    pub handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    pub display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    pub domain: String,
    /// X509 certificate identifying this client in the MLS group ; PEM encoded
    pub certificate: String,
}

impl<'a> TryFrom<(wire_e2e_identity::prelude::WireIdentity, &'a [u8])> for WireIdentity {
    type Error = CryptoError;

    fn try_from((i, cert): (wire_e2e_identity::prelude::WireIdentity, &'a [u8])) -> CryptoResult<Self> {
        use x509_cert::der::Decode as _;
        let document = x509_cert::der::Document::from_der(cert)?;
        let certificate = document.to_pem("CERTIFICATE", LineEnding::LF)?;
        Ok(Self {
            client_id: i.client_id,
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
            certificate,
        })
    }
}

impl MlsCentral {
    /// From a given conversation, get the identity of the members supplied. Identity is only present for
    /// members with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec
    pub async fn get_user_identities(
        &mut self,
        conversation_id: &ConversationId,
        client_ids: &[&ClientId],
    ) -> CryptoResult<Vec<WireIdentity>> {
        self.get_conversation(conversation_id)
            .await?
            .read()
            .await
            .get_user_identities(client_ids)
    }
}

impl MlsConversation {
    fn get_user_identities(&self, client_ids: &[&ClientId]) -> CryptoResult<Vec<WireIdentity>> {
        self.members()
            .into_iter()
            .filter(|(m, _)| client_ids.contains(&&ClientId::from(&m[..])))
            .filter_map(|(_, c)| c.extract_identity().transpose())
            .collect::<CryptoResult<Vec<_>>>()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::test_utils::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const ALICE_ANDROID: &str = "t6wRpI8BRSeviBwwiFp5MQ:a661e79735dc890f@wire.com";
    const ALICE_IOS: &str = "t6wRpI8BRSeviBwwiFp5MQ:ce3c1921aacdbcfe@wire.com";

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_read_identities(case: TestCase) {
        if case.is_x509() {
            run_test_with_client_ids(
                case.clone(),
                [ALICE_ANDROID, ALICE_IOS],
                move |[mut alice_android_central, mut alice_ios_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_android_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_android_central
                            .invite_all(&case, &id, [&mut alice_ios_central])
                            .await
                            .unwrap();

                        let (android_id, ios_id) =
                            (alice_android_central.get_client_id(), alice_ios_central.get_client_id());

                        let mut android_ids = alice_android_central
                            .get_user_identities(&id, &[&android_id, &ios_id])
                            .await
                            .unwrap();
                        android_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                        assert_eq!(android_ids.len(), 2);
                        let mut ios_ids = alice_ios_central
                            .get_user_identities(&id, &[&android_id, &ios_id])
                            .await
                            .unwrap();
                        ios_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                        assert_eq!(ios_ids.len(), 2);

                        assert_eq!(android_ids, ios_ids);

                        let android_identities = alice_android_central
                            .get_user_identities(&id, &[&android_id])
                            .await
                            .unwrap();
                        let android_id = android_identities.first().unwrap();
                        assert_eq!(
                            android_id.client_id.as_bytes(),
                            alice_android_central.client_id().unwrap().0.as_slice()
                        );

                        let ios_identities = alice_android_central
                            .get_user_identities(&id, &[&ios_id])
                            .await
                            .unwrap();
                        let ios_id = ios_identities.first().unwrap();
                        assert_eq!(
                            ios_id.client_id.as_bytes(),
                            alice_ios_central.client_id().unwrap().0.as_slice()
                        );
                    })
                },
            )
            .await
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_not_fail_when_basic(case: TestCase) {
        if case.is_basic() {
            run_test_with_client_ids(
                case.clone(),
                [ALICE_ANDROID, ALICE_IOS],
                move |[mut alice_android_central, mut alice_ios_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_android_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_android_central
                            .invite_all(&case, &id, [&mut alice_ios_central])
                            .await
                            .unwrap();

                        let (android_id, ios_id) =
                            (alice_android_central.get_client_id(), alice_ios_central.get_client_id());

                        let android_ids = alice_android_central
                            .get_user_identities(&id, &[&android_id, &ios_id])
                            .await
                            .unwrap();
                        assert!(android_ids.is_empty());

                        let ios_ids = alice_ios_central
                            .get_user_identities(&id, &[&android_id, &ios_id])
                            .await
                            .unwrap();
                        assert!(ios_ids.is_empty());
                    })
                },
            )
            .await
        }
    }
}
