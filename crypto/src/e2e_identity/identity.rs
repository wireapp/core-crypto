use crate::{
    e2e_identity::device_status::DeviceStatus,
    mls::credential::ext::CredentialExt,
    prelude::{user_id::UserId, ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation},
};
use itertools::Itertools;
use std::collections::HashMap;
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
    /// Status of the Credential at the moment T when this object is created
    pub status: DeviceStatus,
    /// MLS thumbprint
    pub thumbprint: String,
}

impl<'a> TryFrom<(wire_e2e_identity::prelude::WireIdentity, &'a [u8])> for WireIdentity {
    type Error = CryptoError;

    fn try_from((i, cert): (wire_e2e_identity::prelude::WireIdentity, &'a [u8])) -> CryptoResult<Self> {
        use x509_cert::der::Decode as _;
        let document = x509_cert::der::Document::from_der(cert)?;
        let certificate = document.to_pem("CERTIFICATE", LineEnding::LF)?;
        Ok(Self {
            client_id: i.client_id,
            handle: i.handle.to_string(),
            display_name: i.display_name,
            domain: i.domain,
            certificate,
            status: i.status.into(),
            thumbprint: i.thumbprint,
        })
    }
}

impl MlsCentral {
    /// From a given conversation, get the identity of the members supplied. Identity is only present for
    /// members with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec
    pub async fn get_device_identities(
        &mut self,
        conversation_id: &ConversationId,
        client_ids: &[ClientId],
    ) -> CryptoResult<Vec<WireIdentity>> {
        self.get_conversation(conversation_id)
            .await?
            .read()
            .await
            .get_device_identities(client_ids)
    }

    /// From a given conversation, get the identity of the users (device holders) supplied.
    /// Identity is only present for devices with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec.
    ///
    /// Returns a Map with all the identities for a given users. Consumers are then recommended to
    /// reduce those identities to determine the actual status of a user.
    pub async fn get_user_identities(
        &mut self,
        conversation_id: &ConversationId,
        user_ids: &[String],
    ) -> CryptoResult<HashMap<String, Vec<WireIdentity>>> {
        self.get_conversation(conversation_id)
            .await?
            .read()
            .await
            .get_user_identities(user_ids)
    }
}

impl MlsConversation {
    fn get_device_identities(&self, device_ids: &[ClientId]) -> CryptoResult<Vec<WireIdentity>> {
        if device_ids.is_empty() {
            return Err(CryptoError::ImplementationError);
        }
        self.members()
            .into_iter()
            .filter(|(m, _)| device_ids.contains(&ClientId::from(&m[..])))
            .filter_map(|(_, c)| c.extract_identity().transpose())
            .collect::<CryptoResult<Vec<_>>>()
    }

    fn get_user_identities(&self, user_ids: &[String]) -> CryptoResult<HashMap<String, Vec<WireIdentity>>> {
        if user_ids.is_empty() {
            return Err(CryptoError::ImplementationError);
        }
        let user_ids = user_ids.iter().map(|uid| uid.as_bytes()).collect::<Vec<_>>();
        self.members()
            .iter()
            .filter_map(|(m, c)| UserId::try_from(m).ok().zip(Some(c)))
            .filter(|(uid, _)| user_ids.contains(uid))
            .filter_map(|(uid, c)| Some(uid).zip(c.extract_identity().transpose()))
            .group_by(|(uid, _)| *uid)
            .into_iter()
            .map(|(uid, group)| {
                let uid = String::try_from(uid);
                let identities = group.into_iter().map(|(_, id)| id).collect::<CryptoResult<Vec<_>>>();
                // TODO: simplify when `Result::zip` available
                uid.and_then(|uid| identities.map(|ids| (uid, ids)))
            })
            .collect::<CryptoResult<HashMap<_, _>>>()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::test_utils::*;
    use crate::CryptoError;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[allow(clippy::redundant_static_lifetimes)]
    const ALICE_ANDROID: &'static str = "t6wRpI8BRSeviBwwiFp5MQ:a661e79735dc890f@wire.com";
    #[allow(clippy::redundant_static_lifetimes)]
    const ALICE_IOS: &'static str = "t6wRpI8BRSeviBwwiFp5MQ:ce3c1921aacdbcfe@wire.com";
    #[allow(clippy::redundant_static_lifetimes)]
    const BOB_ANDROID: &'static str = "wjoxZL5tTzi2-8iND-HimA:2af3cbe39aed8cc5@wire.com";

    #[async_std::test]
    #[wasm_bindgen_test]
    pub async fn should_read_device_identities() {
        let case = TestCase::default_x509();
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
                        .get_device_identities(&id, &[android_id.clone(), ios_id.clone()])
                        .await
                        .unwrap();
                    android_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                    assert_eq!(android_ids.len(), 2);
                    let mut ios_ids = alice_ios_central
                        .get_device_identities(&id, &[android_id.clone(), ios_id.clone()])
                        .await
                        .unwrap();
                    ios_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                    assert_eq!(ios_ids.len(), 2);

                    assert_eq!(android_ids, ios_ids);

                    let android_identities = alice_android_central
                        .get_device_identities(&id, &[android_id])
                        .await
                        .unwrap();
                    let android_id = android_identities.first().unwrap();
                    assert_eq!(
                        android_id.client_id.as_bytes(),
                        alice_android_central.client_id().unwrap().0.as_slice()
                    );

                    let ios_identities = alice_android_central
                        .get_device_identities(&id, &[ios_id])
                        .await
                        .unwrap();
                    let ios_id = ios_identities.first().unwrap();
                    assert_eq!(
                        ios_id.client_id.as_bytes(),
                        alice_ios_central.client_id().unwrap().0.as_slice()
                    );

                    let invalid = alice_android_central.get_device_identities(&id, &[]).await;
                    assert!(matches!(invalid.unwrap_err(), CryptoError::ImplementationError));
                })
            },
        )
        .await
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    pub async fn should_not_fail_when_basic() {
        let case = TestCase::default();
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
                        .get_device_identities(&id, &[android_id.clone(), ios_id.clone()])
                        .await
                        .unwrap();
                    assert!(android_ids.is_empty());

                    let ios_ids = alice_ios_central
                        .get_device_identities(&id, &[android_id, ios_id])
                        .await
                        .unwrap();
                    assert!(ios_ids.is_empty());
                })
            },
        )
        .await
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    pub async fn should_read_users() {
        let case = TestCase::default_x509();
        run_test_with_deterministic_client_ids(
            case.clone(),
            [
                [ALICE_ANDROID, "alice_wire", "Alice Smith"],
                [ALICE_IOS, "alice_wire", "Alice Smith"],
                [BOB_ANDROID, "bob_wire", "Bob Doe"],
            ],
            move |[mut alice_android_central, mut alice_ios_central, mut bob_android_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_android_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_android_central
                        .invite_all(&case, &id, [&mut alice_ios_central, &mut bob_android_central])
                        .await
                        .unwrap();

                    let nb_members = alice_android_central
                        .get_conversation_unchecked(&id)
                        .await
                        .members()
                        .len();
                    assert_eq!(nb_members, 3);

                    // Finds both Alice's devices
                    let alice_identities = alice_android_central
                        .get_user_identities(&id, &["t6wRpI8BRSeviBwwiFp5MQ".to_string()])
                        .await
                        .unwrap();
                    assert_eq!(alice_identities.len(), 1);
                    let identities = alice_identities.get(&"t6wRpI8BRSeviBwwiFp5MQ".to_string()).unwrap();
                    assert_eq!(identities.len(), 2);

                    // Finds Bob only device
                    let bob_identities = alice_android_central
                        .get_user_identities(&id, &["wjoxZL5tTzi2-8iND-HimA".to_string()])
                        .await
                        .unwrap();
                    assert_eq!(bob_identities.len(), 1);
                    let identities = bob_identities.get(&"wjoxZL5tTzi2-8iND-HimA".to_string()).unwrap();
                    assert_eq!(identities.len(), 1);

                    // Finds all devices
                    let all_identities = alice_android_central
                        .get_user_identities(
                            &id,
                            &[
                                "t6wRpI8BRSeviBwwiFp5MQ".to_string(),
                                "wjoxZL5tTzi2-8iND-HimA".to_string(),
                            ],
                        )
                        .await
                        .unwrap();
                    assert_eq!(all_identities.len(), 2);
                    let alice_identities = alice_identities.get(&"t6wRpI8BRSeviBwwiFp5MQ".to_string()).unwrap();
                    assert_eq!(alice_identities.len(), 2);
                    let bob_identities = bob_identities.get(&"wjoxZL5tTzi2-8iND-HimA".to_string()).unwrap();
                    assert_eq!(bob_identities.len(), 1);

                    // Not found
                    let not_found = alice_android_central
                        .get_user_identities(&id, &["aaaaaaaaaaaaa".to_string()])
                        .await
                        .unwrap();
                    assert!(not_found.is_empty());

                    // Invalid usage
                    let invalid = alice_android_central.get_user_identities(&id, &[]).await;
                    assert!(matches!(invalid.unwrap_err(), CryptoError::ImplementationError));
                })
            },
        )
        .await
    }
}
