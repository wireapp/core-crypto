use std::collections::HashMap;
use std::str::FromStr;

use itertools::Itertools;
use x509_cert::der::pem::LineEnding;

use crate::e2e_identity::id::WireQualifiedClientId;
use crate::mls::credential::ext::CredentialExt;
use crate::{
    e2e_identity::device_status::DeviceStatus,
    prelude::{user_id::UserId, ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation},
};

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
    /// X509 certificate serial number
    pub serial_number: String,
    /// X509 certificate not before as Unix timestamp
    pub not_before: u64,
    /// X509 certificate not after as Unix timestamp
    pub not_after: u64,
}

impl<'a> TryFrom<(wire_e2e_identity::prelude::WireIdentity, &'a [u8])> for WireIdentity {
    type Error = CryptoError;

    fn try_from((i, cert): (wire_e2e_identity::prelude::WireIdentity, &'a [u8])) -> CryptoResult<Self> {
        use x509_cert::der::Decode as _;
        let document = x509_cert::der::Document::from_der(cert)?;
        let certificate = document.to_pem("CERTIFICATE", LineEnding::LF)?;

        let client_id = WireQualifiedClientId::from_str(&i.client_id)?;
        let client_id = String::try_from(client_id)?;

        Ok(Self {
            client_id,
            handle: i.handle.to_string(),
            display_name: i.display_name,
            domain: i.domain,
            certificate,
            status: i.status.into(),
            thumbprint: i.thumbprint,
            serial_number: i.serial_number,
            not_before: i.not_before,
            not_after: i.not_after,
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
            return Err(CryptoError::ConsumerError);
        }
        self.members()
            .into_iter()
            .filter(|(id, _)| device_ids.contains(&ClientId::from(id.as_slice())))
            .filter_map(|(_, c)| c.extract_identity().transpose())
            .collect::<CryptoResult<Vec<_>>>()
    }

    fn get_user_identities(&self, user_ids: &[String]) -> CryptoResult<HashMap<String, Vec<WireIdentity>>> {
        if user_ids.is_empty() {
            return Err(CryptoError::ConsumerError);
        }
        let user_ids = user_ids.iter().map(|uid| uid.as_bytes()).collect::<Vec<_>>();
        self.members()
            .iter()
            .filter_map(|(id, c)| UserId::try_from(id.as_slice()).ok().zip(Some(c)))
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
    use wasm_bindgen_test::*;

    use crate::{test_utils::*, CryptoError};

    wasm_bindgen_test_configure!(run_in_browser);

    #[async_std::test]
    #[wasm_bindgen_test]
    pub async fn should_read_device_identities() {
        let case = TestCase::default_x509();
        run_test_with_client_ids(
            case.clone(),
            ["alice_android", "alice_ios"],
            move |[mut alice_android_central, mut alice_ios_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_android_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_android_central
                        .mls_central
                        .invite_all(&case, &id, [&mut alice_ios_central.mls_central])
                        .await
                        .unwrap();

                    let (android_id, ios_id) = (
                        alice_android_central.mls_central.get_client_id(),
                        alice_ios_central.mls_central.get_client_id(),
                    );

                    let mut android_ids = alice_android_central
                        .mls_central
                        .get_device_identities(&id, &[android_id.clone(), ios_id.clone()])
                        .await
                        .unwrap();
                    android_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                    assert_eq!(android_ids.len(), 2);
                    let mut ios_ids = alice_ios_central
                        .mls_central
                        .get_device_identities(&id, &[android_id.clone(), ios_id.clone()])
                        .await
                        .unwrap();
                    ios_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                    assert_eq!(ios_ids.len(), 2);

                    assert_eq!(android_ids, ios_ids);

                    let android_identities = alice_android_central
                        .mls_central
                        .get_device_identities(&id, &[android_id])
                        .await
                        .unwrap();
                    let android_id = android_identities.first().unwrap();
                    assert_eq!(
                        android_id.client_id.as_bytes(),
                        alice_android_central.mls_central.client_id().unwrap().0.as_slice()
                    );

                    let ios_identities = alice_android_central
                        .mls_central
                        .get_device_identities(&id, &[ios_id])
                        .await
                        .unwrap();
                    let ios_id = ios_identities.first().unwrap();
                    assert_eq!(
                        ios_id.client_id.as_bytes(),
                        alice_ios_central.mls_central.client_id().unwrap().0.as_slice()
                    );

                    let invalid = alice_android_central.mls_central.get_device_identities(&id, &[]).await;
                    assert!(matches!(invalid.unwrap_err(), CryptoError::ConsumerError));
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
            ["alice_android", "alice_ios"],
            move |[mut alice_android_central, mut alice_ios_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_android_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_android_central
                        .mls_central
                        .invite_all(&case, &id, [&mut alice_ios_central.mls_central])
                        .await
                        .unwrap();

                    let (android_id, ios_id) = (
                        alice_android_central.mls_central.get_client_id(),
                        alice_ios_central.mls_central.get_client_id(),
                    );

                    let android_ids = alice_android_central
                        .mls_central
                        .get_device_identities(&id, &[android_id.clone(), ios_id.clone()])
                        .await
                        .unwrap();
                    assert!(android_ids.is_empty());

                    let ios_ids = alice_ios_central
                        .mls_central
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

        let (alice_android, alice_ios) = (
            "satICT30SbiIpjj1n-XQtA:7684f3f95a5e6848@world.com",
            "satICT30SbiIpjj1n-XQtA:7dfd976fc672c899@world.com",
        );
        let bob_android = "I_7X5oRAToKy9z_kvhDKKQ:8b1fd601510d102a@world.com";

        run_test_with_deterministic_client_ids(
            case.clone(),
            [
                [alice_android, "alice_wire", "Alice Smith"],
                [alice_ios, "alice_wire", "Alice Smith"],
                [bob_android, "bob_wire", "Bob Doe"],
            ],
            move |[mut alice_android_central, mut alice_ios_central, mut bob_android_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_android_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_android_central
                        .mls_central
                        .invite_all(
                            &case,
                            &id,
                            [&mut alice_ios_central.mls_central, &mut bob_android_central.mls_central],
                        )
                        .await
                        .unwrap();

                    let nb_members = alice_android_central
                        .mls_central
                        .get_conversation_unchecked(&id)
                        .await
                        .members()
                        .len();
                    assert_eq!(nb_members, 3);

                    assert_eq!(
                        alice_android_central.mls_central.get_user_id(),
                        alice_ios_central.mls_central.get_user_id()
                    );

                    // Finds both Alice's devices
                    let alice_user_id = alice_android_central.mls_central.get_user_id();
                    let alice_identities = alice_android_central
                        .mls_central
                        .get_user_identities(&id, &[alice_user_id.clone()])
                        .await
                        .unwrap();
                    assert_eq!(alice_identities.len(), 1);
                    let identities = alice_identities.get(&alice_user_id).unwrap();
                    assert_eq!(identities.len(), 2);

                    // Finds Bob only device
                    let bob_user_id = bob_android_central.mls_central.get_user_id();
                    let bob_identities = alice_android_central
                        .mls_central
                        .get_user_identities(&id, &[bob_user_id.clone()])
                        .await
                        .unwrap();
                    assert_eq!(bob_identities.len(), 1);
                    let identities = bob_identities.get(&bob_user_id).unwrap();
                    assert_eq!(identities.len(), 1);

                    // Finds all devices
                    let all_identities = alice_android_central
                        .mls_central
                        .get_user_identities(&id, &[alice_user_id.clone(), bob_user_id.clone()])
                        .await
                        .unwrap();
                    assert_eq!(all_identities.len(), 2);
                    let alice_identities = alice_identities.get(&alice_user_id).unwrap();
                    assert_eq!(alice_identities.len(), 2);
                    let bob_identities = bob_identities.get(&bob_user_id).unwrap();
                    assert_eq!(bob_identities.len(), 1);

                    // Not found
                    let not_found = alice_android_central
                        .mls_central
                        .get_user_identities(&id, &["aaaaaaaaaaaaa".to_string()])
                        .await
                        .unwrap();
                    assert!(not_found.is_empty());

                    // Invalid usage
                    let invalid = alice_android_central.mls_central.get_user_identities(&id, &[]).await;
                    assert!(matches!(invalid.unwrap_err(), CryptoError::ConsumerError));
                })
            },
        )
        .await
    }
}
