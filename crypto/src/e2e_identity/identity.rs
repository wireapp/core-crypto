use std::collections::HashMap;
use std::str::FromStr;

use itertools::Itertools;
use openmls_traits::OpenMlsCryptoProvider;
use x509_cert::der::pem::LineEnding;

use crate::e2e_identity::id::WireQualifiedClientId;
use crate::mls::credential::ext::CredentialExt;
use crate::prelude::MlsCredentialType;
use crate::{
    e2e_identity::device_status::DeviceStatus,
    prelude::{user_id::UserId, ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation},
};

/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    pub client_id: String,
    /// MLS thumbprint
    pub thumbprint: String,
    /// Status of the Credential at the moment T when this object is created
    pub status: DeviceStatus,
    /// Indicates whether the credential is Basic or X509
    pub credential_type: MlsCredentialType,
    /// In case 'credential_type' is [MlsCredentialType::X509] this is populated
    pub x509_identity: Option<X509Identity>,
}

/// Represents the parts of [WireIdentity] that are specific to a X509 certificate (and not a Basic one).
///
/// We don't use an enum here since the sole purpose of this is to be exposed through the FFI (and
/// union types are impossible to carry over the FFI boundary)
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct X509Identity {
    /// user handle e.g. `john_wire`
    pub handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    pub display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    pub domain: String,
    /// X509 certificate identifying this client in the MLS group ; PEM encoded
    pub certificate: String,
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

        Ok(Self {
            client_id: client_id.try_into()?,
            status: i.status.into(),
            thumbprint: i.thumbprint,
            credential_type: MlsCredentialType::X509,
            x509_identity: Some(X509Identity {
                handle: i.handle.to_string(),
                display_name: i.display_name,
                domain: i.domain,
                certificate,
                serial_number: i.serial_number,
                not_before: i.not_before,
                not_after: i.not_after,
            }),
        })
    }
}

impl MlsCentral {
    /// From a given conversation, get the identity of the members supplied. Identity is only present for
    /// members with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn get_device_identities(
        &self,
        conversation_id: &ConversationId,
        client_ids: &[ClientId],
    ) -> CryptoResult<Vec<WireIdentity>> {
        self.mls_backend
            .authentication_service()
            .refresh_time_of_interest()
            .await;
        self.get_conversation(conversation_id)
            .await?
            .read()
            .await
            .get_device_identities(
                client_ids,
                self.mls_backend.authentication_service().borrow().await.as_ref(),
            )
    }

    /// From a given conversation, get the identity of the users (device holders) supplied.
    /// Identity is only present for devices with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec.
    ///
    /// Returns a Map with all the identities for a given users. Consumers are then recommended to
    /// reduce those identities to determine the actual status of a user.
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn get_user_identities(
        &self,
        conversation_id: &ConversationId,
        user_ids: &[String],
    ) -> CryptoResult<HashMap<String, Vec<WireIdentity>>> {
        self.mls_backend
            .authentication_service()
            .refresh_time_of_interest()
            .await;
        self.get_conversation(conversation_id)
            .await?
            .read()
            .await
            .get_user_identities(
                user_ids,
                self.mls_backend.authentication_service().borrow().await.as_ref(),
            )
    }
}

impl MlsConversation {
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    fn get_device_identities(
        &self,
        device_ids: &[ClientId],
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> CryptoResult<Vec<WireIdentity>> {
        if device_ids.is_empty() {
            return Err(CryptoError::ConsumerError);
        }
        self.members_with_key()
            .into_iter()
            .filter(|(id, _)| device_ids.contains(&ClientId::from(id.as_slice())))
            .map(|(_, c)| c.extract_identity(self.ciphersuite(), env))
            .collect::<CryptoResult<Vec<_>>>()
    }

    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    fn get_user_identities(
        &self,
        user_ids: &[String],
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> CryptoResult<HashMap<String, Vec<WireIdentity>>> {
        if user_ids.is_empty() {
            return Err(CryptoError::ConsumerError);
        }
        let user_ids = user_ids.iter().map(|uid| uid.as_bytes()).collect::<Vec<_>>();

        self.members_with_key()
            .iter()
            .filter_map(|(id, c)| UserId::try_from(id.as_slice()).ok().zip(Some(c)))
            .filter(|(uid, _)| user_ids.contains(uid))
            .map(|(uid, c)| (uid, c.extract_identity(self.ciphersuite(), env)))
            .map(|(uid, identity)| {
                let uid = String::try_from(uid);
                // could be simplified if `Result::zip` was available
                uid.and_then(|uid| identity.map(|id| (uid, id)))
            })
            .process_results(|iter| iter.into_group_map())
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        mls::MlsCentral,
        prelude::{ClientId, ConversationId, MlsCredentialType},
    };
    use crate::{
        prelude::{DeviceStatus, E2eiConversationState},
        test_utils::*,
        CryptoError,
    };

    wasm_bindgen_test_configure!(run_in_browser);

    async fn all_identities_check<const N: usize>(
        central: &mut MlsCentral,
        id: &ConversationId,
        user_ids: &[String; N],
        expected_sizes: [usize; N],
    ) {
        let all_identities = central.get_user_identities(id, user_ids).await.unwrap();
        assert_eq!(all_identities.len(), N);
        for (expected_size, user_id) in expected_sizes.into_iter().zip(user_ids.iter()) {
            let alice_identities = all_identities.get(user_id).unwrap();
            assert_eq!(alice_identities.len(), expected_size);
        }
        // Not found
        let not_found = central
            .get_user_identities(id, &["aaaaaaaaaaaaa".to_string()])
            .await
            .unwrap();
        assert!(not_found.is_empty());

        // Invalid usage
        let invalid = central.get_user_identities(id, &[]).await;
        assert!(matches!(invalid.unwrap_err(), CryptoError::ConsumerError));
    }

    async fn check_identities_device_status<const N: usize>(
        central: &mut MlsCentral,
        id: &ConversationId,
        client_ids: &[ClientId; N],
        name_status: &[(&'static str, DeviceStatus); N],
    ) {
        let mut identities = central.get_device_identities(id, client_ids).await.unwrap();

        for j in 0..N {
            let client_identity = identities.remove(
                identities
                    .iter()
                    .position(|i| i.x509_identity.as_ref().unwrap().display_name == name_status[j].0)
                    .unwrap(),
            );
            assert_eq!(client_identity.status, name_status[j].1);
        }
        assert!(identities.is_empty());

        assert_eq!(
            central.e2ei_conversation_state(id).await.unwrap(),
            E2eiConversationState::NotVerified
        );
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn should_read_device_identities() {
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
    async fn should_read_revoked_device_cross_signed() {
        let case = TestCase::default_x509();
        run_test_with_client_ids_and_revocation(
            case.clone(),
            ["alice", "bob", "rupert"],
            ["john", "dilbert"],
            &["rupert", "dilbert"],
            move |[mut alice, mut bob, mut rupert], [mut john, mut dilbert]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice
                        .mls_central
                        .invite_all(
                            &case,
                            &id,
                            [
                                &mut bob.mls_central,
                                &mut rupert.mls_central,
                                &mut dilbert.mls_central,
                                &mut john.mls_central,
                            ],
                        )
                        .await
                        .unwrap();

                    let (alice_id, bob_id, rupert_id, dilbert_id, john_id) = (
                        alice.mls_central.get_client_id(),
                        bob.mls_central.get_client_id(),
                        rupert.mls_central.get_client_id(),
                        dilbert.mls_central.get_client_id(),
                        john.mls_central.get_client_id(),
                    );

                    let client_ids = [alice_id, bob_id, rupert_id, dilbert_id, john_id];
                    let name_status = [
                        ("alice", DeviceStatus::Valid),
                        ("bob", DeviceStatus::Valid),
                        ("rupert", DeviceStatus::Revoked),
                        ("john", DeviceStatus::Valid),
                        ("dilbert", DeviceStatus::Revoked),
                    ];
                    // Do it a multiple times to avoid WPB-6904 happening again
                    for _ in 0..2 {
                        check_identities_device_status(&mut alice.mls_central, &id, &client_ids, &name_status).await;
                        check_identities_device_status(&mut bob.mls_central, &id, &client_ids, &name_status).await;
                        check_identities_device_status(&mut rupert.mls_central, &id, &client_ids, &name_status).await;
                        check_identities_device_status(&mut john.mls_central, &id, &client_ids, &name_status).await;
                        check_identities_device_status(&mut dilbert.mls_central, &id, &client_ids, &name_status).await;
                    }
                })
            },
        )
        .await
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn should_read_revoked_device() {
        let case = TestCase::default_x509();
        run_test_with_client_ids_and_revocation(
            case.clone(),
            ["alice", "bob", "rupert"],
            [],
            &["rupert"],
            move |[mut alice, mut bob, mut rupert], []| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice
                        .mls_central
                        .invite_all(&case, &id, [&mut bob.mls_central, &mut rupert.mls_central])
                        .await
                        .unwrap();

                    let (alice_id, bob_id, rupert_id) = (
                        alice.mls_central.get_client_id(),
                        bob.mls_central.get_client_id(),
                        rupert.mls_central.get_client_id(),
                    );

                    let client_ids = [alice_id, bob_id, rupert_id];
                    let name_status = [
                        ("alice", DeviceStatus::Valid),
                        ("bob", DeviceStatus::Valid),
                        ("rupert", DeviceStatus::Revoked),
                    ];

                    // Do it a multiple times to avoid WPB-6904 happening again
                    for _ in 0..2 {
                        check_identities_device_status(&mut alice.mls_central, &id, &client_ids, &name_status).await;
                        check_identities_device_status(&mut bob.mls_central, &id, &client_ids, &name_status).await;
                        check_identities_device_status(&mut rupert.mls_central, &id, &client_ids, &name_status).await;
                    }
                })
            },
        )
        .await
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn should_not_fail_when_basic() {
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

                    let mut android_ids = alice_android_central
                        .mls_central
                        .get_device_identities(&id, &[android_id.clone(), ios_id.clone()])
                        .await
                        .unwrap();
                    android_ids.sort();

                    let mut ios_ids = alice_ios_central
                        .mls_central
                        .get_device_identities(&id, &[android_id, ios_id])
                        .await
                        .unwrap();
                    ios_ids.sort();

                    assert_eq!(ios_ids.len(), 2);
                    assert_eq!(ios_ids, android_ids);

                    assert!(ios_ids.iter().all(|i| {
                        matches!(i.credential_type, MlsCredentialType::Basic)
                            && matches!(i.status, DeviceStatus::Valid)
                            && i.x509_identity.is_none()
                            && !i.thumbprint.is_empty()
                            && !i.client_id.is_empty()
                    }));
                })
            },
        )
        .await
    }

    // this test is a duplicate of its counterpart but taking federation into account
    // The heavy lifting of cross-signing the certificates is being done by the test utils.
    #[async_std::test]
    #[wasm_bindgen_test]
    async fn should_read_users_cross_signed() {
        let case = TestCase::default_x509();

        let (alice_android, alice_ios) = (
            "satICT30SbiIpjj1n-XQtA:7684f3f95a5e6848@world.com",
            "satICT30SbiIpjj1n-XQtA:7dfd976fc672c899@world.com",
        );
        let (alicem_android, alicem_ios) = (
            "8h2PRVj_Qyi7p1XLGmdulw:a7c5ac4446bf@world.com",
            "8h2PRVj_Qyi7p1XLGmdulw:10c6f7a0b5ed@world.com",
        );
        let bob_android = "I_7X5oRAToKy9z_kvhDKKQ:8b1fd601510d102a@world.com";
        let bobt_android = "HSLU78bpQCOYwh4FWCac5g:68db8bac6a65d@world.com";

        run_test_with_deterministic_client_ids_and_revocation(
            case.clone(),
            [
                [alice_android, "alice_wire", "Alice Smith"],
                [alice_ios, "alice_wire", "Alice Smith"],
                [bob_android, "bob_wire", "Bob Doe"],
            ],
            [
                [alicem_android, "alice_zeta", "Alice Muller"],
                [alicem_ios, "alice_zeta", "Alice Muller"],
                [bobt_android, "bob_zeta", "Bob Tables"],
            ],
            &[],
            move |[mut alice_android_central, mut alice_ios_central, mut bob_android_central],
                  [mut alicem_android_central, mut alicem_ios_central, mut bobt_android_central]| {
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
                            [
                                &mut alice_ios_central.mls_central,
                                &mut bob_android_central.mls_central,
                                &mut bobt_android_central.mls_central,
                                &mut alicem_ios_central.mls_central,
                                &mut alicem_android_central.mls_central,
                            ],
                        )
                        .await
                        .unwrap();

                    let nb_members = alice_android_central
                        .mls_central
                        .get_conversation_unchecked(&id)
                        .await
                        .members()
                        .len();
                    assert_eq!(nb_members, 6);

                    assert_eq!(
                        alice_android_central.mls_central.get_user_id(),
                        alice_ios_central.mls_central.get_user_id()
                    );

                    let alicem_user_id = alicem_ios_central.mls_central.get_user_id();
                    let bobt_user_id = bobt_android_central.mls_central.get_user_id();

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
                    let user_ids = [alice_user_id, bob_user_id, alicem_user_id, bobt_user_id];
                    let expected_sizes = [2, 1, 2, 1];

                    all_identities_check(&mut alice_android_central.mls_central, &id, &user_ids, expected_sizes).await;
                    all_identities_check(&mut alicem_android_central.mls_central, &id, &user_ids, expected_sizes).await;
                    all_identities_check(&mut alice_ios_central.mls_central, &id, &user_ids, expected_sizes).await;
                    all_identities_check(&mut alicem_ios_central.mls_central, &id, &user_ids, expected_sizes).await;
                    all_identities_check(&mut bob_android_central.mls_central, &id, &user_ids, expected_sizes).await;
                    all_identities_check(&mut bobt_android_central.mls_central, &id, &user_ids, expected_sizes).await;
                })
            },
        )
        .await
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn should_read_users() {
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

                    let user_ids = [alice_user_id, bob_user_id];
                    let expected_sizes = [2, 1];

                    all_identities_check(&mut alice_android_central.mls_central, &id, &user_ids, expected_sizes).await;
                    all_identities_check(&mut alice_ios_central.mls_central, &id, &user_ids, expected_sizes).await;
                    all_identities_check(&mut bob_android_central.mls_central, &id, &user_ids, expected_sizes).await;
                })
            },
        )
        .await
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn should_exchange_messages_cross_signed() {
        let (alice_android, alice_ios) = (
            "satICT30SbiIpjj1n-XQtA:7684f3f95a5e6848@wire.com",
            "satICT30SbiIpjj1n-XQtA:7dfd976fc672c899@wire.com",
        );
        let (alicem_android, alicem_ios) = (
            "8h2PRVj_Qyi7p1XLGmdulw:a7c5ac4446bf@zeta.com",
            "8h2PRVj_Qyi7p1XLGmdulw:10c6f7a0b5ed@zeta.com",
        );
        let bob_android = "I_7X5oRAToKy9z_kvhDKKQ:8b1fd601510d102a@wire.com";
        let bobt_android = "HSLU78bpQCOYwh4FWCac5g:68db8bac6a65d@zeta.com";

        let case = TestCase::default_x509();

        run_cross_signed_tests_with_client_ids(
            case.clone(),
            [
                [alice_android, "alice_wire", "Alice Smith"],
                [alice_ios, "alice_wire", "Alice Smith"],
                [bob_android, "bob_wire", "Bob Doe"],
            ],
            [
                [alicem_android, "alice_zeta", "Alice Muller"],
                [alicem_ios, "alice_zeta", "Alice Muller"],
                [bobt_android, "bob_zeta", "Bob Tables"],
            ],
            ("wire.com", "zeta.com"),
            move |[mut alices_android_central, mut alices_ios_central, mut bob_android_central],
                  [mut alicem_android_central, mut alicem_ios_central, mut bobt_android_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alices_ios_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    alices_ios_central
                        .invite_all(
                            &case,
                            &id,
                            [
                                &mut alices_android_central,
                                &mut bob_android_central,
                                &mut alicem_android_central,
                                &mut alicem_ios_central,
                                &mut bobt_android_central,
                            ],
                        )
                        .await
                        .unwrap();

                    let nb_members = alices_android_central
                        .get_conversation_unchecked(&id)
                        .await
                        .members()
                        .len();
                    assert_eq!(nb_members, 6);

                    assert_eq!(alicem_android_central.get_user_id(), alicem_ios_central.get_user_id());

                    // cross server communication
                    bobt_android_central
                        .try_talk_to(&id, &mut alices_ios_central)
                        .await
                        .unwrap();

                    // same server communication
                    bob_android_central
                        .try_talk_to(&id, &mut alices_ios_central)
                        .await
                        .unwrap();
                })
            },
        )
        .await;
    }
}
