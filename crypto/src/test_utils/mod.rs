#![cfg(test)]
// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

pub use rstest::*;
pub use rstest_reuse::{self, *};
use std::collections::HashMap;

use crate::{
    prelude::{ClientId, ConversationId, MlsCentral, MlsCentralConfiguration},
    CoreCryptoCallbacks,
};

pub mod central;
pub mod fixtures;
pub mod message;
pub mod x509;
// Cannot name it `proteus` because then it conflicts with proteus the crate :(
#[cfg(feature = "proteus")]
pub mod proteus_utils;

use crate::prelude::{ClientIdentifier, MlsCredentialType, INITIAL_KEYING_MATERIAL_COUNT};
pub use central::*;
pub use fixtures::TestCase;
pub use fixtures::*;
pub use message::*;

// FIXME: This takes around 10 minutes on WASM
// #[cfg(debug_assertions)]
pub const GROUP_SAMPLE_SIZE: usize = 9;
// #[cfg(not(debug_assertions))]
// pub const GROUP_SAMPLE_SIZE: usize = 99;

pub async fn run_test_with_central(
    case: TestCase,
    test: impl FnOnce([MlsCentral; 1]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_client_ids(case.clone(), ["alice"], test).await
}

pub async fn run_test_with_client_ids<const N: usize>(
    case: TestCase,
    client_ids: [&'static str; N],
    test: impl FnOnce([MlsCentral; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_deterministic_client_ids(case, client_ids.map(|i| [i, "", ""]), test).await
}

pub async fn run_test_with_deterministic_client_ids<const N: usize>(
    case: TestCase,
    client_ids: [[&'static str; 3]; N],
    test: impl FnOnce([MlsCentral; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_tests(move |paths: [String; N]| {
        Box::pin(async move {
            let stream = paths.into_iter().enumerate().map(|(i, p)| async move {
                let configuration = MlsCentralConfiguration::try_new(
                    p,
                    "test".into(),
                    None,
                    vec![case.cfg.ciphersuite],
                    None,
                    Some(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .unwrap();
                let mut central = MlsCentral::try_new(configuration).await.unwrap();

                let identity = match case.credential_type {
                    MlsCredentialType::Basic => {
                        let client_id: ClientId = client_ids[i][0].into();
                        ClientIdentifier::Basic(client_id)
                    }
                    MlsCredentialType::X509 => {
                        let sc = case.cfg.ciphersuite.signature_algorithm();
                        let id = client_ids[i];
                        let [client_id, handle, display_name] = id;

                        let cert = match (handle, display_name) {
                            ("", "") => crate::prelude::CertificateBundle::rand(&client_id.into(), sc),
                            _ => crate::prelude::CertificateBundle::new(
                                sc,
                                handle,
                                display_name,
                                Some(&client_id.into()),
                                None,
                            ),
                        };
                        ClientIdentifier::X509(HashMap::from([(sc, cert)]))
                    }
                };
                central
                    .mls_init(
                        identity,
                        vec![case.cfg.ciphersuite],
                        Some(INITIAL_KEYING_MATERIAL_COUNT),
                    )
                    .await
                    .unwrap();
                central.callbacks(Box::<ValidationCallbacks>::default());
                central
            });
            let centrals: [MlsCentral; N] = futures_util::future::join_all(stream).await.try_into().unwrap();
            test(centrals).await;
        })
    })
    .await
}

pub async fn run_test_wo_clients(
    case: TestCase,
    test: impl FnOnce(MlsCentral) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_tests(move |paths: [String; 1]| {
        Box::pin(async move {
            let p = paths.get(0).unwrap();

            let ciphersuites = vec![case.cfg.ciphersuite];
            let configuration = MlsCentralConfiguration::try_new(
                p.to_string(),
                "test".into(),
                None,
                ciphersuites,
                None,
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            )
            .unwrap();
            let mut central = MlsCentral::try_new(configuration).await.unwrap();
            central.callbacks(Box::<ValidationCallbacks>::default());
            test(central).await
        })
    })
    .await
}

pub async fn run_tests<const N: usize>(
    test: impl FnOnce([String; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    let paths: [(String, _); N] = (0..N).map(|_| tmp_db_file()).collect::<Vec<_>>().try_into().unwrap();
    // We need to store TempDir because they impl Drop which would delete the file before test begins
    let cloned_paths = paths
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    test(cloned_paths).await;
    drop(paths);
}

#[cfg(not(target_family = "wasm"))]
pub fn tmp_db_file() -> (String, tempfile::TempDir) {
    let file = tempfile::tempdir().unwrap();
    (MlsCentralConfiguration::tmp_store_path(&file), file)
}

#[cfg(target_family = "wasm")]
pub fn tmp_db_file() -> (String, ()) {
    use rand::distributions::{Alphanumeric, DistString};
    let path = format!("{}.idb", Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
    (path, ())
}

pub fn conversation_id() -> ConversationId {
    let uuid = uuid::Uuid::new_v4();
    ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()))
}

#[derive(Debug)]
pub struct ValidationCallbacks {
    pub authorize: bool,
    pub user_authorize: bool,
    pub client_is_existing_group_user: bool,
}

impl Default for ValidationCallbacks {
    fn default() -> Self {
        Self {
            authorize: true,
            user_authorize: true,
            client_is_existing_group_user: true,
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl CoreCryptoCallbacks for ValidationCallbacks {
    async fn authorize(&self, _conversation_id: ConversationId, _client_id: ClientId) -> bool {
        self.authorize
    }

    async fn user_authorize(
        &self,
        _conversation_id: ConversationId,
        _external_client_id: ClientId,
        _existing_clients: Vec<ClientId>,
    ) -> bool {
        self.user_authorize
    }

    async fn client_is_existing_group_user(
        &self,
        _conversation_id: ConversationId,
        _client_id: ClientId,
        _existing_clients: Vec<ClientId>,
        _parent_conversation_clients: Option<Vec<ClientId>>,
    ) -> bool {
        self.client_is_existing_group_user
    }
}
