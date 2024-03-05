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

#![cfg(test)]

use mls_crypto_provider::PkiKeypair;
use openmls_traits::types::SignatureScheme;
pub use rstest::*;
pub use rstest_reuse::{self, *};
use std::collections::HashMap;

use crate::{
    prelude::{ClientId, ConversationId, E2eiEnrollment, MlsCentral, MlsCentralConfiguration},
    test_utils::x509::{CertificateParams, X509TestChain, X509TestChainActorArg, X509TestChainArgs},
    CoreCryptoCallbacks,
};

pub mod central;
pub mod fixtures;
pub mod message;
pub mod x509;
// Cannot name it `proteus` because then it conflicts with proteus the crate :(
#[cfg(feature = "proteus")]
pub mod proteus_utils;

use crate::e2e_identity::id::{QualifiedE2eiClientId, WireQualifiedClientId};
use crate::prelude::{ClientIdentifier, MlsCredentialType, INITIAL_KEYING_MATERIAL_COUNT};
pub use fixtures::{TestCase, *};
pub use message::*;

// FIXME: This takes around 10 minutes on WASM
// #[cfg(debug_assertions)]
pub const GROUP_SAMPLE_SIZE: usize = 9;
// #[cfg(not(debug_assertions))]
// pub const GROUP_SAMPLE_SIZE: usize = 99;

#[derive(Debug)]
pub struct ClientContext {
    pub mls_central: MlsCentral,
    pub initial_identifier: String,
    pub x509_test_chain: std::sync::Arc<Option<X509TestChain>>,
}

impl ClientContext {
    pub fn x509_chain_unchecked(&self) -> &X509TestChain {
        self.x509_test_chain
            .as_ref()
            .as_ref()
            .expect("No x509 test chain setup")
    }

    pub fn replace_x509_chain(&mut self, new_chain: std::sync::Arc<Option<X509TestChain>>) {
        self.x509_test_chain = new_chain;
    }

    /// Order of priority: Enrollment, X509TestChain, MlsCentral's most recent credential bundle
    pub async fn client_initial_pki_keypair(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
        enrollment: Option<&E2eiEnrollment>,
    ) -> Option<PkiKeypair> {
        if let Some(enrollment) = enrollment {
            return Some(PkiKeypair::new(sc, enrollment.sign_sk.to_vec()).unwrap());
        }

        if let Some(x509_test_chain) = self.x509_test_chain.as_ref().as_ref() {
            return x509_test_chain
                .find_certificate_for_actor(&self.initial_identifier)
                .map(|cert| cert.pki_keypair.clone());
        }

        self.mls_central
            .find_most_recent_credential_bundle(sc, ct)
            .await
            .map(|cred_bundle| PkiKeypair::new(sc, cred_bundle.signature_key.private().into()).unwrap())
    }
}

fn init_x509_test_chain(case: &TestCase, client_ids: &[[&str; 3]], revoked_display_names: &[&str]) -> X509TestChain {
    let default_params = CertificateParams::default();
    let root_params = {
        let mut params = default_params.clone();
        if let Some(root_cn) = &default_params.common_name {
            params.common_name.replace(format!("{} Root CA", root_cn));
        }
        params
    };
    let local_ca_params = {
        let mut params = default_params.clone();
        if let Some(root_cn) = &default_params.common_name {
            params.common_name.replace(format!("{} Intermediate CA", root_cn));
        }
        params
    };

    let local_actors = client_ids
        .iter()
        .map(|[client_id, handle, display_name]| X509TestChainActorArg {
            name: display_name.to_string(),
            handle: if handle.is_empty() {
                format!("{display_name}_wire")
            } else {
                handle.to_string()
            },
            client_id: if client_id.is_empty() {
                QualifiedE2eiClientId::generate_with_domain(local_ca_params.domain.as_ref().unwrap())
                    .try_into()
                    .unwrap()
            } else {
                client_id.to_string()
            },
            is_revoked: revoked_display_names.contains(display_name),
        })
        .collect();

    X509TestChain::init(X509TestChainArgs {
        root_params,
        local_ca_params,
        signature_scheme: case.signature_scheme(),
        federated_test_chains: &[],
        local_actors,
        dump_pem_certs: false,
    })
}

pub async fn run_test_with_central(
    case: TestCase,
    test: impl FnOnce([ClientContext; 1]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_client_ids(case.clone(), ["alice"], test).await
}

pub async fn run_test_with_client_ids<const N: usize>(
    case: TestCase,
    client_ids: [&'static str; N],
    test: impl FnOnce([ClientContext; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_deterministic_client_ids(case, client_ids.map(|display_name| ["", "", display_name]), test).await
}

pub async fn run_test_with_client_ids_and_revocation<const N: usize>(
    case: TestCase,
    client_ids: [&'static str; N],
    revoked_display_names: &'static [&'static str],
    test: impl FnOnce([ClientContext; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_deterministic_client_ids_and_revocation(
        case,
        client_ids.map(|display_name| ["", "", display_name]),
        revoked_display_names,
        test,
    )
    .await
}

pub async fn run_test_with_deterministic_client_ids<const N: usize>(
    case: TestCase,
    client_ids: [[&'static str; 3]; N],
    test: impl FnOnce([ClientContext; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_deterministic_client_ids_and_revocation(case, client_ids, &[], test).await
}

pub async fn run_test_with_deterministic_client_ids_and_revocation<const N: usize>(
    case: TestCase,
    client_ids: [[&'static str; 3]; N],
    revoked_display_names: &'static [&'static str],
    test: impl FnOnce([ClientContext; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_tests(move |paths: [String; N]| {
        Box::pin(async move {
            let x509_test_chain = std::sync::Arc::new(
                case.is_x509()
                    .then(|| init_x509_test_chain(&case, &client_ids, revoked_display_names)),
            );

            let path_x509_chains: Vec<std::sync::Arc<Option<X509TestChain>>> =
                (0..paths.len()).map(|_| x509_test_chain.clone()).collect();

            let stream = paths
                .into_iter()
                .enumerate()
                .zip(path_x509_chains.into_iter())
                .zip(client_ids)
                .map(|(((i, p), x509_test_chain), [_, _, initial_identifier])| async move {
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

                    // Setup the X509 PKI environment
                    if let Some(x509_test_chain) = x509_test_chain.as_ref() {
                        x509_test_chain.register_with_central(&central).await;
                    }

                    let identity = match case.credential_type {
                        MlsCredentialType::Basic => {
                            let client_id: ClientId = WireQualifiedClientId::generate().into();
                            ClientIdentifier::Basic(client_id)
                        }
                        MlsCredentialType::X509 => {
                            use x509_cert::der::Encode as _;
                            let sc = case.cfg.ciphersuite.signature_algorithm();
                            let actor_cert = &x509_test_chain.as_ref().as_ref().unwrap().actors[i];
                            let cert_der = actor_cert.certificate.certificate.to_der().unwrap();
                            let bundle = crate::prelude::CertificateBundle {
                                certificate_chain: vec![cert_der],
                                private_key: crate::mls::credential::x509::CertificatePrivateKey {
                                    signature_scheme: sc,
                                    value: actor_cert.certificate.pki_keypair.signing_key_bytes(),
                                },
                            };

                            ClientIdentifier::X509(HashMap::from([(sc, bundle)]))
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
                    ClientContext {
                        mls_central: central,
                        initial_identifier: initial_identifier.into(),
                        x509_test_chain,
                    }
                });
            let centrals: [ClientContext; N] = futures_util::future::join_all(stream).await.try_into().unwrap();
            test(centrals).await;
        })
    })
    .await
}

pub async fn run_test_wo_clients(
    case: TestCase,
    test: impl FnOnce(ClientContext) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_tests(move |paths: [String; 1]| {
        Box::pin(async move {
            let p = paths.first().unwrap();
            // let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

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
            test(ClientContext {
                mls_central: central,
                initial_identifier: String::from("nobody"),
                x509_test_chain: None.into(),
            })
            .await
        })
    })
    .await
}

pub async fn run_tests<const N: usize>(
    test: impl FnOnce([String; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    let _ = pretty_env_logger::try_init();
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
