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

pub use openmls_traits::types::SignatureScheme;
pub use rstest::*;
pub use rstest_reuse::{self, *};
use std::collections::HashMap;
use std::sync::Arc;
use crate::{
    mls::context::CentralContext,
    prelude::{ClientId, ConversationId, MlsCentral, MlsCentralConfiguration},
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
pub use crate::prelude::{ClientIdentifier, MlsCredentialType, INITIAL_KEYING_MATERIAL_COUNT};
pub use fixtures::{TestCase, *};
pub use message::*;
use crate::prelude::Client;

pub const GROUP_SAMPLE_SIZE: usize = 9;

#[derive(Debug, Clone)]
pub struct ClientContext {
    pub context: CentralContext,
    pub central: MlsCentral,
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
    
    pub async fn client(&self) -> Client {
        let client_guard = self.context.mls_client().await.unwrap();
        client_guard.as_ref().unwrap().clone()
    }
    
    pub async fn get_client_id(&self) -> ClientId {
        self.client().await.id().clone()
    }
}

fn init_x509_test_chain(
    case: &TestCase,
    client_ids: &[[&str; 3]],
    revoked_display_names: &[&str],
    cert_params: CertificateParams,
) -> X509TestChain {
    let root_params = {
        let mut params = cert_params.clone();
        if let Some(root_cn) = &cert_params.common_name {
            params.common_name.replace(format!("{} Root CA", root_cn));
        }
        params
    };
    let local_ca_params = {
        let mut params = cert_params.clone();
        if let Some(root_cn) = &cert_params.common_name {
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

pub async fn run_test_with_client_ids_and_revocation<const N: usize, const F: usize>(
    case: TestCase,
    client_ids: [&'static str; N],
    other_client_ids: [&'static str; F],
    revoked_display_names: &'static [&'static str],
    test: impl FnOnce(
            [ClientContext; N],
            [ClientContext; F],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>
        + 'static,
) {
    run_test_with_deterministic_client_ids_and_revocation(
        case,
        client_ids.map(|display_name| ["", "", display_name]),
        other_client_ids.map(|display_name| ["", "", display_name]),
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
    run_test_with_deterministic_client_ids_and_revocation(case, client_ids, [], &[], |context1, _| {
        Box::pin(async move { test(context1).await })
    })
    .await
}

/// Generates 2 x509 test chains, where the intermediate certificates are also cross-signed.
pub fn init_cross_signed_x509_test_chains<const N: usize, const F: usize>(
    case: &TestCase,
    client_ids: [[&'static str; 3]; N],
    other_client_ids: [[&'static str; 3]; F],
    (params1, params2): (CertificateParams, CertificateParams),
    revoked_display_names: &'static [&'static str],
) -> (X509TestChain, X509TestChain) {
    let mut chain1 = init_x509_test_chain(case, &client_ids, revoked_display_names, params1);
    let mut chain2 = init_x509_test_chain(case, &other_client_ids, revoked_display_names, params2);
    chain1.cross_sign(&mut chain2);
    (chain1, chain2)
}

pub async fn run_cross_signed_tests_with_client_ids<const N: usize, const F: usize>(
    case: TestCase,
    client_ids: [[&'static str; 3]; N],
    other_client_ids: [[&'static str; 3]; F],
    (domain1, domain2): (&'static str, &'static str),
    test: impl FnOnce(
            [ClientContext; N],
            [ClientContext; F],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>
        + 'static,
) {
    assert!(case.is_x509(), "This is only supported for x509 test cases");
    run_cross_tests(move |paths1: [String; N], paths2: [String; F]| {
        Box::pin(async move {
            let params1 = CertificateParams {
                org: domain1.into(),
                common_name: Some("Wire".into()),
                domain: Some(domain1.into()),
                ..Default::default()
            };
            let params2 = CertificateParams {
                org: domain2.into(),
                common_name: Some("Wire DE".into()),
                domain: Some(domain2.into()),
                ..Default::default()
            };

            let (chain1, chain2) =
                init_cross_signed_x509_test_chains(&case, client_ids, other_client_ids, (params1, params2), &[]);

            let centrals1 = create_centrals(&case, paths1, Some(&chain1)).await;
            let centrals2 = create_centrals(&case, paths2, Some(&chain2)).await;
            let mut contexts1 = Vec::new();
            for central in centrals1 {
                contexts1.push(ClientContext{
                    context: central.new_transaction().await.unwrap(),
                    central,
                    x509_test_chain: Arc::new(None),
                });
            }

            let mut contexts2 = Vec::new();
            for central in centrals2 {
                contexts2.push(ClientContext{
                    context: central.new_transaction().await.unwrap(),
                    central,
                    x509_test_chain: Arc::new(None),
                });
            }

            test(
                contexts1.clone().try_into().unwrap(),
                contexts2.clone().try_into().unwrap(),
            )
            .await;
            for c in contexts1 {
                c.context.finish().await.unwrap();
            }
            for c in contexts2 {
                c.context.finish().await.unwrap();
            }
        })
    })
    .await;
}

async fn create_centrals<const N: usize>(
    case: &TestCase,
    paths: [String; N],
    chain: Option<&X509TestChain>,
) -> [MlsCentral; N] {
    let stream = paths.into_iter().enumerate().map(|(i, p)| {
        async move {
            let configuration = MlsCentralConfiguration::try_new(
                p,
                "test".into(),
                None,
                vec![case.cfg.ciphersuite],
                None,
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            )
            .unwrap();
            let central = MlsCentral::try_new(configuration).await.unwrap();
            let context = central.new_transaction().await.unwrap();

            // Setup the X509 PKI environment
            if let Some(chain) = chain {
                chain.register_with_central(&context).await;
            }

            let identity = match case.credential_type {
                MlsCredentialType::Basic => {
                    let client_id: ClientId = WireQualifiedClientId::generate().into();
                    ClientIdentifier::Basic(client_id)
                }
                MlsCredentialType::X509 => {
                    use x509_cert::der::Encode as _;
                    let sc = case.cfg.ciphersuite.signature_algorithm();
                    let actor_cert = &chain.unwrap().actors[i];
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
            context
                .mls_init(
                    identity,
                    vec![case.cfg.ciphersuite],
                    Some(INITIAL_KEYING_MATERIAL_COUNT),
                )
                .await
                .unwrap();
            context.finish().await.unwrap();
            central.callbacks(std::sync::Arc::<ValidationCallbacks>::default()).await;
            central
        }
    });
    futures_util::future::join_all(stream).await.try_into().unwrap()
}

pub async fn run_test_with_deterministic_client_ids_and_revocation<const N: usize, const F: usize>(
    case: TestCase,
    client_ids: [[&'static str; 3]; N],
    cross_signed_client_ids: [[&'static str; 3]; F],
    revoked_display_names: &'static [&'static str],
    test: impl FnOnce(
            [ClientContext; N],
            [ClientContext; F],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>
        + 'static,
) {
    run_cross_tests(move |paths1: [String; N], paths2: [String; F]| {
        Box::pin(async move {
            let (chain1, chain2) = match (case.is_x509(), cross_signed_client_ids.is_empty()) {
                (true, true) => (
                    Some(init_x509_test_chain(
                        &case,
                        &client_ids,
                        revoked_display_names,
                        CertificateParams::default(),
                    )),
                    None,
                ),
                (true, false) => {
                    let res = init_cross_signed_x509_test_chains(
                        &case,
                        client_ids,
                        cross_signed_client_ids,
                        (
                            CertificateParams {
                                org: "world1.com".into(),
                                domain: Some("world1.com".into()),
                                ..CertificateParams::default()
                            },
                            CertificateParams {
                                org: "world2.com".into(),
                                domain: Some("world2.com".into()),
                                ..CertificateParams::default()
                            },
                        ),
                        revoked_display_names,
                    );
                    (Some(res.0), Some(res.1))
                }
                _ => (None, None),
            };

            let centrals = create_centrals(&case, paths1, chain1.as_ref()).await;
            let mut centrals1 = Vec::new();
            for (index, mls_central) in centrals.into_iter().enumerate() {
                let context = ClientContext {
                    context: mls_central.new_transaction().await.unwrap(),
                    central: mls_central,
                    x509_test_chain: std::sync::Arc::new(chain1.clone()),
                };
                centrals1.insert(index, context);
            }
            let centrals = create_centrals(&case, paths2, chain2.as_ref()).await;
            let mut centrals2 = Vec::new();
            for (index, mls_central) in centrals.into_iter().enumerate() {
                let context = ClientContext {
                    context: mls_central.new_transaction().await.unwrap(),
                    central: mls_central,
                    x509_test_chain: std::sync::Arc::new(chain2.clone()),
                };
                centrals2.insert(index, context);
            }

            test(
                centrals1.clone().try_into().unwrap(),
                centrals2.clone().try_into().unwrap(),
            )
            .await;

            for c in centrals1 {
                c.context.finish().await.unwrap();
            }
            for c in centrals2 {
                c.context.finish().await.unwrap();
            }
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
            let central = MlsCentral::try_new(configuration).await.unwrap();
            central.callbacks(std::sync::Arc::<ValidationCallbacks>::default()).await;
            let context = central.new_transaction().await.unwrap();
            test(ClientContext {
                context: context.clone(),
                central,
                x509_test_chain: None.into(),
            })
            .await;
            context.finish().await.unwrap();
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

pub async fn run_cross_tests<const N: usize, const F: usize>(
    test: impl FnOnce([String; N], [String; F]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>
        + 'static,
) {
    let _ = pretty_env_logger::try_init();
    let paths1: [(String, _); N] = (0..N).map(|_| tmp_db_file()).collect::<Vec<_>>().try_into().unwrap();
    let paths2: [(String, _); F] = (0..F).map(|_| tmp_db_file()).collect::<Vec<_>>().try_into().unwrap();
    // We need to store TempDir because they impl Drop which would delete the file before test begins
    let cloned_paths1 = paths1
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let cloned_paths2 = paths2
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    test(cloned_paths1, cloned_paths2).await;
    drop(paths1);
    drop(paths2);
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
