// disabling the requirement for documentation here because these test utils should not be held to the same standard,
// and historically have not been.
#![allow(missing_docs)]

use crate::{
    CoreCrypto, MlsTransport, MlsTransportResponse,
    prelude::{ClientId, ConversationId, MlsClientConfiguration, Session},
    test_utils::x509::{CertificateParams, X509TestChain, X509TestChainActorArg, X509TestChainArgs},
};
use core_crypto_keystore::DatabaseKey;

use async_lock::RwLock;
use openmls::framing::MlsMessageOut;
pub use openmls_traits::types::SignatureScheme;
pub use rstest::*;
pub use rstest_reuse::{self, *};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

pub mod context;
mod epoch_observer;
mod error;
pub mod fixtures;
pub mod message;
pub mod x509;
// Cannot name it `proteus` because then it conflicts with proteus the crate :(
#[cfg(feature = "proteus")]
pub mod proteus_utils;

use crate::e2e_identity::id::{QualifiedE2eiClientId, WireQualifiedClientId};
pub use crate::prelude::{ClientIdentifier, INITIAL_KEYING_MATERIAL_COUNT, MlsCredentialType};
use crate::prelude::{MlsCommitBundle, MlsGroupInfoBundle};
use crate::transaction_context::TransactionContext;
pub(crate) use epoch_observer::TestEpochObserver;
pub use error::Error as TestError;
use error::Result;
pub use fixtures::{TestCase, *};
pub use message::*;

pub const GROUP_SAMPLE_SIZE: usize = 9;

/// Trace up the error's source chain, and return whether the innermost matches the
/// provided pattern, and guard if supplied.
///
/// Basic syntax matches that of [`std::matches`].
///
/// In case the innermost error of your type is wrapped in a `Box` or similar, you can use
/// an expanded syntax: after the pattern or guard expression, a third argument like
/// `deref Box<ExpectedType>: *`. If you have a more deeply nested type, you can add as
/// many deref operations (stars) as you need.
///
/// We can't write `fn innermost_source` because Rust can't prove that the innermost
/// error lives as long as the original error, and demands that it live as long as
/// `'static`, which is unhelpful. But we can inline the whole thing with a macro, as here.
macro_rules! innermost_source_matches {
    // sure would be nice if we didn't have to write the whole body of this macro twice here.
    // doesn't work though: pass the `matches!` line as a simple `matches!` expression, and
    // `err` is out of scope in the outer context.
    // pass it as a lambda expression taking `err` as a function, and rustc decides that somehow
    // we're causing borrowed data to escape from a closure's scope.
    ($err:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {{
        let mut err: &dyn std::error::Error = &$err;
        while let Some(inner) = err.source() {
            err = inner;
        }

        let outcome = matches!(err.downcast_ref(), Some($pattern) $(if $guard)?);
        if !outcome {
            eprintln!("{err:?}: {err}");
        }

        outcome
    }};
    ($err:expr, $pattern:pat $(if $guard:expr)?, deref $t:ty : $($deref:tt)* $(,)?) => {{
        let mut err: &dyn std::error::Error = &$err;
        while let Some(inner) = err.source() {
            err = inner;
        }

        let outcome = matches!(err.downcast_ref::<$t>().map(|t| &*$($deref)* t), Some($pattern) $(if $guard)?);
        if !outcome {
            eprintln!("{err:?}: {err}");
        }

        outcome
    }};
}
pub(crate) use innermost_source_matches;

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub context: TransactionContext,
    pub session: Session,
    pub mls_transport: Arc<dyn MlsTransportTestExt>,
    pub x509_test_chain: std::sync::Arc<Option<X509TestChain>>,
}

impl SessionContext {
    pub fn x509_chain_unchecked(&self) -> &X509TestChain {
        self.x509_test_chain
            .as_ref()
            .as_ref()
            .expect("No x509 test chain setup")
    }

    pub fn replace_x509_chain(&mut self, new_chain: std::sync::Arc<Option<X509TestChain>>) {
        self.x509_test_chain = new_chain;
    }

    pub async fn session(&self) -> Session {
        self.session.clone()
    }

    pub async fn get_client_id(&self) -> ClientId {
        self.session.id().await.unwrap()
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
    test: impl FnOnce([SessionContext; 1]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_client_ids(case.clone(), ["alice"], test).await
}

pub async fn run_test_with_client_ids<const N: usize>(
    case: TestCase,
    client_ids: [&'static str; N],
    test: impl FnOnce([SessionContext; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_test_with_deterministic_client_ids(case, client_ids.map(|display_name| ["", "", display_name]), test).await
}

pub async fn run_test_with_client_ids_and_revocation<const N: usize, const F: usize>(
    case: TestCase,
    client_ids: [&'static str; N],
    other_client_ids: [&'static str; F],
    revoked_display_names: &'static [&'static str],
    test: impl FnOnce(
        [SessionContext; N],
        [SessionContext; F],
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
    test: impl FnOnce([SessionContext; N]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
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
        [SessionContext; N],
        [SessionContext; F],
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

            let transport1 = Arc::<CoreCryptoTransportSuccessProvider>::default();
            let transport2 = Arc::<CoreCryptoTransportSuccessProvider>::default();
            let centrals1 = create_centrals(&case, paths1, Some(&chain1), transport1.clone()).await;
            let centrals2 = create_centrals(&case, paths2, Some(&chain2), transport2.clone()).await;
            let mut contexts1 = Vec::new();
            for central in centrals1 {
                let cc = CoreCrypto::from(central);
                let context = cc.new_transaction().await.unwrap();
                let central = cc.mls;
                contexts1.push(SessionContext {
                    context,
                    session: central,
                    mls_transport: transport1.clone(),
                    x509_test_chain: Arc::new(None),
                });
            }

            let mut contexts2 = Vec::new();
            for central in centrals2 {
                let cc = CoreCrypto::from(central);
                let context = cc.new_transaction().await.unwrap();
                let central = cc.mls;
                contexts2.push(SessionContext {
                    context,
                    session: central,
                    mls_transport: transport2.clone(),
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
    transport: Arc<dyn MlsTransport>,
) -> [Session; N] {
    let transport = &transport.clone();
    let stream = paths.into_iter().enumerate().map(|(i, p)| {
        async move {
            let configuration = MlsClientConfiguration::try_new(
                p,
                DatabaseKey::generate(),
                None,
                vec![case.cfg.ciphersuite],
                None,
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            )
            .unwrap();
            let client = Session::try_new(configuration).await.unwrap();
            let cc = CoreCrypto::from(client);
            let context = cc.new_transaction().await.unwrap();
            let central = cc.mls;

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
            central.provide_transport(transport.clone()).await;
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
        [SessionContext; N],
        [SessionContext; F],
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

            let transport = Arc::<CoreCryptoTransportSuccessProvider>::default();
            let centrals = create_centrals(&case, paths1, chain1.as_ref(), transport.clone()).await;
            let mut centrals1 = Vec::new();
            for (index, client) in centrals.into_iter().enumerate() {
                let cc = CoreCrypto::from(client);
                let context = SessionContext {
                    context: cc.new_transaction().await.unwrap(),
                    session: cc.mls,
                    mls_transport: transport.clone(),
                    x509_test_chain: Arc::new(chain1.clone()),
                };
                centrals1.insert(index, context);
            }
            let transport = Arc::<CoreCryptoTransportSuccessProvider>::default();
            let centrals = create_centrals(&case, paths2, chain2.as_ref(), transport.clone()).await;
            let mut centrals2 = Vec::new();
            for (index, client) in centrals.into_iter().enumerate() {
                let cc = CoreCrypto::from(client);
                let context = SessionContext {
                    context: cc.new_transaction().await.unwrap(),
                    session: cc.mls,
                    mls_transport: transport.clone(),
                    x509_test_chain: Arc::new(chain2.clone()),
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
    test: impl FnOnce(SessionContext) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> + 'static,
) {
    run_tests(move |paths: [String; 1]| {
        Box::pin(async move {
            let p = paths.first().unwrap();
            // let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

            let ciphersuites = vec![case.cfg.ciphersuite];
            let configuration = MlsClientConfiguration::try_new(
                p.to_string(),
                DatabaseKey::generate(),
                None,
                ciphersuites,
                None,
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            )
            .unwrap();
            let client = Session::try_new(configuration).await.unwrap();
            let transport = Arc::<CoreCryptoTransportSuccessProvider>::default();
            client.provide_transport(transport.clone()).await;
            let cc = CoreCrypto::from(client);
            let context = cc.new_transaction().await.unwrap();
            test(SessionContext {
                context: context.clone(),
                session: cc.mls,
                mls_transport: transport.clone(),
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
    let _ = env_logger::try_init();
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
    let _ = env_logger::try_init();
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
    (MlsClientConfiguration::tmp_store_path(&file), file)
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

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait MlsTransportTestExt: MlsTransport {
    async fn latest_commit_bundle(&self) -> MlsCommitBundle;
    async fn latest_welcome_message(&self) -> MlsMessageOut {
        self.latest_commit_bundle().await.welcome.unwrap().clone()
    }

    async fn latest_commit(&self) -> MlsMessageOut {
        self.latest_commit_bundle().await.commit.clone()
    }

    async fn latest_group_info(&self) -> MlsGroupInfoBundle {
        self.latest_commit_bundle().await.group_info.clone()
    }

    async fn latest_message(&self) -> Vec<u8>;
}

#[derive(Debug, Default)]
pub struct CoreCryptoTransportSuccessProvider {
    latest_commit_bundle: RwLock<Option<MlsCommitBundle>>,
    latest_message: RwLock<Option<Vec<u8>>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl MlsTransport for CoreCryptoTransportSuccessProvider {
    async fn send_commit_bundle(&self, commit_bundle: MlsCommitBundle) -> crate::Result<MlsTransportResponse> {
        self.latest_commit_bundle.write().await.replace(commit_bundle);
        Ok(MlsTransportResponse::Success)
    }

    async fn send_message(&self, mls_message: Vec<u8>) -> crate::Result<MlsTransportResponse> {
        self.latest_message.write().await.replace(mls_message);
        Ok(MlsTransportResponse::Success)
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl MlsTransportTestExt for CoreCryptoTransportSuccessProvider {
    async fn latest_commit_bundle(&self) -> MlsCommitBundle {
        self.latest_commit_bundle
            .read()
            .await
            .clone()
            .expect("latest_commit_bundle")
    }

    async fn latest_message(&self) -> Vec<u8> {
        self.latest_message.read().await.clone().expect("latest_message")
    }
}

#[derive(Debug, Default)]
pub struct CoreCryptoTransportAbortProvider;

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl MlsTransport for CoreCryptoTransportAbortProvider {
    async fn send_commit_bundle(&self, _commit_bundle: MlsCommitBundle) -> crate::Result<MlsTransportResponse> {
        Ok(MlsTransportResponse::Abort {
            reason: "abort provider always aborts!".to_string(),
        })
    }

    async fn send_message(&self, _mls_message: Vec<u8>) -> crate::Result<MlsTransportResponse> {
        Ok(MlsTransportResponse::Abort {
            reason: "abort provider always aborts!".to_string(),
        })
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl MlsTransportTestExt for CoreCryptoTransportAbortProvider {
    async fn latest_commit_bundle(&self) -> MlsCommitBundle {
        unreachable!("abort provider never stores a commit bundle")
    }

    async fn latest_message(&self) -> Vec<u8> {
        unreachable!("abort provider never stores a message")
    }
}

/// This alternates between retry and success responses (starts with retry).
#[derive(Debug, Default)]
pub struct CoreCryptoTransportRetrySuccessProvider {
    latest_commit_bundle: RwLock<Option<MlsCommitBundle>>,
    latest_message: RwLock<Option<Vec<u8>>>,
    just_returned_retry: RwLock<bool>,
    retry_count: RwLock<u32>,
    success_count: RwLock<u32>,
    intermediate_commits: RwLock<Option<IntermediateCommits>>,
}

#[derive(Debug, Clone)]
struct IntermediateCommits {
    receiver: SessionContext,
    conversation_id: ConversationId,
    commits: Arc<[MlsMessageOut]>,
}

impl CoreCryptoTransportRetrySuccessProvider {
    /// Adds intermediate commits that will be consumed and processed before the next time `Retry` is returned.
    pub fn with_intermediate_commits(
        mut self,
        receiver: SessionContext,
        commits: &[MlsMessageOut],
        conversation_id: &ConversationId,
    ) -> Self {
        self.intermediate_commits = Some(IntermediateCommits {
            receiver,
            commits: commits.into(),
            conversation_id: conversation_id.clone(),
        })
        .into();
        self
    }

    pub async fn retry_count(&self) -> u32 {
        *self.retry_count.read().await
    }

    pub async fn success_count(&self) -> u32 {
        *self.success_count.read().await
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl MlsTransport for CoreCryptoTransportRetrySuccessProvider {
    async fn send_commit_bundle(&self, commit_bundle: MlsCommitBundle) -> crate::Result<MlsTransportResponse> {
        let mut just_returned_retry = self.just_returned_retry.write().await;
        if *just_returned_retry {
            *just_returned_retry = false;
            *self.success_count.write().await += 1;
            self.latest_commit_bundle.write().await.replace(commit_bundle);
            Ok(MlsTransportResponse::Success)
        } else {
            *just_returned_retry = true;
            *self.retry_count.write().await += 1;
            let mut intermediate_commits = self.intermediate_commits.write().await;
            let Some(IntermediateCommits {
                receiver,
                conversation_id,
                commits,
            }) = intermediate_commits.deref()
            else {
                return Ok(MlsTransportResponse::Retry);
            };
            for commit in commits.iter() {
                receiver
                    .context
                    .conversation(conversation_id)
                    .await
                    .expect("conversation guard")
                    .decrypt_message(commit.to_bytes().expect("reading bytes from intermediate commit"))
                    .await
                    .expect("processed intermediate commit");
            }
            *intermediate_commits = None;
            Ok(MlsTransportResponse::Retry)
        }
    }

    async fn send_message(&self, mls_message: Vec<u8>) -> crate::Result<MlsTransportResponse> {
        let mut just_returned_retry = self.just_returned_retry.write().await;
        if *just_returned_retry {
            self.latest_message.write().await.replace(mls_message);
            *just_returned_retry = false;
            *self.success_count.write().await += 1;
            Ok(MlsTransportResponse::Success)
        } else {
            *just_returned_retry = true;
            *self.retry_count.write().await += 1;
            Ok(MlsTransportResponse::Retry)
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl MlsTransportTestExt for CoreCryptoTransportRetrySuccessProvider {
    async fn latest_commit_bundle(&self) -> MlsCommitBundle {
        self.latest_commit_bundle
            .read()
            .await
            .clone()
            .expect("latest_commit_bundle")
    }

    async fn latest_message(&self) -> Vec<u8> {
        self.latest_message.read().await.clone().expect("latest_message")
    }
}
