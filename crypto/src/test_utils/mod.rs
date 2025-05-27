// disabling the requirement for documentation here because these test utils should not be held to the same standard,
// and historically have not been.
#![allow(missing_docs)]

pub mod context;
mod epoch_observer;
mod error;
pub mod message;
pub mod test_context;
mod test_conversation;
pub mod x509;
// Cannot name it `proteus` because then it conflicts with proteus the crate :(
#[cfg(feature = "proteus")]
pub mod proteus_utils;

pub(crate) use self::epoch_observer::TestEpochObserver;
use self::error::Result;
pub use self::{error::Error as TestError, message::*, test_context::*, test_conversation::TestConversation};
pub use crate::prelude::{ClientIdentifier, INITIAL_KEYING_MATERIAL_COUNT, MlsCredentialType};
use crate::{
    CoreCrypto, MlsTransport, MlsTransportResponse, RecursiveError,
    e2e_identity::id::QualifiedE2eiClientId,
    prelude::{
        CertificateBundle, ClientId, ConversationId, MlsClientConfiguration, MlsCommitBundle, MlsGroupInfoBundle,
        Session,
    },
    test_utils::x509::{CertificateParams, X509TestChain, X509TestChainActorArg, X509TestChainArgs},
    transaction_context::TransactionContext,
};
use core_crypto_keystore::DatabaseKey;

use async_lock::RwLock;
use openmls::framing::MlsMessageOut;
pub use openmls_traits::types::SignatureScheme;

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

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
    pub transaction: TransactionContext,
    pub session: Session,
    mls_transport: Arc<RwLock<Arc<dyn MlsTransportTestExt + 'static>>>,
    x509_test_chain: std::sync::Arc<Option<X509TestChain>>,
    // We need to store the `TempDir` struct for the duration of the test session,
    // because its drop implementation takes care of the directory deletion.
    #[cfg(not(target_family = "wasm"))]
    _db_file: (String, Arc<tempfile::TempDir>),
    #[cfg(target_family = "wasm")]
    _db_file: (String, ()),
}

#[derive(Default, Clone, Copy)]
pub enum TestCertificateSource {
    /// Can be used in all x509 tests that don't use cross-signed certificate chains
    #[default]
    Generated,
    /// Must be used in contexts where using cross-signed certificate chains
    TestChainActor(usize),
}

impl SessionContext {
    /// Use this if you want to instantiate a session with a credential different from
    /// the default one of the test context
    pub async fn new_with_identifier(
        context: &TestContext,
        identifier: ClientIdentifier,
        chain: Option<&X509TestChain>,
    ) -> crate::Result<Self> {
        // We need to store the `TempDir` struct for the duration of the test session,
        // because its drop implementation takes care of the directory deletion.
        let (db_dir_string, db_dir) = tmp_db_file();
        let transport = context.transport.clone();
        let configuration = MlsClientConfiguration::try_new(
            db_dir_string.clone(),
            DatabaseKey::generate(),
            None,
            vec![context.cfg.ciphersuite],
            None,
            Some(INITIAL_KEYING_MATERIAL_COUNT),
        )
        .unwrap();
        let session = Session::try_new(configuration).await.unwrap();
        let cc = CoreCrypto::from(session);
        let transaction = cc.new_transaction().await.unwrap();
        let session = cc.mls;
        // Setup the X509 PKI environment
        if let Some(chain) = chain.as_ref() {
            chain.register_with_central(&transaction).await;
        }

        transaction
            .mls_init(
                identifier,
                vec![context.cfg.ciphersuite],
                Some(INITIAL_KEYING_MATERIAL_COUNT),
            )
            .await
            .map_err(RecursiveError::transaction("mls init"))?;
        session.provide_transport(transport.clone()).await;

        let result = Self {
            transaction,
            session,
            mls_transport: Arc::new(RwLock::new(transport)),
            x509_test_chain: Arc::new(chain.cloned()),
            #[cfg(not(target_family = "wasm"))]
            _db_file: (db_dir_string, Arc::new(db_dir)),
            #[cfg(target_family = "wasm")]
            _db_file: (db_dir_string, db_dir),
        };
        Ok(result)
    }

    pub(crate) async fn new_uninitialized(context: &TestContext) -> Self {
        let (db_dir_string, db_dir) = tmp_db_file();
        let ciphersuites = vec![context.cfg.ciphersuite];
        let configuration = MlsClientConfiguration::try_new(
            db_dir_string.clone(),
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
        Self {
            transaction: context.clone(),
            session: cc.mls,
            mls_transport: Arc::new(RwLock::new(transport.clone())),
            x509_test_chain: None.into(),
            #[cfg(not(target_family = "wasm"))]
            _db_file: (db_dir_string, Arc::new(db_dir)),
            #[cfg(target_family = "wasm")]
            _db_file: (db_dir_string, db_dir),
        }
    }

    fn x509_client_id(
        client_id: &ClientId,
        signature_scheme: SignatureScheme,
        cert_source: &TestCertificateSource,
        chain: &X509TestChain,
    ) -> ClientIdentifier {
        // Take bundle from chain or generate a new one
        let bundle = match cert_source {
            TestCertificateSource::Generated => {
                crate::prelude::CertificateBundle::rand(client_id, chain.find_local_intermediate_ca())
            }
            TestCertificateSource::TestChainActor(i) => {
                use x509_cert::der::Encode as _;
                let actor = chain
                                .actors
                                .get(*i)
                                .expect("if using test chain actors, you must have enough actors in the list. Did you mean to generate a certificate?");
                let actor_cert = &actor.certificate;
                let cert_der = actor_cert.certificate.to_der().unwrap();
                CertificateBundle {
                    certificate_chain: vec![cert_der],
                    private_key: crate::mls::credential::x509::CertificatePrivateKey {
                        signature_scheme,
                        value: actor_cert.pki_keypair.signing_key_bytes(),
                    },
                }
            }
        };
        ClientIdentifier::X509(HashMap::from([(signature_scheme, bundle)]))
    }

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

    pub async fn replace_transport(&self, new_transport: Arc<dyn MlsTransportTestExt>) {
        self.transaction
            .set_transport_callbacks(Some(new_transport.clone()))
            .await
            .unwrap();

        let mut transport_guard = self.mls_transport.write().await;
        *transport_guard = new_transport;
    }

    pub async fn mls_transport(&self) -> Arc<dyn MlsTransportTestExt> {
        self.mls_transport.read().await.clone()
    }
}

fn init_x509_test_chain(
    case: &TestContext,
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
                    .transaction
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
