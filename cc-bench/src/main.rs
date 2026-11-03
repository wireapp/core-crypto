//! Benchmarks core-crypto's crypto backends, for comparing builds of different revisions.
//!
//! Every run does some setup, then the measured work. hyperfine times the whole process, so run
//! with `--setup-only` as well to know how much of that is setup. Phase timings go to stderr.

use std::{
    hint::black_box,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use core_crypto::{
    CipherSuite, ClientId, CommitBundle, ConversationConfiguration, ConversationId, CoreCrypto, Credential,
    CredentialRef, Database, DecryptedMessage, HistorySecret, KeyPackageIn, MlsCiphersuite, MlsMessageIn, MlsTransport,
    RustCrypto, TransportData,
};
use openmls_traits::{crypto::OpenMlsCrypto as _, types::AeadType};
use tls_codec::{Deserialize as _, Serialize as _};

#[derive(Parser)]
#[command(about = "Benchmark core-crypto's crypto primitives and MLS operations")]
struct Cli {
    /// MLS ciphersuite, as its IANA number (1, 2, 3, 5 or 7).
    #[arg(long, global = true, default_value_t = 1)]
    ciphersuite: u16,

    /// Do only the setup, so its cost can be subtracted from a full run.
    #[arg(long, global = true)]
    setup_only: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Call one primitive of the crypto provider in a loop.
    Primitive {
        op: Op,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
        /// Size of the input for ops that take data.
        #[arg(long, default_value_t = 1024)]
        size: usize,
    },
    /// Run an MLS scenario through the public core-crypto API.
    #[command(subcommand)]
    Mls(Scenario),
}

#[derive(Clone, Copy, ValueEnum)]
enum Op {
    Hash,
    AeadSeal,
    AeadOpen,
    SigKeygen,
    SigSign,
    SigVerify,
    HkdfExtract,
    HkdfExpand,
    HpkeSeal,
    HpkeOpen,
    HpkeDeriveKeypair,
}

#[derive(Subcommand)]
enum Scenario {
    /// Generate key packages in a single transaction.
    Keypackages {
        #[arg(long, default_value_t = 100)]
        count: usize,
    },
    /// Add `members` clients to a new conversation in one commit; every one of them joins via the welcome.
    CreateGroup {
        #[arg(long, default_value_t = 10)]
        members: usize,
    },
    /// One member encrypts `count` messages and another decrypts them, a transaction per message.
    Messages {
        #[arg(long, default_value_t = 10)]
        members: usize,
        #[arg(long, default_value_t = 100)]
        count: usize,
        #[arg(long, default_value_t = 64)]
        size: usize,
    },
    /// One member commits `count` key updates and another processes them.
    Commits {
        #[arg(long, default_value_t = 10)]
        members: usize,
        #[arg(long, default_value_t = 100)]
        count: usize,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cipher_suite = CipherSuite::try_from(cli.ciphersuite)
        .map_err(|_| anyhow::anyhow!("unknown ciphersuite {}", cli.ciphersuite))?;

    match cli.command {
        Command::Primitive { op, iterations, size } => primitive(op, cipher_suite, iterations, size, cli.setup_only),
        Command::Mls(scenario) => mls(scenario, cipher_suite, cli.setup_only).await,
    }
}

/// Times the measured phase and reports it, unless `setup_only` is set.
fn measure(setup_started: Instant, setup_only: bool, work: impl FnOnce() -> Result<()>) -> Result<()> {
    eprintln!("setup: {:?}", setup_started.elapsed());
    if setup_only {
        return Ok(());
    }
    let started = Instant::now();
    work()?;
    eprintln!("work:  {:?}", started.elapsed());
    Ok(())
}

async fn measure_async(setup_started: Instant, setup_only: bool, work: impl AsyncFnOnce() -> Result<()>) -> Result<()> {
    eprintln!("setup: {:?}", setup_started.elapsed());
    if setup_only {
        return Ok(());
    }
    let started = Instant::now();
    work().await?;
    eprintln!("work:  {:?}", started.elapsed());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------------------------

fn primitive(op: Op, cipher_suite: CipherSuite, iterations: usize, size: usize, setup_only: bool) -> Result<()> {
    let setup_started = Instant::now();
    let cs = MlsCiphersuite::from(cipher_suite);
    let crypto = RustCrypto::default();
    let hash = cs.hash_algorithm();
    let aead = cs.aead_algorithm();
    let scheme = cs.signature_algorithm();
    let data = vec![0xa5u8; size];
    let key = vec![0x42u8; if aead == AeadType::Aes128Gcm { 16 } else { 32 }];
    let nonce = [7u8; 12];
    let aad = b"cc-bench aad";

    match op {
        Op::Hash => measure(setup_started, setup_only, || {
            run(iterations, || Ok(crypto.hash(hash, &data)?))
        }),
        Op::AeadSeal => measure(setup_started, setup_only, || {
            run(iterations, || Ok(crypto.aead_encrypt(aead, &key, &data, &nonce, aad)?))
        }),
        Op::AeadOpen => {
            let ciphertext = crypto.aead_encrypt(aead, &key, &data, &nonce, aad)?;
            measure(setup_started, setup_only, || {
                run(iterations, || {
                    Ok(crypto.aead_decrypt(aead, &key, &ciphertext, &nonce, aad)?)
                })
            })
        }
        Op::SigKeygen => measure(setup_started, setup_only, || {
            run(iterations, || Ok(crypto.signature_key_gen(scheme)?))
        }),
        Op::SigSign => {
            let (sk, pk) = crypto.signature_key_gen(scheme)?;
            let signer = Signer::detect(&crypto, scheme, sk, pk);
            measure(setup_started, setup_only, || {
                run(iterations, || signer.sign(&crypto, &data))
            })
        }
        Op::SigVerify => {
            let (sk, pk) = crypto.signature_key_gen(scheme)?;
            let signature = Signer::detect(&crypto, scheme, sk, pk.clone()).sign(&crypto, &data)?;
            measure(setup_started, setup_only, || {
                run(iterations, || {
                    Ok(crypto.verify_signature(scheme, &data, &pk, &signature)?)
                })
            })
        }
        Op::HkdfExtract => measure(setup_started, setup_only, || {
            run(iterations, || Ok(crypto.hkdf_extract(hash, &key, &data)?))
        }),
        Op::HkdfExpand => {
            let prk = crypto.hkdf_extract(hash, &key, &data)?;
            measure(setup_started, setup_only, || {
                run(iterations, || {
                    Ok(crypto.hkdf_expand(hash, prk.as_slice(), aad, cs.hash_length())?)
                })
            })
        }
        Op::HpkeSeal => {
            let keypair = crypto.derive_hpke_keypair(cs.hpke_config(), &[0x11; 64])?;
            measure(setup_started, setup_only, || {
                run(iterations, || {
                    Ok(crypto.hpke_seal(cs.hpke_config(), &keypair.public, b"info", aad, &data)?)
                })
            })
        }
        Op::HpkeOpen => {
            let keypair = crypto.derive_hpke_keypair(cs.hpke_config(), &[0x11; 64])?;
            let ciphertext = crypto.hpke_seal(cs.hpke_config(), &keypair.public, b"info", aad, &data)?;
            measure(setup_started, setup_only, || {
                run(iterations, || {
                    let plaintext = crypto.hpke_open(cs.hpke_config(), &ciphertext, &keypair.private, b"info", aad)?;
                    ensure!(plaintext == data, "HPKE round trip changed the plaintext");
                    Ok(())
                })
            })
        }
        Op::HpkeDeriveKeypair => measure(setup_started, setup_only, || {
            run(iterations, || {
                Ok(crypto.derive_hpke_keypair(cs.hpke_config(), &[0x11; 64])?)
            })
        }),
    }
}

/// Calls `f` `iterations` times, keeping the optimizer from discarding its output.
fn run<T>(iterations: usize, f: impl Fn() -> Result<T>) -> Result<()> {
    for _ in 0..iterations {
        black_box(f()?);
    }
    Ok(())
}

/// How this build signs.
///
/// On `main`, `OpenMlsCrypto::sign` is `unimplemented!` and MLS signs through the openmls fork's
/// `DefaultSigner`. The variants route signing through the provider. We measure whichever path
/// the build actually uses for MLS.
enum Signer {
    Provider {
        scheme: openmls_traits::types::SignatureScheme,
        sk: Vec<u8>,
    },
    Fork(openmls_basic_credential::SignatureKeyPair),
}

impl Signer {
    fn detect(crypto: &RustCrypto, scheme: openmls_traits::types::SignatureScheme, sk: Vec<u8>, pk: Vec<u8>) -> Self {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let provider_signs = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crypto.sign(scheme, b"probe", &sk).is_ok()
        }))
        .unwrap_or(false);
        std::panic::set_hook(previous_hook);

        if provider_signs {
            eprintln!("signing through the provider");
            Self::Provider { scheme, sk }
        } else {
            eprintln!("signing through the openmls fork's DefaultSigner");
            Self::Fork(openmls_basic_credential::SignatureKeyPair::from_raw(scheme, sk, pk))
        }
    }

    fn sign(&self, crypto: &RustCrypto, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Provider { scheme, sk } => Ok(crypto.sign(*scheme, data, sk)?),
            Self::Fork(keypair) => openmls_traits::signatures::Signer::sign(keypair, data)
                .map_err(|e| anyhow::anyhow!("signing failed: {e:?}")),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// MLS scenarios
// ---------------------------------------------------------------------------------------------

/// Records the latest commit bundle, standing in for the delivery service.
#[derive(Debug, Default)]
struct Transport {
    latest: Mutex<Option<CommitBundle>>,
}

impl Transport {
    fn take(&self) -> Result<CommitBundle> {
        self.latest.lock().unwrap().take().context("no commit bundle was sent")
    }
}

#[async_trait::async_trait]
impl MlsTransport for Transport {
    async fn send_commit_bundle(&self, commit_bundle: CommitBundle) -> core_crypto::Result<()> {
        *self.latest.lock().unwrap() = Some(commit_bundle);
        Ok(())
    }

    async fn prepare_for_transport(&self, _secret: &HistorySecret) -> core_crypto::Result<TransportData> {
        Ok(b"unused".to_vec().into())
    }
}

/// A core-crypto instance with its own in-memory database and one basic credential.
struct Client {
    cc: Arc<CoreCrypto>,
    transport: Arc<Transport>,
    credential: CredentialRef,
}

impl Client {
    async fn new(cipher_suite: CipherSuite, device_id: u64) -> Result<Self> {
        let cc = CoreCrypto::new(Database::open_in_memory()?);
        let transport = Arc::new(Transport::default());
        let client_id = ClientId::new(uuid::Uuid::new_v4(), device_id, "bench.wire.com");

        let tx = cc.new_transaction().await?;
        tx.mls_init(client_id.clone(), transport.clone()).await?;
        let credential = tx.add_credential(Credential::basic(cipher_suite, client_id)?).await?;
        tx.finish().await?;

        Ok(Self {
            cc,
            transport,
            credential,
        })
    }

    async fn key_packages(&self, count: usize) -> Result<Vec<KeyPackageIn>> {
        let tx = self.cc.new_transaction().await?;
        let mut key_packages = Vec::with_capacity(count);
        for _ in 0..count {
            let key_package = tx.generate_key_package(&self.credential, None).await?;
            let bytes = key_package.tls_serialize_detached()?;
            key_packages.push(KeyPackageIn::tls_deserialize(&mut bytes.as_slice())?);
        }
        tx.finish().await?;
        Ok(key_packages)
    }

    async fn create_conversation(&self, id: &ConversationId, cipher_suite: CipherSuite) -> Result<()> {
        let tx = self.cc.new_transaction().await?;
        let config = ConversationConfiguration {
            cipher_suite,
            ..Default::default()
        };
        tx.new_conversation(id, &self.credential, config).await?;
        tx.finish().await?;
        Ok(())
    }

    /// Adds the key packages in one commit and returns the serialized welcome.
    async fn add_members(&self, id: &ConversationId, key_packages: Vec<KeyPackageIn>) -> Result<Vec<u8>> {
        let tx = self.cc.new_transaction().await?;
        tx.conversation(id).await?.add_members(key_packages).await?;
        tx.finish().await?;
        let welcome = self.transport.take()?.welcome.context("add_members sent no welcome")?;
        Ok(welcome.tls_serialize_detached()?)
    }

    async fn join(&self, welcome: &[u8]) -> Result<()> {
        let tx = self.cc.new_transaction().await?;
        tx.process_welcome_message(MlsMessageIn::tls_deserialize(&mut &welcome[..])?)
            .await?;
        tx.finish().await?;
        Ok(())
    }

    async fn encrypt(&self, id: &ConversationId, plaintext: &[u8]) -> Result<Vec<u8>> {
        let tx = self.cc.new_transaction().await?;
        let ciphertext = tx.conversation(id).await?.encrypt_message(plaintext).await?;
        tx.finish().await?;
        Ok(ciphertext)
    }

    async fn decrypt(&self, id: &ConversationId, message: &[u8]) -> Result<DecryptedMessage> {
        let tx = self.cc.new_transaction().await?;
        let decrypted = tx.conversation(id).await?.decrypt_message(message).await?;
        tx.finish().await?;
        Ok(decrypted)
    }

    /// Commits a key update and returns the serialized commit.
    async fn update_key_material(&self, id: &ConversationId) -> Result<Vec<u8>> {
        let tx = self.cc.new_transaction().await?;
        tx.conversation(id).await?.update_key_material().await?;
        tx.finish().await?;
        Ok(self.transport.take()?.commit.tls_serialize_detached()?)
    }
}

/// Builds a conversation of `members` clients, including the creator. Only the creator and the
/// first joiner process anything; the rest exist so the group, and its tree, has the right size.
async fn group(cipher_suite: CipherSuite, members: usize) -> Result<(ConversationId, Client, Client)> {
    ensure!(members >= 2, "a group needs at least two members");
    let id = ConversationId::from(b"cc-bench conversation".to_vec());
    let creator = Client::new(cipher_suite, 0).await?;
    creator.create_conversation(&id, cipher_suite).await?;

    let receiver = Client::new(cipher_suite, 1).await?;
    let mut key_packages = receiver.key_packages(1).await?;
    for device_id in 2..members {
        let other = Client::new(cipher_suite, device_id as u64).await?;
        key_packages.extend(other.key_packages(1).await?);
    }
    let welcome = creator.add_members(&id, key_packages).await?;
    receiver.join(&welcome).await?;
    Ok((id, creator, receiver))
}

async fn mls(scenario: Scenario, cipher_suite: CipherSuite, setup_only: bool) -> Result<()> {
    let setup_started = Instant::now();
    match scenario {
        Scenario::Keypackages { count } => {
            let client = Client::new(cipher_suite, 0).await?;
            measure_async(setup_started, setup_only, async || {
                ensure!(client.key_packages(count).await?.len() == count);
                Ok(())
            })
            .await
        }
        Scenario::CreateGroup { members } => {
            ensure!(members >= 2, "a group needs at least two members");
            let id = ConversationId::from(b"cc-bench conversation".to_vec());
            let creator = Client::new(cipher_suite, 0).await?;
            creator.create_conversation(&id, cipher_suite).await?;
            let mut joiners = Vec::with_capacity(members - 1);
            let mut key_packages = Vec::with_capacity(members - 1);
            for device_id in 1..members {
                let joiner = Client::new(cipher_suite, device_id as u64).await?;
                key_packages.extend(joiner.key_packages(1).await?);
                joiners.push(joiner);
            }
            measure_async(setup_started, setup_only, async || {
                let welcome = creator.add_members(&id, key_packages).await?;
                for joiner in &joiners {
                    joiner.join(&welcome).await?;
                }
                Ok(())
            })
            .await
        }
        Scenario::Messages { members, count, size } => {
            let (id, sender, receiver) = group(cipher_suite, members).await?;
            let plaintext = vec![0x5au8; size];
            measure_async(setup_started, setup_only, async || {
                for _ in 0..count {
                    let ciphertext = sender.encrypt(&id, &plaintext).await?;
                    let DecryptedMessage::ApplicationMessage(decrypted) = receiver.decrypt(&id, &ciphertext).await?
                    else {
                        bail!("expected an application message");
                    };
                    ensure!(decrypted.plaintext == plaintext, "decryption changed the plaintext");
                }
                Ok(())
            })
            .await
        }
        Scenario::Commits { members, count } => {
            let (id, committer, receiver) = group(cipher_suite, members).await?;
            measure_async(setup_started, setup_only, async || {
                for _ in 0..count {
                    let commit = committer.update_key_material(&id).await?;
                    let DecryptedMessage::Commit(_) = receiver.decrypt(&id, &commit).await? else {
                        bail!("expected a commit");
                    };
                }
                Ok(())
            })
            .await
        }
    }
}
