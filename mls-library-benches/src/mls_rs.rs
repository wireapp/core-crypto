use std::{cell::RefCell, ops::Deref};

use mls_rs::{
    CipherSuite, CipherSuiteProvider as _, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
    client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider},
    group::ReceivedMessage,
    identity::{
        SigningIdentity,
        basic::{BasicCredential, BasicIdentityProvider},
    },
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::{BenchSetup, BenchmarkCase};

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

type ClientConfig = WithIdentityProvider<BasicIdentityProvider, WithCryptoProvider<RustCryptoProvider, BaseConfig>>;
type FullClient = Client<ClientConfig>;
type FullGroup = Group<ClientConfig>;

struct Agent {
    client: FullClient,
}

impl Agent {
    fn new(identity: impl AsRef<[u8]>) -> Self {
        let crypto_provider = RustCryptoProvider::new();
        let ciphersuite_provider = crypto_provider
            .cipher_suite_provider(CIPHERSUITE)
            .expect("this ciphersuite is supported");

        let (secret_key, public_key) = ciphersuite_provider
            .signature_key_generate()
            .expect("can generate signing keys");
        let id = BasicCredential::new(identity.as_ref().into());

        let signing_identity = SigningIdentity::new(id.into_credential(), public_key);
        let client = Client::builder()
            .crypto_provider(crypto_provider)
            .identity_provider(BasicIdentityProvider::new())
            .signing_identity(signing_identity, secret_key, CIPHERSUITE)
            .build();

        Agent { client }
    }
}

impl Deref for Agent {
    type Target = FullClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

#[derive(Default)]
pub struct MlsRs;

impl BenchSetup for MlsRs {
    type Case = Case;

    fn ident() -> &'static str {
        "mls-rs"
    }

    fn setup(
        &mut self,
        plaintext_generator: &crate::PlaintextGenerator,
        n_senders: usize,
        n_messages: usize,
    ) -> (Self::Case, u32) {
        let recipient = Agent::new("recipient");
        let mut senders = Vec::with_capacity(n_senders);
        for ident in 0..n_senders {
            senders.push(Agent::new(ident.to_be_bytes()));
        }

        let mut group = recipient
            .create_group(ExtensionList::default(), ExtensionList::default(), None)
            .expect("can create a group");
        let mut add_senders_commit = group.commit_builder();
        for sender in &senders {
            let key_package = sender
                .generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
                .expect("generating sender key package");
            add_senders_commit = add_senders_commit
                .add_member(key_package)
                .expect("can insert the add proposal for this sender to the commit");
        }
        let add_senders_commit = add_senders_commit
            .build()
            .expect("can build a commit adding all senders");
        debug_assert_eq!(
            add_senders_commit.welcome_messages.len(),
            1,
            "we should be configured to send a single welcome message to everyone"
        );

        group
            .apply_pending_commit()
            .expect("can apply pending commit adding all senders");

        let tree_data = group.export_tree();
        let mut sender_groups = Vec::with_capacity(n_senders);
        for sender in &senders {
            let (group, _new_member_info) = sender
                .join_group(Some(tree_data.clone()), &add_senders_commit.welcome_messages[0], None)
                .expect("sender can join group");
            sender_groups.push(RefCell::new(group));
        }

        let mut crc_hasher = crc32fast::Hasher::new();
        let mut messages = Vec::with_capacity(n_messages);
        let mut rng = rand::rng();

        // we have to iterate immutably over `sender_groups`, because otherwise we can't `.cycle`, but that means
        // we need this whole RefCell thing to prove that any given group is only mutable in one place at a time
        for group in sender_groups.iter().cycle().take(n_messages) {
            let group = &mut *group.borrow_mut();
            let plaintext = plaintext_generator.generate_plaintext(&mut rng);
            crc_hasher.update(&plaintext);
            let ciphertext = group
                .encrypt_application_message(&plaintext, Vec::new())
                .expect("can encrypt an application message")
                .to_bytes()
                .expect("application message can be serialized");
            messages.push(ciphertext);
        }

        (Case { group, messages }, crc_hasher.finalize())
    }
}

pub struct Case {
    group: FullGroup,
    messages: Vec<Vec<u8>>,
}

impl BenchmarkCase for Case {
    fn decrypt_all(mut self) -> u32 {
        let mut crc_hasher = crc32fast::Hasher::new();

        for message in self.messages {
            let message = MlsMessage::from_bytes(&message).expect("message was MlsMessage type");
            let ReceivedMessage::ApplicationMessage(message) = self
                .group
                .process_incoming_message(message)
                .expect("group can process incoming message")
            else {
                panic!("message was not ApplicationMessage");
            };

            crc_hasher.update(message.data());
        }

        crc_hasher.finalize()
    }
}
