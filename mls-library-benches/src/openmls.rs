use std::cell::RefCell;

use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::{BenchSetup, BenchmarkCase};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const SIGNATURE_SCHEME: SignatureScheme = CIPHERSUITE.signature_algorithm();

/// An actor in this scenario: the recipient, or one of potentially many senders
struct Agent {
    provider: OpenMlsRustCrypto,
    credential: BasicCredential,
    signature_keys: SignatureKeyPair,
}

impl Agent {
    fn new(identity: impl AsRef<[u8]>) -> Self {
        let credential = BasicCredential::new(identity.as_ref().into());
        let signature_keys = SignatureKeyPair::new(SIGNATURE_SCHEME).expect("Error generating a signature key pair.");
        let provider = OpenMlsRustCrypto::default();

        // Store the signature key into the key store so OpenMLS has access
        // to it.
        signature_keys
            .store(provider.storage())
            .expect("Error storing signature keys in key store.");

        Self {
            provider,
            credential,
            signature_keys,
        }
    }

    fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.credential.clone().into(),
            signature_key: self.signature_keys.public().into(),
        }
    }
}

#[derive(Default)]
pub struct OpenMls;

impl BenchSetup for OpenMls {
    type Case = Case;

    fn ident() -> &'static str {
        "OpenMLS"
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

        // create a group
        let mut group = MlsGroup::new(
            &recipient.provider,
            &recipient.signature_keys,
            &MlsGroupCreateConfig::default(),
            recipient.credential_with_key(),
        )
        .expect("group creation must succeed");

        // invite all senders
        let key_packages = senders
            .iter()
            .map(|agent| {
                KeyPackage::builder()
                    .build(
                        CIPHERSUITE,
                        &agent.provider,
                        &agent.signature_keys,
                        agent.credential_with_key(),
                    )
                    .expect("packing keypackage succeeds")
                    .key_package()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        let (_message, welcome, _group_info) = group
            .add_members(&recipient.provider, &recipient.signature_keys, &key_packages)
            .expect("adding members to group should succeed");

        // merge this pending add commit
        group
            .merge_pending_commit(&recipient.provider)
            .expect("merging commit adding new members");
        let ratchet_tree = group.export_ratchet_tree();

        let welcome = welcome.tls_serialize_detached().expect("could serialize welcome");
        let welcome = MlsMessageIn::tls_deserialize(&mut welcome.as_slice()).expect("can parse welcome from bytes");
        let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            unreachable!("this is definitely a welcome message");
        };

        let mut sender_groups = Vec::with_capacity(n_senders);
        for agent in &senders {
            let staged_join = StagedWelcome::new_from_welcome(
                &agent.provider,
                &MlsGroupJoinConfig::default(),
                welcome.clone(),
                Some(ratchet_tree.clone().into()),
            )
            .expect("can create staged join from welcome");

            sender_groups.push(RefCell::new(
                staged_join
                    .into_group(&agent.provider)
                    .expect("can create group from staged join"),
            ));
        }

        // we have the senders and sender groups; that's finally enough to generate as many messages as we need
        // We cycle through each sender in turn, because we don't want to depend on accidental optimization
        // using the same sender over and over

        let mut crc_hasher = crc32fast::Hasher::new();
        let mut messages = Vec::with_capacity(n_messages);
        let mut rng = rand::rng();

        // we have to iterate immutably over `sender_groups`, because otherwise we can't `.cycle`, but that means
        // we need this whole RefCell thing to prove that any given group is only mutable in one place at a time
        for (agent, group) in senders.iter().zip(sender_groups.iter()).cycle().take(n_messages) {
            let group = &mut *group.borrow_mut();
            let plaintext = plaintext_generator.generate_plaintext(&mut rng);
            crc_hasher.update(&plaintext);
            let ciphertext = group
                .create_message(&agent.provider, &agent.signature_keys, &plaintext)
                .expect("can encrypt an application message")
                .to_bytes()
                .expect("can encode an application message as bytes");
            messages.push(ciphertext);
        }

        (
            Case {
                recipient,
                group,
                messages,
            },
            crc_hasher.finalize(),
        )
    }
}

pub struct Case {
    recipient: Agent,
    group: MlsGroup,
    messages: Vec<Vec<u8>>,
}

impl BenchmarkCase for Case {
    fn decrypt_all(mut self) -> u32 {
        let mut crc_hasher = crc32fast::Hasher::new();

        for message in self.messages {
            let message = MlsMessageIn::tls_deserialize(&mut message.as_slice()).expect("message was MessageIn type");
            let MlsMessageBodyIn::PrivateMessage(message) = message.extract() else {
                panic!("message was not PrivateMessage");
            };
            let message = self
                .group
                .process_message(&self.recipient.provider, message)
                .expect("can process private message");
            let ProcessedMessageContent::ApplicationMessage(message) = message.into_content() else {
                panic!("message was somehow not an application message");
            };
            let plaintext = message.into_bytes();

            crc_hasher.update(&plaintext);
        }

        crc_hasher.finalize()
    }
}
