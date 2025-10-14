use std::ops::Deref;

use base64::Engine;
use clap::{Parser, Subcommand};
use clap_stdin::FileOrStdin;
use mls_rs::{
    KeyPackage, MlsMessage,
    extension::{ExtensionType, MlsExtension, built_in::RatchetTreeExt},
    group::GroupInfo,
    mls_rs_codec::MlsDecode,
};
use proteus_wasm::{
    internal::{message::SessionTag, util::fmt_hex},
    keys::{PreKeyBundle, Signature},
    message::{CipherMessage, Envelope, Message, PreKeyMessage},
};

#[derive(Debug)]
#[allow(dead_code)]
struct ProteusPreKeyBundle {
    pub version: u8,
    pub prekey_id: u16,
    pub public_key: String,
    pub identity_key: String,
    pub signature: Option<Signature>,
}

impl From<PreKeyBundle> for ProteusPreKeyBundle {
    fn from(bundle: PreKeyBundle) -> Self {
        Self {
            version: bundle.version,
            prekey_id: bundle.prekey_id.value(),
            public_key: bundle.public_key.fingerprint(),
            identity_key: bundle.identity_key.fingerprint(),
            signature: bundle.signature,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct ProteusEnvelope {
    version: u16,
    mac: String,
    message: ProteusMessage,
}

#[derive(Debug)]
#[allow(dead_code)]
enum ProteusMessage {
    Plain(ProteusCipherMessage),
    Keyed(ProteusPrekeyMessage),
}

#[derive(Debug)]
#[allow(dead_code)]
struct ProteusPrekeyMessage {
    prekey_id: u16,
    base_key: String,
    identity_key: String,
    message: ProteusCipherMessage,
}

#[derive(Debug)]
#[allow(dead_code)]
struct ProteusCipherMessage {
    pub session_tag: SessionTag,
    pub counter: u32,
    pub prev_counter: u32,
    pub ratchet_key: String,
    pub cipher_text: String,
}

impl From<Envelope<'_>> for ProteusEnvelope {
    fn from(envelope: Envelope) -> Self {
        Self {
            version: envelope.version(),
            mac: fmt_hex(&envelope.mac().clone().into_bytes()),
            message: envelope.message().into(),
        }
    }
}

impl From<&Message<'_>> for ProteusMessage {
    fn from(message: &Message) -> Self {
        match message {
            Message::Plain(plain) => ProteusMessage::Plain(plain.deref().into()),
            Message::Keyed(keyed) => ProteusMessage::Keyed(keyed.deref().into()),
        }
    }
}

impl From<&PreKeyMessage<'_>> for ProteusPrekeyMessage {
    fn from(message: &PreKeyMessage) -> Self {
        Self {
            prekey_id: message.prekey_id.value(),
            base_key: message.base_key.fingerprint(),
            identity_key: message.identity_key.fingerprint(),
            message: (&message.message).into(),
        }
    }
}

impl From<&CipherMessage<'_>> for ProteusCipherMessage {
    fn from(message: &CipherMessage) -> Self {
        Self {
            session_tag: message.session_tag,
            counter: message.counter.value(),
            prev_counter: message.prev_counter.value(),
            ratchet_key: message.ratchet_key.fingerprint(),
            cipher_text: base64::prelude::BASE64_STANDARD.encode(message.cipher_text.clone()),
        }
    }
}

/// Utility for decoding various wire formats for mls and proteus
#[derive(Parser, Debug)]
#[clap(name = "decode", version)]
pub struct App {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Decode and display a proteus prekey bundle
    PrekeyBundle { bundle: FileOrStdin<String> },
    /// Decode and display a proteus message
    ProteusMessage {
        /// File containing a base64 encoded proteus message, or `-` to read from stdin.
        message: FileOrStdin<String>,
    },
    /// MLS key package
    MlsKeypackage { package: FileOrStdin<String> },
    /// Decode and display an MLS message
    MlsMessage {
        /// File containing a base64 encoded mls message, or `-` to read from stdin.
        message: FileOrStdin<String>,
        /// Display raw mls tls decoded structure.
        #[arg(short, long)]
        raw_message: bool,
        /// Display all members if group info is provided.
        #[arg(short, long)]
        members: bool,
        /// Display decoded basic identities if group info is provided.
        #[arg(short, long)]
        identities: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = App::parse();
    match app.command {
        Command::PrekeyBundle { bundle } => {
            let input: String = bundle.contents()?;
            let bytes = base64::prelude::BASE64_STANDARD.decode(input)?;
            let bundle = PreKeyBundle::deserialise(&bytes)?;
            println!("{:#?}", ProteusPreKeyBundle::from(bundle));
            Ok(())
        }
        Command::ProteusMessage { message } => {
            let input: String = message.contents()?;
            let bytes = base64::prelude::BASE64_STANDARD.decode(input)?;
            let message = Envelope::deserialise(&bytes)?;
            println!("{:#?}", ProteusEnvelope::from(message));
            Ok(())
        }
        Command::MlsKeypackage { package } => {
            let input: String = package.contents()?;
            let bytes = base64::prelude::BASE64_STANDARD.decode(input)?;
            let key_package = KeyPackage::mls_decode(&mut bytes.as_slice())?;
            println!("{key_package:#?}");
            Ok(())
        }

        Command::MlsMessage {
            message,
            raw_message,
            members,
            identities,
        } => {
            let input: String = message.contents()?;
            let bytes = base64::prelude::BASE64_STANDARD.decode(input)?;
            let mut group_info = None;

            if let Ok(message) = MlsMessage::mls_decode(&mut bytes.as_slice()) {
                if raw_message {
                    println!("{message:#?}");
                }
                group_info = message.into_group_info();
            }

            if let Ok(gi) = GroupInfo::mls_decode(&mut bytes.as_slice()) {
                if raw_message {
                    println!("{gi:#?}");
                }
                group_info = Some(gi);
            }

            if let Some(group_info) = group_info {
                if members {
                    print_members(&group_info);
                }

                if identities {
                    print_basic_identities(&group_info);
                }
            }

            Ok(())
        }
    }
}

fn print_members(group_info: &GroupInfo) {
    group_info.extensions().iter().for_each(|ext| {
        if ext.extension_type == ExtensionType::RATCHET_TREE
            && let Some(tree) = RatchetTreeExt::from_bytes(ext.extension_data.as_slice()).ok()
        {
            tree.tree_data.roster().members().iter().for_each(|member| {
                println!("{:#?}", member);
            });
        }
    })
}

fn print_basic_identities(group_info: &GroupInfo) {
    group_info.extensions().iter().for_each(|ext| {
        if ext.extension_type == ExtensionType::RATCHET_TREE
            && let Some(tree) = RatchetTreeExt::from_bytes(ext.extension_data.as_slice()).ok()
        {
            tree.tree_data.roster().members().iter().for_each(|member| {
                if let Some(bytes) = member.signing_identity.credential.as_basic().map(|f| &f.identifier) {
                    println!(
                        "leaf index: {:#?} identity: {:#?}",
                        member.index,
                        str::from_utf8(bytes).unwrap_or("invalid utf-8")
                    );
                }
            });
        }
    });
}
