use base64::Engine;
use clap::{Parser, Subcommand};
use proteus_wasm::internal::message::SessionTag;
use proteus_wasm::internal::util::fmt_hex;
use proteus_wasm::keys::{PreKeyBundle, Signature};
use proteus_wasm::message::{CipherMessage, Envelope, Message, PreKeyMessage};
use std::ops::Deref;

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
    /// Decode a proteus prekey bundle
    PrekeyBundle { bundle: String },
    /// Decode a proteus message
    ProteusMessage {
        /// Base64 encoded proteus message
        message: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = App::parse();
    match app.command {
        Command::PrekeyBundle { bundle } => {
            let bytes = base64::prelude::BASE64_STANDARD.decode(bundle)?;
            let bundle = PreKeyBundle::deserialise(&bytes)?;
            println!("{:#?}", ProteusPreKeyBundle::from(bundle));
            Ok(())
        }
        Command::ProteusMessage { message } => {
            let bytes = base64::prelude::BASE64_STANDARD.decode(message)?;
            let message = Envelope::deserialise(&bytes)?;
            println!("{:#?}", ProteusEnvelope::from(message));
            Ok(())
        }
    }
}
