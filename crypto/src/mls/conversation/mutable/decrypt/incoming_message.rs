use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
use tls_codec::Deserialize as _;

use super::Result;
use crate::{
    RejectionReason, TlsCodecError,
    mls::conversation::mutable::tnt::{TntMessage, TntWireFormat},
};

/// An incoming message, parsed into an appropriate container.
#[derive(Clone, derive_more::From)]
pub(in crate::mls::conversation) enum ParsedMessage {
    Mls(ProtocolMessage),
    Tnt(TntMessage),
}

impl ParsedMessage {
    /// Parse some bytes into either an MLS message or a TNT message.
    fn parse(bytes: &[u8]) -> Result<Self, RejectionReason> {
        // Bytes 0 and 1 are the protocol version, bytes 2 and 3 are the wire format.
        let wire_format_bytes = bytes.get(2..=3).ok_or(TlsCodecError::deserialize("u16 (wire format)")(
            tls_codec::Error::EndOfStream,
        ))?;
        let wire_format =
            u16::tls_deserialize_exact(wire_format_bytes).map_err(TlsCodecError::deserialize("u16 (wire format)"))?;

        let incoming_message = match wire_format {
            TntWireFormat::MIN..=TntWireFormat::MAX => TntMessage::tls_deserialize_exact(bytes)
                .map_err(TlsCodecError::deserialize("TntMessage"))?
                .into(),
            _ => match MlsMessageIn::tls_deserialize_exact(bytes)
                .map_err(TlsCodecError::deserialize("mls message in"))?
                .extract()
            {
                MlsMessageBodyIn::PublicMessage(public_message_in) => ProtocolMessage::from(public_message_in),
                MlsMessageBodyIn::PrivateMessage(private_message_in) => private_message_in.into(),
                _ => return Err(RejectionReason::InappropriateMessageBodyType),
            }
            .into(),
        };

        Ok(incoming_message)
    }

    /// Get the content type of this message.
    pub(in crate::mls::conversation) fn content_type(&self) -> ContentType {
        match self {
            ParsedMessage::Tnt(_) => ContentType::Application,
            ParsedMessage::Mls(ProtocolMessage::PrivateMessage(m)) => m.content_type(),
            ParsedMessage::Mls(ProtocolMessage::PublicMessage(m)) => m.content_type(),
        }
    }

    /// Get the epoch of this message.
    pub(in crate::mls::conversation) fn epoch(&self) -> u64 {
        match self {
            ParsedMessage::Tnt(tnt_message) => tnt_message.epoch(),
            ParsedMessage::Mls(ProtocolMessage::PrivateMessage(m)) => m.epoch().as_u64(),
            ParsedMessage::Mls(ProtocolMessage::PublicMessage(m)) => m.epoch().as_u64(),
        }
    }
}

/// An incoming message's parsed container, and its original arrival sequence.
///
/// The arrival sequence gives us two pieces of information: both the actual arrival sequence
/// stored in the DB, but also its existence demonstrates that the message was in fact
/// buffered in the DB. Where the arrival sequence is `None`, this message has not been buffered;
/// it was provided by the caller.
pub(in crate::mls::conversation) struct IncomingMessage {
    pub(in crate::mls::conversation) parsed: ParsedMessage,
    /// The original arrival sequence of this message.
    ///
    /// `None` if this was freshly parsed and the arrival sequence has not yet been determined.
    ///
    /// `Some(arrival_sequence)` if this has already been buffered in the keystore; contains the original
    /// arrival sequence value.
    pub(super) arrival_sequence: Option<u64>,
}

impl IncomingMessage {
    /// Parse some bytes into a parsed message, paired with the arrival sequence.
    pub(in crate::mls::conversation) fn parse(bytes: &[u8]) -> Result<Self, RejectionReason> {
        let parsed = ParsedMessage::parse(bytes)?;
        Ok(Self {
            parsed,
            arrival_sequence: None,
        })
    }
}
