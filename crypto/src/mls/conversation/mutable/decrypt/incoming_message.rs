use openmls::prelude::{ContentType, MlsMessageIn, MlsMessageInBody};
use tls_codec::Deserialize as _;

use super::{Error, Result};
use crate::{
    TlsCodecError,
    mls::conversation::mutable::tnt::{TntMessage, TntWireFormat},
};

/// An incoming message, parsed into an appropriate container.
//
// We choose to accept the size difference here--approx. 300 bytes--on the basis that
// memory isn't particularly constrained for this application, and this struct is
// short-lived.
#[expect(clippy::large_enum_variant)]
#[derive(Clone, derive_more::From)]
pub(in crate::mls::conversation) enum ParsedMessage {
    Mls(MlsMessageIn),
    Tnt(TntMessage),
}

impl ParsedMessage {
    /// Parse some bytes into either an MLS message or a TNT message.
    fn parse(bytes: &[u8]) -> Result<Self, TlsCodecError> {
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
            _ => MlsMessageIn::tls_deserialize_exact(bytes)
                .map_err(TlsCodecError::deserialize("mls message in"))?
                .into(),
        };

        Ok(incoming_message)
    }

    /// Get the content type of this message.
    ///
    /// All TNT messages have Application content type. Public and Private MLS messages take the content type from
    /// their message bodies, and other MLS messages return an `InappropriateMessageBodyType` error.
    pub(in crate::mls::conversation) fn content_type(&self) -> Result<ContentType> {
        let content_type = match self {
            ParsedMessage::Tnt(_) => ContentType::Application,
            ParsedMessage::Mls(mls_message_in) => match mls_message_in.body_as_ref() {
                MlsMessageInBody::PublicMessage(m) => m.content_type(),
                MlsMessageInBody::PrivateMessage(m) => m.content_type(),
                _ => return Err(Error::InappropriateMessageBodyType),
            },
        };
        Ok(content_type)
    }

    /// Get the epoch of this message.
    pub(in crate::mls::conversation) fn epoch(&self) -> Result<u64> {
        match self {
            ParsedMessage::Mls(mls_message_in) => match mls_message_in.body_as_ref() {
                MlsMessageInBody::PublicMessage(public_message_in) => Ok(public_message_in.epoch().as_u64()),
                MlsMessageInBody::PrivateMessage(private_message_in) => Ok(private_message_in.epoch().as_u64()),
                _ => Err(Error::InappropriateMessageBodyType),
            },
            ParsedMessage::Tnt(tnt_message) => Ok(tnt_message.epoch()),
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
    pub(in crate::mls::conversation) fn parse(bytes: &[u8]) -> Result<Self, TlsCodecError> {
        let parsed = ParsedMessage::parse(bytes)?;
        Ok(Self {
            parsed,
            arrival_sequence: None,
        })
    }
}
