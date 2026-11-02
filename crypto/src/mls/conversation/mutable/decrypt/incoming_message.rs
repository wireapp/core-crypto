use openmls::prelude::MlsMessageIn;
use tls_codec::Deserialize as _;

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
#[derive(derive_more::From)]
pub(super) enum ParsedMessage {
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
}

/// A pair: an incoming message's parsed container, and also the bytes from which it was parsed.
pub(super) struct IncomingMessage<'a> {
    pub(super) parsed: ParsedMessage,
    // We can't really take advantage of this until we have `apply_one`: WPB-29257
    #[expect(unused)]
    pub(super) bytes: &'a [u8],
}

impl<'a> IncomingMessage<'a> {
    /// Parse some bytes into a parsed message, paired with the actual incoming bytes
    pub(super) fn parse(bytes: &'a [u8]) -> Result<Self, TlsCodecError> {
        let parsed = ParsedMessage::parse(bytes)?;
        Ok(Self { parsed, bytes })
    }
}
