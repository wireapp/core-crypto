use crate::{CoreCryptoResult, SignatureScheme};

/// A RFC 9420 External Sender
///
/// This can be used to initialize a subconversation.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::From, derive_more::Into, uniffi::Object)]
#[uniffi::export(Eq)]
pub struct ExternalSender(pub(crate) core_crypto::ExternalSender);

#[uniffi::export]
impl ExternalSender {
    /// Serialize this external sender into a byte vector.
    ///
    /// This produces the public key and matches `parse_public_key`.
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }

    /// Parse an external sender given a JWK.
    ///
    /// This expects a raw json serialized JWK. It works with any Signature scheme.
    #[uniffi::constructor(name = "parse_jwk")]
    pub fn parse_jwk(jwk: &[u8]) -> CoreCryptoResult<Self> {
        core_crypto::ExternalSender::parse_jwk(jwk)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Parse an external sender given a raw public key.
    ///
    /// This supports the legacy behaviour where the server was providing the external sender public key
    /// raw.
    // TODO: remove at some point when the backend API is not used anymore. Tracking issue: WPB-9614
    #[uniffi::constructor(name = "parse_public_key")]
    pub fn parse_public_key(key: &[u8], signature_scheme: SignatureScheme) -> CoreCryptoResult<ExternalSender> {
        core_crypto::ExternalSender::parse_public_key(key, signature_scheme.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Parse an external sender.
    ///
    /// This first attempts to parse this as a JWK per `parse_jwk`,
    /// and falls back to `parse_public_key` if the former method fails.
    #[uniffi::constructor(name = "parse")]
    pub fn external_sender_parse(key: &[u8], signature_scheme: SignatureScheme) -> CoreCryptoResult<ExternalSender> {
        core_crypto::ExternalSender::parse(key, signature_scheme.into())
            .map(Into::into)
            .map_err(Into::into)
    }
}
