use openmls::{
    extensions::ExternalSender as MlsExternalSender,
    prelude::{Credential as MlsCredential, OpenMlsCrypto as _, OpenMlsSignaturePublicKey, SignatureScheme},
};
use wire_e2e_identity::parse_json_jwk;

use super::{Error, Result};
use crate::{MlsError, RecursiveError, mls_provider::CRYPTO};

const WIRE_SERVER_IDENTITY: &str = "wire-server";

/// A RFC 9420 External Sender
///
/// This can be used to initialize a subconversation.
#[derive(
    Debug, Clone, PartialEq, Eq, derive_more::From, derive_more::Into, derive_more::Deref, derive_more::DerefMut,
)]
pub struct ExternalSender(pub(crate) MlsExternalSender);

impl ExternalSender {
    /// Serialize this external sender into a byte vector.
    ///
    /// This produces the public key and matches [`Self::parse_public_key`].
    pub fn serialize(&self) -> Vec<u8> {
        self.0.signature_key().as_slice().to_vec()
    }

    /// Parse an external sender given a JWK.
    ///
    /// This expects a raw json serialized JWK. It works with any Signature scheme.
    pub fn parse_jwk(jwk: &[u8]) -> Result<ExternalSender> {
        let pk = parse_json_jwk(jwk)
            .map_err(wire_e2e_identity::E2eIdentityError::from)
            .map_err(RecursiveError::e2e_identity("parsing jwk"))?;
        Ok(MlsExternalSender::new(pk.into(), MlsCredential::new_basic(WIRE_SERVER_IDENTITY.into())).into())
    }

    /// Parse an external sender given a raw public key.
    ///
    /// This supports the legacy behaviour where the server was providing the external sender public key
    /// raw.
    // TODO: remove at some point when the backend API is not used anymore. Tracking issue: WPB-9614
    pub fn parse_public_key(key: &[u8], signature_scheme: SignatureScheme) -> Result<ExternalSender> {
        CRYPTO
            .validate_signature_key(signature_scheme, key)
            .map_err(MlsError::wrap("validating signature key"))?;
        let key = OpenMlsSignaturePublicKey::new(key.into(), signature_scheme)
            .map_err(MlsError::wrap("creating new signature public key"))?;
        Ok(MlsExternalSender::new(key.into(), MlsCredential::new_basic(WIRE_SERVER_IDENTITY.into())).into())
    }

    /// Parse an external sender.
    ///
    /// This first attempts to parse this as a JWK per `parse_jwk`,
    /// and falls back to `parse_public_key` if the former method fails.
    pub fn parse(key: &[u8], signature_scheme: SignatureScheme) -> Result<ExternalSender> {
        Self::parse_jwk(key).or_else(|_| Self::parse_public_key(key, signature_scheme))
    }
}

impl TryFrom<Vec<u8>> for ExternalSender {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::parse_jwk(&value)
    }
}
