//! The identity in an MLS credential.
//!
//! openmls treats a credential's content as opaque bytes, so reading an identity out of it is up to us. This does
//! what the old openmls fork did, so a credential has the same identity as before.

use std::borrow::Cow;

use base64::Engine as _;
use openmls::prelude::{Credential as MlsCredential, CredentialType as MlsCredentialType, X509Credential};
use percent_encoding::percent_decode_str;
use x509_cert::{
    Certificate,
    der::Decode as _,
    ext::pkix::{SubjectAltName, name::GeneralName},
};

use super::{Error, Result};

/// The identity of a credential: a client id for a credential issued by Wire.
///
/// A basic credential's content is its identity. An X509 credential's identity is the client id in its leaf
/// certificate's subject alternative name.
pub(crate) fn credential_identity(credential: &MlsCredential) -> Result<Cow<'_, [u8]>> {
    match credential.credential_type() {
        MlsCredentialType::Basic => Ok(Cow::Borrowed(credential.serialized_content())),
        MlsCredentialType::X509 => {
            let leaf = leaf_certificate(credential)?;
            client_id_from_certificate(&leaf)
                .map(Cow::Owned)
                .ok_or(Error::InvalidIdentity)
        }
        other => Err(Error::UnsupportedCredentialType(other.into())),
    }
}

/// The leaf certificate of an X509 credential.
pub(crate) fn leaf_certificate(credential: &MlsCredential) -> Result<Certificate> {
    let credential = X509Credential::try_from(credential.clone()).map_err(Error::DecodeX509Chain)?;
    let leaf = credential.certificates().first().ok_or(Error::InvalidIdentity)?;
    Certificate::from_der(leaf.as_slice()).map_err(Error::DecodeX509)
}

/// Whether the current time is strictly between the certificate's `not_before` and `not_after`.
pub(crate) fn is_time_valid(certificate: &Certificate) -> bool {
    let validity = certificate.tbs_certificate().validity();
    let Ok(now) = web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH) else {
        return false;
    };
    now > validity.not_before.to_unix_duration() && now < validity.not_after.to_unix_duration()
}

/// The client id in the first `wireapp://` URI of the certificate's subject alternative name.
fn client_id_from_certificate(certificate: &Certificate) -> Option<Vec<u8>> {
    let (_critical, san) = certificate
        .tbs_certificate()
        .filter_extensions::<SubjectAltName>()
        .next()?
        .ok()?;
    san.0
        .iter()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
            _ => None,
        })
        .find_map(client_id_from_wire_uri)
}

/// Turn `wireapp://ZHpLZLZMROeMWp4sJlL2XA!dee090f1ed94e4c8@wire.com` into
/// `647a4b64-b64c-44e7-8c5a-9e2c2652f65c:dee090f1ed94e4c8@wire.com`.
///
/// The user id is base64 in the URI and a hyphenated UUID in the client id. The `!` may be percent-encoded, as it is
/// in end-entity certificates.
fn client_id_from_wire_uri(uri: &str) -> Option<Vec<u8>> {
    const WIRE_URI_SCHEME: &str = "wireapp://";

    let client_id = uri.strip_prefix(WIRE_URI_SCHEME)?;
    let client_id = percent_decode_str(client_id).decode_utf8().ok()?;

    let (user_id, rest) = client_id.split_once('!')?;
    let user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(user_id).ok()?;
    let user_id = uuid::Uuid::from_slice(&user_id).ok()?;

    let mut hyphenated = [0; uuid::fmt::Hyphenated::LENGTH];
    user_id.hyphenated().encode_lower(&mut hyphenated);

    Some([hyphenated.as_slice(), b":", rest.as_bytes()].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED: &[u8] = b"647a4b64-b64c-44e7-8c5a-9e2c2652f65c:dee090f1ed94e4c8@wire.com";

    #[test]
    fn wire_uri_becomes_qualified_client_id() {
        let client_id = client_id_from_wire_uri("wireapp://ZHpLZLZMROeMWp4sJlL2XA!dee090f1ed94e4c8@wire.com");
        assert_eq!(client_id.as_deref(), Some(EXPECTED));
    }

    #[test]
    fn wire_uri_is_percent_decoded_before_splitting() {
        let client_id = client_id_from_wire_uri("wireapp://ZHpLZLZMROeMWp4sJlL2XA%21dee090f1ed94e4c8@wire.com");
        assert_eq!(client_id.as_deref(), Some(EXPECTED));
    }

    #[test]
    fn uri_with_another_scheme_has_no_client_id() {
        assert_eq!(
            client_id_from_wire_uri("https://ZHpLZLZMROeMWp4sJlL2XA!dee090f1ed94e4c8@wire.com"),
            None
        );
    }

    #[test]
    fn basic_credential_identity_is_its_content() {
        let credential = openmls::prelude::BasicCredential::new(b"some client".to_vec()).into();
        assert_eq!(credential_identity(&credential).unwrap().as_ref(), b"some client");
    }
}
