use std::sync::Arc;

use core_crypto::{KeyPackageIn, RecursiveError, mls::key_package::KeypackageExt};
use tls_codec::{Deserialize as _, Serialize as _};

use crate::{Ciphersuite, CoreCryptoError, CoreCryptoResult, CredentialType, SignatureScheme};

/// A lightweight distinct reference to a `KeyPackage` sufficient to uniquely identify it
///
/// This contains some metadata to assist in sorting and filtering refs without needing to perform the
/// relatively heavy operation of converting to a full keypackage.
#[derive(Clone, derive_more::From, derive_more::Deref, uniffi::Object)]
pub struct KeypackageRef(core_crypto::KeypackageRef);

#[uniffi::export]
impl KeypackageRef {
    /// Get the bytes of the hash reference to a [`Keypackage`]
    pub fn hash_ref(&self) -> Vec<u8> {
        self.0.hash_ref().into()
    }

    /// Get the ciphersuite associated with this key package ref.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.0.ciphersuite().into()
    }

    /// Get the signature scheme associated wtih this key package ref.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.0.signature_scheme().into()
    }

    /// Get the credential type associated with this key package ref.
    pub fn credential_type(&self) -> CredentialType {
        self.0.credential_type().into()
    }

    /// Determines whether this keypackage is valid in the sense of the former `client_valid_keypackages_count` method.
    ///
    /// In practice, this just checks whether its lifetime (if present) has expired or not.
    pub fn is_valid(&self) -> bool {
        self.0.is_valid()
    }
}

impl KeypackageRef {
    pub(crate) fn coerce_arc<T: Into<Self>>(t: T) -> Arc<Self> {
        Arc::new(t.into())
    }

    pub(crate) fn as_cc(&self) -> &core_crypto::KeypackageRef {
        &self.0
    }
}

/// This inner struct hides the implementation detail that there are two OpenMLS structs conflated here.
#[derive(Clone, derive_more::From)]
enum Inner {
    Out(core_crypto::Keypackage),
    In(core_crypto::KeyPackageIn),
}

/// A signed object describing a client's identity and capabilities.
///
/// Includes a public key that can be used to encrypt to that client.
/// Other clients can use a client's KeyPackage to introduce that client to a new group.
#[derive(Clone, uniffi::Object)]
pub struct Keypackage(Inner);

impl From<Keypackage> for KeyPackageIn {
    fn from(value: Keypackage) -> Self {
        match value.0 {
            Inner::Out(key_package) => key_package.into(),
            Inner::In(key_package_in) => key_package_in,
        }
    }
}

impl Keypackage {
    /// Bundle the inner type up appropriately
    #[expect(private_bounds)]
    pub(crate) fn coerce_arc<T: Into<Inner>>(t: T) -> Arc<Keypackage> {
        std::sync::Arc::new(Keypackage(t.into()))
    }
}

#[uniffi::export]
impl Keypackage {
    /// Construct a new `Keypackage` from a byte array
    #[uniffi::constructor]
    pub fn new(bytes: &[u8]) -> CoreCryptoResult<Self> {
        KeyPackageIn::tls_deserialize_exact(bytes)
            .map(|kp_in| Self(Inner::In(kp_in)))
            .map_err(core_crypto::mls::conversation::Error::tls_deserialize("keypackagein"))
            .map_err(Into::into)
    }

    /// Serialize this to a byte vector.
    pub fn serialize(&self) -> CoreCryptoResult<Vec<u8>> {
        match &self.0 {
            Inner::Out(key_package) => key_package
                .tls_serialize_detached()
                .map_err(core_crypto::mls::conversation::Error::tls_serialize("keypackage"))
                .map_err(RecursiveError::mls_conversation("serializing keypackage"))
                .map_err(Into::into),
            Inner::In(key_package_in) => key_package_in
                .tls_serialize_detached()
                .map_err(core_crypto::mls::conversation::Error::tls_serialize("keypackage"))
                .map_err(RecursiveError::mls_conversation("serializing keypackagein"))
                .map_err(Into::into),
        }
    }

    /// Convert this to a reference
    pub fn r#ref(&self) -> CoreCryptoResult<KeypackageRef> {
        match &self.0 {
            Inner::Out(key_package) => key_package
                .make_ref()
                .map(KeypackageRef)
                .map_err(RecursiveError::mls_client("generating hashref for key package"))
                .map_err(Into::into),
            Inner::In(_) => Err(CoreCryptoError::ad_hoc(
                "only keypackages provided by CC can generate a reference",
            )),
        }
    }
}
