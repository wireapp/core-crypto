use std::sync::Arc;

use core_crypto::{KeyPackageIn, RecursiveError, mls::key_package::KeyPackageExt};
use tls_codec::{Deserialize as _, Serialize as _};

use crate::{CoreCryptoError, CoreCryptoResult, bytes_wrapper::bytes_wrapper};

bytes_wrapper!(
    /// A lightweight distinct reference to a `KeyPackage` sufficient to uniquely identify it
    KeypackageRef
);

impl KeypackageRef {
    pub(crate) fn from_cc(kp_ref: &core_crypto::KeyPackageRef) -> KeypackageRefMaybeArc {
        keypackage_ref_coerce_maybe_arc(kp_ref.as_slice())
    }
}

/// This inner struct hides the implementation detail that there are two OpenMLS structs conflated here.
#[derive(Clone, derive_more::From)]
enum Inner {
    Out(core_crypto::KeyPackage),
    In(core_crypto::KeyPackageIn),
}

/// A signed object describing a client's identity and capabilities.
///
/// Includes a public key that can be used to encrypt to that client.
/// Other clients can use a client's KeyPackage to introduce that client to a new group.
#[derive(Clone, uniffi::Object)]
pub struct Keypackage(Inner);

pub(crate) type KeypackageMaybeArc = std::sync::Arc<Keypackage>;

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
                .map(|kp_ref| kp_ref.as_slice().to_owned().into())
                .map_err(RecursiveError::mls_client("generating hashref for key package"))
                .map_err(Into::into),
            Inner::In(_) => Err(CoreCryptoError::ad_hoc(
                "only keypackages provided by CC can generate a reference",
            )),
        }
    }
}
