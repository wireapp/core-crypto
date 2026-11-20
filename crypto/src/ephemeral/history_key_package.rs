//! The key package of a history client, with its private keys.

use obfuscate::Obfuscate;
use openmls::{
    group::LeafNodeLifetimePolicy,
    prelude::{
        KeyPackage, KeyPackageBundle, KeyPackageIn, KeyPackageVerifyError, ProtocolVersion,
        tls_codec::{self, Deserialize as _, Serialize as _},
    },
};
use openmls_traits::{OpenMlsProvider as _, storage::StorageProvider as _, types::HpkePrivateKey};
use zeroize::Zeroizing;

use crate::{
    Error, KeystoreError, OpenMlsError, Result,
    mls_provider::{CRYPTO, MlsProvider},
};

/// The key package of a history client, with its private keys.
pub(crate) struct HistoryKeyPackage(KeyPackageBundle);

impl Obfuscate for HistoryKeyPackage {
    fn obfuscate(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<secret>")
    }
}

/// Why a history client's key package couldn't be decoded.
#[derive(Debug, thiserror::Error)]
enum DecodeError {
    #[error(transparent)]
    Tls(#[from] tls_codec::Error),
    #[error("invalid key package: {0}")]
    InvalidKeyPackage(#[from] KeyPackageVerifyError),
}

impl HistoryKeyPackage {
    /// Load a key package that openmls has just stored, along with its private keys.
    pub(crate) fn load(provider: &MlsProvider<'_>, key_package: &KeyPackage) -> Result<Self> {
        let hash_ref = key_package
            .hash_ref(provider.crypto())
            .map_err(OpenMlsError::wrap("computing the key package's hash ref"))?;
        provider
            .storage()
            .key_package(&hash_ref)
            .map_err(KeystoreError::wrap("loading the history client's key package"))?
            .map(Self)
            .ok_or(Error::InvalidHistorySecret(
                "the key package we just generated is not stored",
            ))
    }

    /// Store the key package and its private keys, the way openmls stores the key packages it generates.
    pub(crate) fn store(&self, provider: &MlsProvider<'_>) -> Result<()> {
        let hash_ref = self
            .key_package()
            .hash_ref(provider.crypto())
            .map_err(OpenMlsError::wrap("computing the key package's hash ref"))?;
        provider
            .storage()
            .write_key_package(&hash_ref, &self.0)
            .map_err(KeystoreError::wrap("storing the history client's key package"))?;
        Ok(())
    }

    pub(crate) fn key_package(&self) -> &KeyPackage {
        self.0.key_package()
    }

    /// The encoding in a history secret:
    ///
    /// ```text
    /// struct {
    ///     KeyPackage key_package;
    ///     opaque init_private_key<V>;
    ///     opaque encryption_private_key<V>;
    /// } HistoryKeyPackage;
    /// ```
    fn to_tls_bytes(&self) -> Result<Zeroizing<Vec<u8>>, tls_codec::Error> {
        let mut bytes = Zeroizing::new(Vec::new());
        self.0.key_package().tls_serialize(&mut *bytes)?;
        self.0.init_private_key().tls_serialize(&mut *bytes)?;
        self.0.encryption_private_key().tls_serialize(&mut *bytes)?;
        Ok(bytes)
    }

    /// Decode what [`Self::to_tls_bytes`] encoded, and validate the key package.
    ///
    /// The lifetime isn't checked. A history secret may be restored long after its key package expired: the
    /// history client was added to its conversation back when the key package was still valid.
    fn from_tls_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (key_package, init_private_key, encryption_private_key) =
            <(KeyPackageIn, HpkePrivateKey, HpkePrivateKey)>::tls_deserialize_exact(bytes)?;
        let key_package = key_package.validate_with_lifetime_policy(
            CRYPTO.as_ref(),
            ProtocolVersion::Mls10,
            LeafNodeLifetimePolicy::Skip,
        )?;
        Ok(Self(KeyPackageBundle::new(
            key_package,
            init_private_key,
            encryption_private_key,
        )))
    }
}

/// Serde for the key package in a [`HistorySecret`](super::HistorySecret).
///
/// A history secret is sent to other clients, which may run other versions of core-crypto and may keep the secret
/// around. So its encoding mustn't depend on how openmls happens to serialize its types. The key package is
/// serialized as bytes, holding the encoding described at [`HistoryKeyPackage::to_tls_bytes`].
pub(super) mod wire {
    use serde::{
        Deserializer, Serializer,
        de::{self, Visitor},
        ser::Error as _,
    };

    use super::HistoryKeyPackage;

    pub(crate) fn serialize<S: Serializer>(key_package: &HistoryKeyPackage, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = key_package.to_tls_bytes().map_err(S::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<HistoryKeyPackage, D::Error> {
        deserializer.deserialize_bytes(HistoryKeyPackageVisitor)
    }

    struct HistoryKeyPackageVisitor;

    impl<'de> Visitor<'de> for HistoryKeyPackageVisitor {
        type Value = HistoryKeyPackage;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("the bytes of a history client's key package")
        }

        fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            HistoryKeyPackage::from_tls_bytes(bytes).map_err(E::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use rstest_reuse::apply;

    use super::*;
    use crate::{
        HistorySecret,
        test_utils::{TestContext, all_cred_cipher},
    };

    #[apply(all_cred_cipher)]
    async fn history_secret_survives_a_round_trip(case: TestContext) {
        let secret = crate::ephemeral::generate_history_secret(case.cipher_suite())
            .await
            .unwrap();
        let encoded = rmp_serde::to_vec(&secret).unwrap();
        let decoded = rmp_serde::from_slice::<HistorySecret>(&encoded).unwrap();

        assert_eq!(decoded.client_id, secret.client_id);
        assert_eq!(decoded.key_package.key_package(), secret.key_package.key_package());
        assert_eq!(
            decoded.key_package.to_tls_bytes().unwrap(),
            secret.key_package.to_tls_bytes().unwrap()
        );
    }

    #[apply(all_cred_cipher)]
    async fn trailing_bytes_are_rejected(case: TestContext) {
        let secret = crate::ephemeral::generate_history_secret(case.cipher_suite())
            .await
            .unwrap();
        let mut bytes = secret.key_package.to_tls_bytes().unwrap();
        bytes.push(0);
        assert!(matches!(
            HistoryKeyPackage::from_tls_bytes(&bytes),
            Err(DecodeError::Tls(tls_codec::Error::TrailingData))
        ));
    }
}
