use std::sync::Arc;

use core_crypto::{CipherSuite as CryptoCipherSuite, CredentialFindFilters};
use core_crypto_keystore::Sha256Hash;

use crate::{CipherSuite, ClientId, CoreCryptoFfi, CoreCryptoResult, CredentialRef, CredentialType};

#[uniffi::export]
impl CoreCryptoFfi {
    /// Get the public key associated with this credential
    pub async fn public_key(&self, credential_ref: Arc<CredentialRef>) -> CoreCryptoResult<Vec<u8>> {
        self.inner.public_key(&credential_ref.0).await.map_err(Into::into)
    }

    /// Get all credentials from this client.
    pub async fn get_credentials(&self) -> CoreCryptoResult<Vec<Arc<CredentialRef>>> {
        self.inner
            .get_credentials()
            .await
            .map(|credentials| credentials.into_iter().map(CredentialRef::from).map(Arc::new).collect())
            .map_err(Into::into)
    }
}

#[cfg_attr(any(feature = "wasm", feature = "napi"), uniffi::export)]
impl CoreCryptoFfi {
    /// Get all credentials from this client which match the provided parameters.
    ///
    /// Parameters which are unset or `None` match anything. Those with a particular value find only credentials
    /// matching that value.
    #[uniffi::method(default(
        client_id = None,
        public_key = None,
        cipher_suite = None,
        credential_type = None,
        earliest_validity = None,
    ))]
    pub async fn find_credentials_ffi(
        &self,
        client_id: Option<Arc<ClientId>>,
        public_key: Option<Vec<u8>>,
        cipher_suite: Option<CipherSuite>,
        credential_type: Option<CredentialType>,
        earliest_validity: Option<u64>,
    ) -> CoreCryptoResult<Vec<Arc<CredentialRef>>> {
        self.find_credentials_inner(client_id, public_key, cipher_suite, credential_type, earliest_validity)
            .await
    }
}

#[cfg_attr(not(any(feature = "wasm", feature = "napi")), uniffi::export)]
impl CoreCryptoFfi {
    /// Get all credentials from this client which match the provided parameters.
    ///
    /// Parameters which are unset or `None` match anything. Those with a particular value find only credentials
    /// matching that value.
    #[uniffi::method(default(
        client_id = None,
        public_key = None,
        cipher_suite = None,
        credential_type = None,
        earliest_validity = None,
    ))]
    pub async fn find_credentials(
        &self,
        client_id: Option<Arc<ClientId>>,
        public_key: Option<Vec<u8>>,
        cipher_suite: Option<CipherSuite>,
        credential_type: Option<CredentialType>,
        earliest_validity: Option<u64>,
    ) -> CoreCryptoResult<Vec<Arc<CredentialRef>>> {
        self.find_credentials_inner(client_id, public_key, cipher_suite, credential_type, earliest_validity)
            .await
    }
}

impl CoreCryptoFfi {
    /// Get all credentials from this client which match the provided parameters.
    ///
    /// Parameters which are unset or `None` match anything. Those with a particular value find only credentials
    /// matching that value.
    async fn find_credentials_inner(
        &self,
        client_id: Option<Arc<ClientId>>,
        public_key: Option<Vec<u8>>,
        cipher_suite: Option<CipherSuite>,
        credential_type: Option<CredentialType>,
        earliest_validity: Option<u64>,
    ) -> CoreCryptoResult<Vec<Arc<CredentialRef>>> {
        let client_id = client_id.as_ref().map(|c| c.as_ref().as_ref());

        let cipher_suite = cipher_suite.map(CryptoCipherSuite::from);

        let credential_type = credential_type.map(core_crypto::CredentialType::from);

        let find_filters = CredentialFindFilters {
            client_id,
            public_key_hash: public_key.map(Sha256Hash::hash_from),
            cipher_suite,
            credential_type,
            earliest_validity,
        };

        self.inner
            .find_credentials(find_filters)
            .await
            .map(|credentials| credentials.into_iter().map(CredentialRef::from).map(Arc::new).collect())
            .map_err(Into::into)
    }
}
