// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

pub(crate) mod id;
pub(crate) mod identifier;
pub(crate) mod key_package;

use openmls::credentials::CredentialBundle;
use openmls_traits::{
    key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue},
    OpenMlsCryptoProvider,
};

use crate::{
    mls::credential::CredentialExt,
    prelude::{
        identifier::ClientIdentifier,
        key_package::{INITIAL_KEYING_MATERIAL_COUNT, KEYPACKAGE_DEFAULT_LIFETIME},
        ClientId, CryptoError, CryptoResult, MlsCiphersuite, MlsError,
    },
};
use core_crypto_keystore::entities::{EntityFindParams, MlsIdentity};
use mls_crypto_provider::MlsCryptoProvider;

/// Represents a MLS client which in our case is the equivalent of a device.
/// It can be the Android, iOS, web or desktop application which the authenticated user is using.
/// A user has many client, a client has only one user.
/// A client can belong to many MLS groups
#[derive(Debug, Clone)]
pub struct Client {
    id: ClientId,
    credentials: CredentialBundle,
    ciphersuite: MlsCiphersuite,
    keypackage_lifetime: std::time::Duration,
}

impl Client {
    /// Initializes the client.
    /// If the client's cryptographic material is already stored in the keystore, it loads it
    /// Otherwise, it is being created.
    ///
    /// # Arguments
    /// * `identifier` - client identifier ; either a [ClientId] or a x509 certificate chain
    /// * `ciphersuites` - all ciphersuites this client is supposed to support
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors can happen
    pub async fn init(
        identifier: ClientIdentifier,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        use core_crypto_keystore::CryptoKeystoreMls as _;

        let id = identifier.get_id()?;
        let client = if let Some(signature) = backend.key_store().mls_load_identity_signature(&id.to_string()).await? {
            match Self::load(id.as_ref(), &signature, ciphersuites, backend).await {
                Ok(client) => client,
                Err(CryptoError::ClientSignatureNotFound) => {
                    Self::generate(identifier, backend, ciphersuites, true).await?
                }
                Err(e) => return Err(e),
            }
        } else {
            Self::generate(identifier, backend, ciphersuites, true).await?
        };

        Ok(client)
    }

    /// Initializes a raw MLS keypair without an associated client ID
    /// Returns the raw bytes of the public key
    ///
    /// # Arguments
    /// * `ciphersuites` - all ciphersuites this client is supposed to support
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors can happen
    pub async fn generate_raw_keypair(
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<u8>> {
        let identity_count = backend.key_store().count::<MlsIdentity>().await?;
        if identity_count > 0 {
            return Err(CryptoError::IdentityAlreadyPresent);
        }

        use openmls_traits::random::OpenMlsRand as _;
        // Here we generate a provisional, random, uuid-like random Client ID for no purpose other than database/store constraints
        let provisional_client_id = backend.rand().random_vec(16)?.into();

        // TODO: support many ciphersuites
        let ciphersuite = *ciphersuites.first().ok_or(CryptoError::ImplementationError)?;
        let credentials = Self::generate_basic_credential_bundle(&provisional_client_id, ciphersuite, backend)?;

        let signature = credentials.keystore_key()?;

        let identity = MlsIdentity {
            id: provisional_client_id.to_string(),
            signature: signature.clone(),
            credential: credentials.to_key_store_value().map_err(MlsError::from)?,
        };

        backend.key_store().save(identity).await?;

        Ok(signature)
    }

    /// Finalizes initialization using a 2-step process of uploading first a public key and then associating a new Client ID to that keypair
    ///
    /// # Arguments
    /// * `client_id` - The client ID you have fetched from the MLS Authentication Service
    /// * `signature_public_key` - The client's public key. We need it to make sure
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// **WARNING**: You have absolutely NO reason to call this if you didn't call [Client::generate_raw_keypair] first. You have been warned!
    pub async fn init_with_external_client_id(
        client_id: ClientId,
        signature_public_key: &[u8],
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        // TODO: support many ciphersuites
        let ciphersuite = *ciphersuites.first().ok_or(CryptoError::ImplementationError)?;

        let keystore = backend.key_store();

        // Find all the identities, get the only one that exists (or bail), then insert the new one + delete the provisional one
        let mut store_identities: Vec<MlsIdentity> = keystore.find_all(EntityFindParams::default()).await?;

        if store_identities.len() > 1 {
            return Err(CryptoError::TooManyIdentitiesPresent);
        }

        let Some(provisional_identity) = store_identities.pop() else {
            return Err(CryptoError::NoProvisionalIdentityFound);
        };

        if signature_public_key != provisional_identity.signature {
            return Err(CryptoError::ClientSignatureMismatch);
        }

        // Now we restore the provisional credential from the store
        let provisional_credentials: CredentialBundle =
            CredentialBundle::from_key_store_value(&provisional_identity.credential).map_err(MlsError::from)?;

        // Extract what's interesting from it
        let (cred, sk) = provisional_credentials.into_parts();
        let pk = cred.signature_key().as_slice();
        let keypair =
            openmls::ciphersuite::signature::SignatureKeypair::from_bytes(sk.signature_scheme, sk.value, pk.to_vec());

        // Then rebuild a proper credential with the new client ID
        let credentials = CredentialBundle::from_parts(client_id.0.clone(), keypair);

        // Delete the old identity optimistically
        keystore
            .delete::<CredentialBundle>(provisional_identity.id.as_bytes())
            .await?;

        // And now we save the new one
        keystore
            .save(MlsIdentity {
                id: client_id.to_string(),
                signature: credentials.keystore_key()?,
                credential: credentials.to_key_store_value().map_err(MlsError::from)?,
            })
            .await?;

        Ok(Self {
            id: client_id,
            credentials,
            ciphersuite,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
    }

    /// Generates a brand new client from scratch
    pub(crate) async fn generate(
        identifier: ClientIdentifier,
        backend: &MlsCryptoProvider,
        ciphersuites: &[MlsCiphersuite],
        provision: bool,
    ) -> CryptoResult<Self> {
        // TODO: support many ciphersuites
        let ciphersuite = *ciphersuites.first().ok_or(CryptoError::ImplementationError)?;

        let (id, credentials) = match identifier {
            ClientIdentifier::Basic(id) => {
                let cred = Self::generate_basic_credential_bundle(&id, ciphersuite, backend)?;
                (id, cred)
            }
            ClientIdentifier::X509(cert) => (cert.get_client_id()?, Self::generate_x509_credential_bundle(cert)?),
        };

        let identity = MlsIdentity {
            id: id.to_string(),
            signature: credentials.keystore_key()?,
            credential: credentials.to_key_store_value().map_err(MlsError::from)?,
        };

        backend.key_store().save(identity).await?;

        let client = Self {
            id,
            credentials,
            ciphersuite,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        };

        if provision {
            client
                .request_keying_material(INITIAL_KEYING_MATERIAL_COUNT, backend)
                .await?;
        }

        Ok(client)
    }

    /// Loads the client from the keystore.
    pub(crate) async fn load(
        id: &ClientId,
        signature_public_key: &[u8],
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        // TODO: support many ciphersuites
        let ciphersuite = *ciphersuites.first().ok_or(CryptoError::ImplementationError)?;

        let identity: MlsIdentity = backend
            .key_store()
            .find(id.to_string())
            .await?
            .ok_or(CryptoError::ClientSignatureNotFound)?;

        if signature_public_key != identity.signature {
            return Err(CryptoError::ClientSignatureMismatch);
        }

        let credentials: CredentialBundle =
            CredentialBundle::from_key_store_value(&identity.credential).map_err(MlsError::from)?;

        Ok(Self {
            id: identity.id.as_bytes().into(),
            credentials,
            ciphersuite,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
    }

    #[allow(dead_code)]
    pub(crate) async fn load_credential_bundle(
        &self,
        signature_public_key: &[u8],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<CredentialBundle> {
        let credentials: CredentialBundle = backend
            .key_store()
            .read(signature_public_key)
            .await
            .ok_or(CryptoError::ClientSignatureNotFound)?;
        Ok(credentials)
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub fn id(&self) -> &ClientId {
        &self.id
    }

    /// Returns the client's public signature key from its [openmls::credentials::Credential]
    pub fn public_key(&self) -> &[u8] {
        self.credentials.credential().signature_key().as_slice()
    }

    /// Returns the client's [`CredentialBundle`] ([openmls::credentials::Credential] + private signature key)
    pub fn credentials(&self) -> &CredentialBundle {
        &self.credentials
    }
}

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Client {}

#[cfg(test)]
impl Client {
    pub async fn random_generate(
        case: &crate::test_utils::TestCase,
        backend: &MlsCryptoProvider,
        provision: bool,
    ) -> CryptoResult<Self> {
        let user_uuid = uuid::Uuid::new_v4();
        let rnd_id = rand::random::<usize>();
        let client_id: ClientId = format!("{}:{rnd_id:x}@members.wire.com", user_uuid.hyphenated())
            .as_bytes()
            .into();
        let identity = match case.credential_type {
            openmls::credentials::CredentialType::Basic => ClientIdentifier::Basic(client_id),
            openmls::credentials::CredentialType::X509 => {
                ClientIdentifier::X509(crate::prelude::CertificateBundle::rand(case.ciphersuite(), client_id))
            }
        };
        Self::generate(identity, backend, &[case.ciphersuite()], provision).await
    }

    pub async fn keypackages(&self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<openmls::prelude::KeyPackage>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let kps = backend
            .key_store()
            .mls_fetch_keypackage_bundles(u32::MAX)
            .await?
            .into_iter()
            .try_fold(
                vec![],
                |mut acc, kpb: openmls::prelude::KeyPackageBundle| -> CryptoResult<_> {
                    acc.push(kpb.key_package().clone());
                    Ok(acc)
                },
            )?;

        Ok(kps)
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{mls::credential::CredentialExt, test_utils::*};
    use mls_crypto_provider::MlsCryptoProvider;

    use super::Client;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_generate_client(case: TestCase) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        assert!(Client::random_generate(&case, &backend, false).await.is_ok());
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_externally_generate_client(case: TestCase) {
        run_tests(move |[tmp_dir_argument]| {
            Box::pin(async move {
                let backend = MlsCryptoProvider::try_new(tmp_dir_argument, "test").await.unwrap();
                // phase 1: generate standalone keypair
                let keypair_sig_pk = Client::generate_raw_keypair(&[case.ciphersuite()], &backend)
                    .await
                    .unwrap();

                let mut identities: Vec<core_crypto_keystore::entities::MlsIdentity> = backend
                    .borrow_keystore()
                    .find_all(core_crypto_keystore::entities::EntityFindParams::default())
                    .await
                    .unwrap();

                assert_eq!(identities.len(), 1);

                let prov_identity = identities.pop().unwrap();

                // Make sure we are actually returning the signature public key
                assert_eq!(prov_identity.signature, keypair_sig_pk);

                // phase 2: pretend we have a new client ID from the backend, and try to init the client this way
                let client_id: super::ClientId = b"whatever:my:client:is@wire.com".to_vec().into();
                let alice = Client::init_with_external_client_id(
                    client_id.clone(),
                    &keypair_sig_pk,
                    &[case.ciphersuite()],
                    &backend,
                )
                .await
                .unwrap();

                // Make sure both client id and PK are intact
                assert_eq!(alice.id, client_id);
                let credentials = alice.credentials();
                assert_eq!(credentials.keystore_key().unwrap(), keypair_sig_pk.as_slice());
            })
        })
        .await
    }
}
