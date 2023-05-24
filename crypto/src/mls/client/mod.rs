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
pub(crate) mod identities;
pub(crate) mod key_package;

use openmls::credentials::CredentialBundle;
use openmls_traits::{
    key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue},
    OpenMlsCryptoProvider,
};

use crate::{
    mls::credential::ext::CredentialExt,
    prelude::{
        identifier::ClientIdentifier,
        key_package::{INITIAL_KEYING_MATERIAL_COUNT, KEYPACKAGE_DEFAULT_LIFETIME},
        ClientId, CryptoError, CryptoResult, MlsCiphersuite, MlsCredentialType, MlsError,
    },
};
use core_crypto_keystore::entities::{EntityFindParams, MlsIdentity};
use futures_util::{StreamExt as _, TryStreamExt as _};
use identities::ClientIdentities;
use mls_crypto_provider::MlsCryptoProvider;

/// Represents a MLS client which in our case is the equivalent of a device.
/// It can be the Android, iOS, web or desktop application which the authenticated user is using.
/// A user has many client, a client has only one user.
/// A client can belong to many MLS groups
#[derive(Debug, Clone)]
pub struct Client {
    id: ClientId,
    pub(crate) identities: ClientIdentities,
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
    pub async fn generate_raw_keypairs(
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<Vec<u8>>> {
        const TEMP_KEY_SIZE: usize = 16;

        //TODO: dehydrate & optimize
        let identity_count = Self::fetch_basic_identities(backend).await?.len();
        if identity_count >= ciphersuites.len() {
            return Err(CryptoError::IdentityAlreadyPresent);
        }

        futures_util::stream::iter(ciphersuites)
            .map(Ok::<_, CryptoError>)
            .try_fold(Vec::with_capacity(ciphersuites.len()), |mut acc, &cs| async move {
                use openmls_traits::random::OpenMlsRand as _;
                // Here we generate a provisional, random, uuid-like random Client ID for no purpose other than database/store constraints
                let provisional_client_id = backend.rand().random_vec(TEMP_KEY_SIZE)?.into();

                let cb = Self::new_basic_credential_bundle(&provisional_client_id, cs, backend)?;
                let signature = cb.keystore_key()?;
                let identity = MlsIdentity {
                    id: provisional_client_id.to_string(),
                    ciphersuite: cs.into(),
                    credential_type: MlsCredentialType::Basic as u8,
                    signature: signature.clone(),
                    credential: cb.to_key_store_value().map_err(MlsError::from)?,
                };
                backend.key_store().save(identity).await?;

                acc.push(signature);

                Ok(acc)
            })
            .await
    }

    /// Finalizes initialization using a 2-step process of uploading first a public key and then associating a new Client ID to that keypair
    ///
    /// # Arguments
    /// * `client_id` - The client ID you have fetched from the MLS Authentication Service
    /// * `signature_public_key` - The client's public key. We need it to make sure
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// **WARNING**: You have absolutely NO reason to call this if you didn't call [Client::generate_raw_keypairs] first. You have been warned!
    pub async fn init_with_external_client_id(
        client_id: ClientId,
        signature_public_keys: Vec<Vec<u8>>,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        // Find all the identities, get the only one that exists (or bail), then insert the new one + delete the provisional one
        let basic_store_identities = Self::fetch_basic_identities(backend).await?;

        match basic_store_identities.len() {
            i if i < ciphersuites.len() => return Err(CryptoError::NoProvisionalIdentityFound),
            i if i > ciphersuites.len() => return Err(CryptoError::TooManyIdentitiesPresent),
            i if i != signature_public_keys.len() => return Err(CryptoError::ImplementationError),
            _ => {}
        }

        let prov_public_keys = ciphersuites.iter().zip(signature_public_keys.iter());

        let identities = basic_store_identities.iter().zip(prov_public_keys);

        let client = Self {
            id: client_id.clone(),
            identities: ClientIdentities::new(basic_store_identities.len()),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        };

        let id = &client_id;
        futures_util::stream::iter(identities)
            .map(Ok::<_, CryptoError>)
            .try_fold(client, |mut acc, (provisional_identity, (&cs, prov_pk))| async move {
                if prov_pk != &provisional_identity.signature {
                    return Err(CryptoError::ClientSignatureMismatch);
                }

                // Now we restore the provisional credential from the store
                let cb =
                    CredentialBundle::from_key_store_value(&provisional_identity.credential).map_err(MlsError::from)?;

                // Extract what's interesting from it
                let (cred, sk) = cb.into_parts();
                let pk = cred.signature_key().as_slice();
                let kp = openmls::ciphersuite::signature::SignatureKeypair::from_bytes(
                    sk.signature_scheme,
                    sk.value,
                    pk.to_vec(),
                );

                // Then rebuild a proper credential with the new client ID
                let cb = CredentialBundle::from_parts(id.0.clone(), kp);

                // Delete the old identity optimistically
                backend
                    .key_store()
                    .delete::<CredentialBundle>(provisional_identity.id.as_bytes())
                    .await?;

                // And now we save the new one
                Self::save_identity(backend, id, cs, &cb).await?;

                acc.identities.push_credential_bundle(cs, cb)?;
                Ok(acc)
            })
            .await
    }

    /// Generates a brand new client from scratch
    pub(crate) async fn generate(
        identifier: ClientIdentifier,
        backend: &MlsCryptoProvider,
        ciphersuites: &[MlsCiphersuite],
        provision: bool,
    ) -> CryptoResult<Self> {
        let id = identifier.get_id()?;
        let client = Self {
            id: id.into_owned(),
            identities: ClientIdentities::new(ciphersuites.len()),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        };

        let identities = identifier.generate_credential_bundles(backend, ciphersuites)?;
        let client = futures_util::stream::iter(identities)
            .map(Ok::<_, CryptoError>)
            .try_fold(client, |mut acc, (cs, id, cb)| async move {
                Self::save_identity(backend, &id, cs, &cb).await?;
                acc.identities.push_credential_bundle(cs, cb)?;
                Ok(acc)
            })
            .await?;

        if provision {
            use futures_util::{StreamExt as _, TryStreamExt as _};

            futures_util::stream::iter(ciphersuites)
                .map(Ok::<_, CryptoError>)
                .try_for_each(|cs| async {
                    client
                        .request_key_packages(INITIAL_KEYING_MATERIAL_COUNT, *cs, backend)
                        .await?;
                    Ok(())
                })
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
        let identities = futures_util::stream::iter(ciphersuites)
            .map(Ok::<_, CryptoError>)
            .try_fold(ClientIdentities::new(ciphersuites.len()), |mut acc, &cs| async move {
                // TODO: support many ciphersuites i.e. refactor the keystore
                let identity = backend
                    .key_store()
                    .find::<MlsIdentity>(id.to_string())
                    .await?
                    .ok_or(CryptoError::ClientSignatureNotFound)?;

                if signature_public_key != identity.signature {
                    return Err(CryptoError::ClientSignatureMismatch);
                }

                let cb = CredentialBundle::from_key_store_value(&identity.credential).map_err(MlsError::from)?;

                acc.push_credential_bundle(cs, cb)?;
                Ok(acc)
            })
            .await?;

        Ok(Self {
            id: id.clone(),
            identities,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
    }

    #[allow(dead_code)]
    pub(crate) async fn load_credential_bundle(
        &self,
        signature_public_key: &[u8],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<CredentialBundle> {
        backend
            .key_store()
            .read::<CredentialBundle>(signature_public_key)
            .await
            .ok_or(CryptoError::ClientSignatureNotFound)
    }

    async fn fetch_basic_identities(backend: &MlsCryptoProvider) -> CryptoResult<Vec<MlsIdentity>> {
        Ok(backend
            .key_store()
            .find_all::<MlsIdentity>(EntityFindParams::default())
            .await?
            .into_iter()
            .filter(|i| i.credential_type == (MlsCredentialType::Basic as u8))
            .collect::<Vec<_>>())
    }

    async fn save_identity(
        backend: &MlsCryptoProvider,
        id: &ClientId,
        cs: MlsCiphersuite,
        cb: &CredentialBundle,
    ) -> CryptoResult<()> {
        let identity = MlsIdentity {
            id: id.to_string(),
            ciphersuite: cs.into(),
            credential_type: cb.get_type() as u8,
            signature: cb.keystore_key()?,
            credential: cb.to_key_store_value().map_err(MlsError::from)?,
        };
        Ok(backend.key_store().save(identity).await.map(|_| ())?)
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub fn id(&self) -> &ClientId {
        &self.id
    }

    pub(crate) async fn get_or_create_credential_bundle(
        &mut self,
        backend: &MlsCryptoProvider,
        cs: MlsCiphersuite,
        ct: MlsCredentialType,
    ) -> CryptoResult<&CredentialBundle> {
        if let MlsCredentialType::Basic = ct {
            self.init_basic_credential_bundle_if_missing(backend, cs).await?;
        }
        self.find_credential_bundle(cs, ct)
    }

    pub(crate) async fn init_basic_credential_bundle_if_missing(
        &mut self,
        backend: &MlsCryptoProvider,
        cs: MlsCiphersuite,
    ) -> CryptoResult<()> {
        if self
            .identities
            .find_credential_bundle(cs, MlsCredentialType::Basic)
            .is_none()
        {
            let cb = Self::new_basic_credential_bundle(self.id(), cs, backend)?;
            let identity = MlsIdentity {
                id: self.id().to_string(),
                ciphersuite: cs.into(),
                credential_type: MlsCredentialType::Basic as u8,
                signature: cb.keystore_key()?,
                credential: cb.to_key_store_value().map_err(MlsError::from)?,
            };
            backend.key_store().save(identity).await?;
            self.identities.push_credential_bundle(cs, cb)?;
        }
        Ok(())
    }

    pub(crate) fn find_credential_bundle(
        &self,
        cs: MlsCiphersuite,
        ct: MlsCredentialType,
    ) -> CryptoResult<&CredentialBundle> {
        self.identities
            .find_credential_bundle(cs, ct)
            .ok_or(CryptoError::IdentityInitializationError)
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
            MlsCredentialType::Basic => ClientIdentifier::Basic(client_id),
            MlsCredentialType::X509 => {
                crate::prelude::CertificateBundle::rand_identifier(&[case.ciphersuite()], client_id)
            }
        };
        Self::generate(identity, backend, &[case.ciphersuite()], provision).await
    }

    pub async fn find_keypackages(
        &self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<openmls::prelude::KeyPackage>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let kps = backend
            .key_store()
            .mls_fetch_keypackage_bundles::<openmls::prelude::KeyPackageBundle>(u32::MAX)
            .await?
            .into_iter()
            .try_fold(vec![], |mut acc, kpb| -> CryptoResult<_> {
                acc.push(kpb.key_package().clone());
                Ok(acc)
            })?;
        Ok(kps)
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::prelude::MlsCredentialType;
    use crate::{mls::credential::ext::CredentialExt, test_utils::*};
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
        if matches!(case.credential_type, MlsCredentialType::Basic) {
            run_tests(move |[tmp_dir_argument]| {
                Box::pin(async move {
                    let backend = MlsCryptoProvider::try_new(tmp_dir_argument, "test").await.unwrap();
                    // phase 1: generate standalone keypair
                    let keypair_sig_pk = Client::generate_raw_keypairs(&[case.ciphersuite()], &backend)
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
                    // TODO: test with multi-ciphersuite
                    assert_eq!(&prov_identity.signature, keypair_sig_pk.first().unwrap());

                    // phase 2: pretend we have a new client ID from the backend, and try to init the client this way
                    let client_id: super::ClientId = b"whatever:my:client:is@wire.com".to_vec().into();
                    let alice = Client::init_with_external_client_id(
                        client_id.clone(),
                        keypair_sig_pk.clone(),
                        &[case.ciphersuite()],
                        &backend,
                    )
                    .await
                    .unwrap();

                    // Make sure both client id and PK are intact
                    assert_eq!(alice.id(), &client_id);
                    let credentials = alice
                        .find_credential_bundle(case.ciphersuite(), case.credential_type)
                        .unwrap();
                    assert_eq!(
                        &credentials.keystore_key().unwrap().as_slice(),
                        keypair_sig_pk.first().unwrap()
                    );
                })
            })
            .await
        }
    }
}
