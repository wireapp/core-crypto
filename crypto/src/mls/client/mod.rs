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

use std::unimplemented;

use crate::{
    mls::credential::CredentialBundle,
    prelude::{
        identifier::ClientIdentifier,
        key_package::{INITIAL_KEYING_MATERIAL_COUNT, KEYPACKAGE_DEFAULT_LIFETIME},
        ClientId, CryptoError, CryptoResult, MlsCentral, MlsCiphersuite, MlsCredentialType, MlsError,
    },
};
use openmls::prelude::{Credential, CredentialType};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use core_crypto_keystore::{
    entities::{EntityFindParams, MlsCredential, MlsSignatureKeyPair},
    CryptoKeystoreMls,
};
use futures_util::{StreamExt as _, TryStreamExt as _};
use identities::ClientIdentities;
use mls_crypto_provider::MlsCryptoProvider;

impl MlsCentral {
    pub(crate) fn mls_client(&self) -> CryptoResult<&Client> {
        self.mls_client.as_ref().ok_or(CryptoError::MlsNotInitialized)
    }
}

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
        let id = identifier.get_id()?;

        let client = if let Some(credential) = backend.key_store().find::<MlsCredential>(id.as_slice()).await? {
            match Self::load(id.as_ref(), &credential, ciphersuites, backend).await {
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
    ) -> CryptoResult<Vec<ClientId>> {
        const TEMP_KEY_SIZE: usize = 16;

        let credentials = Self::find_all_basic_credentials(backend).await?;
        if !credentials.is_empty() {
            return Err(CryptoError::IdentityAlreadyPresent);
        }

        use openmls_traits::random::OpenMlsRand as _;
        // Here we generate a provisional, random, uuid-like random Client ID for no purpose other than database/store constraints
        let mut tmp_client_ids = Vec::with_capacity(ciphersuites.len());
        for cs in ciphersuites {
            let tmp_client_id: ClientId = backend.rand().random_vec(TEMP_KEY_SIZE)?.into();
            let cb = Self::new_basic_credential_bundle(&tmp_client_id, *cs, backend)?;

            let identity = MlsSignatureKeyPair {
                signature_scheme: cs.signature_algorithm() as u16,
                pk: cb.signature_key.to_public_vec(),
                keypair: cb.signature_key.tls_serialize_detached().map_err(MlsError::from)?,
                credential_id: tmp_client_id.clone().into(),
            };
            backend.key_store().save(identity).await?;

            tmp_client_ids.push(tmp_client_id);
        }

        Ok(tmp_client_ids)
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
        _client_id: ClientId,
        tmp_ids: Vec<ClientId>,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        // Find all the credentials, get the only one that exists (or bail), then insert the new one + delete the provisional one
        let basic_stored_credentials = Self::find_all_basic_credentials(backend).await?;

        match basic_stored_credentials.len() {
            i if i < ciphersuites.len() => return Err(CryptoError::NoProvisionalIdentityFound),
            i if i > ciphersuites.len() => return Err(CryptoError::TooManyIdentitiesPresent),
            _ => {}
        }

        // we verify that the supplied temporary ids are all present in the credentials we have in store
        let all_tmp_ids_exist = basic_stored_credentials
            .iter()
            .all(|c| tmp_ids.contains(&c.identity().into()));
        if !all_tmp_ids_exist {
            // TODO: proper error
            return Err(CryptoError::ImplementationError);
        }

        // let identities = basic_stored_credentials.iter().zip(ciphersuites);

        // let client = Self {
        //     id: client_id.clone(),
        //     identities: ClientIdentities::new(basic_stored_credentials.len()),
        //     keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        // };

        // let id = &client_id;
        // futures_util::stream::iter(identities)
        //     .map(Ok::<_, CryptoError>)
        //     .try_fold(client, |mut acc, (tmp_credential, &cs)| async move {
        //         // Now we restore the provisional credential from the store
        //         let tmp_keypair = backend
        //             .key_store()
        //             .find::<MlsSignatureKeyPair>(tmp_credential.identity())
        //             .await?
        //             .ok_or(CryptoError::ImplementationError)?;

        //         let new_keypair = MlsSignatureKeyPair {
        //             signature_scheme: tmp_keypair.signature_scheme,
        //             keypair: tmp_keypair.keypair.clone(),
        //             pk: tmp_keypair.pk.clone(),
        //             credential_id: id.clone().into(),
        //         };

        //         let new_credential = MlsCredential {
        //             id: id.clone().into(),
        //             credential: tmp_credential.identity().to_vec(),
        //         };

        //         // Delete the old identity optimistically
        //         backend
        //             .key_store()
        //             .remove::<MlsSignatureKeyPair, &[u8]>(&new_keypair.pk)
        //             .await?;
        //         backend
        //             .key_store()
        //             .remove::<MlsCredential, &[u8]>(tmp_credential.identity())
        //             .await?;

        //         let signature_key =
        //             SignatureKeyPair::tls_deserialize_bytes(&new_keypair.keypair).map_err(MlsError::from)?;
        //         let cb = CredentialBundle {
        //             credential: Credential::new_basic(new_credential.credential.clone()),
        //             signature_key,
        //         };

        //         // And now we save the new one
        //         Self::save_identity(backend, id, cs, &cb).await?;

        //         acc.identities.push_credential_bundle(cs, cb)?;
        //         Ok(acc)
        //     })
        //     .await
        unimplemented!("Rewrite needed for this method")
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
        credential: &MlsCredential,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let mls_credential = Credential::tls_deserialize_bytes(&credential.credential).map_err(MlsError::from)?;
        let mut keypairs = ClientIdentities::new(ciphersuites.len());
        for cs in ciphersuites {
            let keypair = if let Some(keypair) = backend
                .key_store()
                .mls_keypair_for_signature_scheme(&credential.id, cs.signature_algorithm())
                .await?
            {
                keypair
            } else {
                let (sk, pk) = backend
                    .crypto()
                    .signature_key_gen(cs.signature_algorithm())
                    .map_err(MlsError::from)?;
                let keypair = SignatureKeyPair::from_raw(cs.signature_algorithm(), sk, pk.clone());
                let store_keypair = MlsSignatureKeyPair {
                    signature_scheme: cs.signature_algorithm() as _,
                    keypair: keypair.tls_serialize_detached().map_err(MlsError::from)?,
                    pk,
                    credential_id: credential.id.clone(),
                };
                backend.key_store().save(store_keypair.clone()).await?;
                store_keypair
            };

            let raw_keypair = SignatureKeyPair::tls_deserialize_bytes(&keypair.keypair).map_err(MlsError::from)?;
            let cb = CredentialBundle {
                credential: mls_credential.clone(),
                signature_key: raw_keypair,
            };

            keypairs.push_credential_bundle(*cs, cb)?;
        }

        Ok(Self {
            id: id.clone(),
            identities: keypairs,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
    }

    async fn find_all_basic_credentials(backend: &MlsCryptoProvider) -> CryptoResult<Vec<Credential>> {
        let store_credentials = backend
            .key_store()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .await?;
        let mut credentials = Vec::with_capacity(store_credentials.len());
        for store_credential in store_credentials.into_iter() {
            let credential = Credential::tls_deserialize_bytes(&store_credential.credential).map_err(MlsError::from)?;
            if !matches!(credential.credential_type(), CredentialType::Basic) {
                continue;
            }
            credentials.push(credential);
        }

        Ok(credentials)
    }

    async fn save_identity(
        backend: &MlsCryptoProvider,
        id: &ClientId,
        cs: MlsCiphersuite,
        cb: &CredentialBundle,
    ) -> CryptoResult<()> {
        if backend.key_store().find::<MlsCredential>(id.0.clone()).await?.is_none() {
            backend
                .key_store()
                .save(MlsCredential {
                    id: id.clone().into(),
                    credential: cb.credential.tls_serialize_detached().map_err(MlsError::from)?,
                })
                .await?;
        }

        backend
            .key_store()
            .save(MlsSignatureKeyPair {
                signature_scheme: cs.0.signature_algorithm() as _,
                keypair: cb.signature_key.tls_serialize_detached().map_err(MlsError::from)?,
                pk: cb.signature_key.to_public_vec(),
                credential_id: id.clone().into(),
            })
            .await?;
        Ok(())
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
            let id = self.id();
            let cb = Self::new_basic_credential_bundle(id, cs, backend)?;
            backend
                .key_store()
                .save(MlsCredential {
                    id: id.clone().into(),
                    credential: cb.credential.tls_serialize_detached().map_err(MlsError::from)?,
                })
                .await?;
            backend
                .key_store()
                .save(MlsSignatureKeyPair {
                    signature_scheme: cb.signature_key.signature_scheme() as _,
                    keypair: cb.signature_key.tls_serialize_detached().map_err(MlsError::from)?,
                    pk: cb.signature_key.to_public_vec(),
                    credential_id: id.clone().into(),
                })
                .await?;

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
            .mls_fetch_keypackages::<openmls::prelude::KeyPackage>(u32::MAX)
            .await?;
        Ok(kps)
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;
    use mls_crypto_provider::MlsCryptoProvider;

    use super::Client;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_generate_client(case: TestCase) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        assert!(Client::random_generate(&case, &backend, false).await.is_ok());
    }

    // #[apply(all_cred_cipher)]
    // #[wasm_bindgen_test]
    // pub async fn can_externally_generate_client(case: TestCase) {
    //     if matches!(case.credential_type, MlsCredentialType::Basic) {
    //         run_tests(move |[tmp_dir_argument]| {
    //             Box::pin(async move {
    //                 let backend = MlsCryptoProvider::try_new(tmp_dir_argument, "test").await.unwrap();
    //                 // phase 1: generate standalone keypair
    //                 let keypair_sig_pk = Client::generate_raw_keypairs(&[case.ciphersuite()], &backend)
    //                     .await
    //                     .unwrap();

    //                 let mut identities: Vec<core_crypto_keystore::entities::MlsIdentity> = backend
    //                     .borrow_keystore()
    //                     .find_all(core_crypto_keystore::entities::EntityFindParams::default())
    //                     .await
    //                     .unwrap();

    //                 assert_eq!(identities.len(), 1);

    //                 let prov_identity = identities.pop().unwrap();

    //                 // Make sure we are actually returning the signature public key
    //                 // TODO: test with multi-ciphersuite
    //                 assert_eq!(&prov_identity.signature, keypair_sig_pk.first().unwrap());

    //                 // phase 2: pretend we have a new client ID from the backend, and try to init the client this way
    //                 let client_id: super::ClientId = b"whatever:my:client:is@wire.com".to_vec().into();
    //                 let alice = Client::init_with_external_client_id(
    //                     client_id.clone(),
    //                     keypair_sig_pk.clone(),
    //                     &[case.ciphersuite()],
    //                     &backend,
    //                 )
    //                 .await
    //                 .unwrap();

    //                 // Make sure both client id and PK are intact
    //                 assert_eq!(alice.id(), &client_id);
    //                 let credentials = alice
    //                     .find_credential_bundle(case.ciphersuite(), case.credential_type)
    //                     .unwrap();
    //                 assert_eq!(
    //                     &credentials.keystore_key().unwrap().as_slice(),
    //                     keypair_sig_pk.first().unwrap()
    //                 );
    //             })
    //         })
    //         .await
    //     }
    // }
}
