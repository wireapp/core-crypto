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

mod error;
pub(crate) mod id;
pub(crate) mod identifier;
pub(crate) mod identities;
pub(crate) mod key_package;
pub(crate) mod user_id;

use crate::{
    KeystoreError, LeafError, MlsError, RecursiveError,
    mls::credential::{CredentialBundle, ext::CredentialExt},
    prelude::{
        CertificateBundle, ClientId, MlsCiphersuite, MlsCredentialType, identifier::ClientIdentifier,
        key_package::KEYPACKAGE_DEFAULT_LIFETIME,
    },
};
pub(crate) use error::{Error, Result};

use async_lock::RwLock;
use core_crypto_keystore::{Connection, CryptoKeystoreError, connection::FetchFromDatabase};
use log::debug;
use openmls::prelude::{Credential, CredentialType};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsCryptoProvider, crypto::OpenMlsCrypto, types::SignatureScheme};
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tls_codec::{Deserialize, Serialize};

use core_crypto_keystore::entities::{EntityFindParams, MlsCredential, MlsSignatureKeyPair};
use identities::ClientIdentities;
use mls_crypto_provider::MlsCryptoProvider;

/// Represents a MLS client which in our case is the equivalent of a device.
///
/// It can be the Android, iOS, web or desktop application which the authenticated user is using.
/// A user has many client, a client has only one user.
/// A client can belong to many MLS groups
///
/// It is cheap to clone a `Client` because everything heavy is wrapped inside an [Arc].
#[derive(Clone, Debug, Default)]
pub struct Client {
    state: Arc<RwLock<Option<ClientInner>>>,
}

#[derive(Debug, Clone)]
struct ClientInner {
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
        &self,
        identifier: ClientIdentifier,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
        nb_key_package: usize,
    ) -> Result<()> {
        self.ensure_unready().await?;
        let id = identifier.get_id()?;

        let credentials = backend
            .key_store()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls credentials"))?;

        let credentials = credentials
            .into_iter()
            .filter(|mls_credential| &mls_credential.id[..] == id.as_slice())
            .map(|mls_credential| -> Result<_> {
                let credential = Credential::tls_deserialize(&mut mls_credential.credential.as_slice())
                    .map_err(Error::tls_deserialize("mls credential"))?;
                Ok((credential, mls_credential.created_at))
            })
            .collect::<Result<Vec<_>>>()?;

        if !credentials.is_empty() {
            let signature_schemes = ciphersuites
                .iter()
                .map(|cs| cs.signature_algorithm())
                .collect::<HashSet<_>>();
            match self.load(backend, id.as_ref(), credentials, signature_schemes).await {
                Ok(client) => client,
                Err(Error::ClientSignatureNotFound) => {
                    debug!(count = nb_key_package, ciphersuites:? = ciphersuites; "Client signature not found. Generating client");
                    self.generate(identifier, backend, ciphersuites, nb_key_package).await?
                }
                Err(e) => return Err(e),
            }
        } else {
            debug!(count = nb_key_package, ciphersuites:? = ciphersuites; "Generating client");
            self.generate(identifier, backend, ciphersuites, nb_key_package).await?
        };

        Ok(())
    }

    pub(crate) async fn is_ready(&self) -> bool {
        let inner_lock = self.state.read().await;
        inner_lock.is_some()
    }

    async fn ensure_unready(&self) -> Result<()> {
        if self.is_ready().await {
            Err(Error::UnexpectedlyReady)
        } else {
            Ok(())
        }
    }

    async fn replace_inner(&self, new_inner: ClientInner) {
        let mut inner_lock = self.state.write().await;
        *inner_lock = Some(new_inner);
    }

    /// Initializes a raw MLS keypair without an associated client ID
    /// Returns a random ClientId to bind later in [Client::init_with_external_client_id]
    ///
    /// # Arguments
    /// * `ciphersuites` - all ciphersuites this client is supposed to support
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// # Errors
    /// KeyStore and OpenMls errors can happen
    pub async fn generate_raw_keypairs(
        &self,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> Result<Vec<ClientId>> {
        self.ensure_unready().await?;
        const TEMP_KEY_SIZE: usize = 16;

        let credentials = Self::find_all_basic_credentials(backend).await?;
        if !credentials.is_empty() {
            return Err(Error::IdentityAlreadyPresent);
        }

        use openmls_traits::random::OpenMlsRand as _;
        // Here we generate a provisional, random, uuid-like random Client ID for no purpose other than database/store constraints
        let mut tmp_client_ids = Vec::with_capacity(ciphersuites.len());
        for cs in ciphersuites {
            let tmp_client_id: ClientId = backend
                .rand()
                .random_vec(TEMP_KEY_SIZE)
                .map_err(MlsError::wrap("generating random client id"))?
                .into();

            let cb = Self::new_basic_credential_bundle(&tmp_client_id, cs.signature_algorithm(), backend)
                .map_err(RecursiveError::mls_credential("creating new basic credential bundle"))?;

            let sign_kp = MlsSignatureKeyPair::new(
                cs.signature_algorithm(),
                cb.signature_key.to_public_vec(),
                cb.signature_key
                    .tls_serialize_detached()
                    .map_err(Error::tls_serialize("signature key"))?,
                tmp_client_id.clone().into(),
            );
            backend
                .key_store()
                .save(sign_kp)
                .await
                .map_err(KeystoreError::wrap("save signature keypair in keystore"))?;

            tmp_client_ids.push(tmp_client_id);
        }

        Ok(tmp_client_ids)
    }

    /// Finalizes initialization using a 2-step process of uploading first a public key and then associating a new Client ID to that keypair
    ///
    /// # Arguments
    /// * `client_id` - The client ID you have fetched from the MLS Authentication Service
    /// * `tmp_ids` - The temporary random client ids generated in the previous step [Client::generate_raw_keypairs]
    /// * `ciphersuites` - To initialize the Client with
    /// * `backend` - the KeyStore and crypto provider to read identities from
    ///
    /// **WARNING**: You have absolutely NO reason to call this if you didn't call [Client::generate_raw_keypairs] first. You have been warned!
    pub async fn init_with_external_client_id(
        &self,
        client_id: ClientId,
        tmp_ids: Vec<ClientId>,
        ciphersuites: &[MlsCiphersuite],
        backend: &MlsCryptoProvider,
    ) -> Result<()> {
        self.ensure_unready().await?;
        // Find all the keypairs, get the ones that exist (or bail), then insert new ones + delete the provisional ones
        let stored_skp = backend
            .key_store()
            .find_all::<MlsSignatureKeyPair>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls signature keypairs"))?;

        match stored_skp.len().cmp(&tmp_ids.len()) {
            std::cmp::Ordering::Less => return Err(Error::NoProvisionalIdentityFound),
            std::cmp::Ordering::Greater => return Err(Error::TooManyIdentitiesPresent),
            _ => {}
        }

        // we verify that the supplied temporary ids are all present in the keypairs we have in store
        let all_tmp_ids_exist = stored_skp
            .iter()
            .all(|kp| tmp_ids.contains(&kp.credential_id.as_slice().into()));
        if !all_tmp_ids_exist {
            return Err(Error::NoProvisionalIdentityFound);
        }

        let identities = stored_skp.iter().zip(ciphersuites);

        self.replace_inner(ClientInner {
            id: client_id.clone(),
            identities: ClientIdentities::new(stored_skp.len()),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
        .await;

        let id = &client_id;

        for (tmp_kp, &cs) in identities {
            let scheme = tmp_kp
                .signature_scheme
                .try_into()
                .map_err(|_| Error::InvalidSignatureScheme)?;
            let new_keypair =
                MlsSignatureKeyPair::new(scheme, tmp_kp.pk.clone(), tmp_kp.keypair.clone(), id.clone().into());

            let new_credential = MlsCredential {
                id: id.clone().into(),
                credential: tmp_kp.credential_id.clone(),
                created_at: 0,
            };

            // Delete the old identity optimistically
            backend
                .key_store()
                .remove::<MlsSignatureKeyPair, &[u8]>(&new_keypair.pk)
                .await
                .map_err(KeystoreError::wrap("removing mls signature keypair"))?;

            let signature_key = SignatureKeyPair::tls_deserialize(&mut new_keypair.keypair.as_slice())
                .map_err(Error::tls_deserialize("signature key"))?;
            let cb = CredentialBundle {
                credential: Credential::new_basic(new_credential.credential.clone()),
                signature_key,
                created_at: 0, // this is fine setting a default value here, this will be set in `save_identity` to the current timestamp
            };

            // And now we save the new one
            self.save_identity(&backend.keystore(), Some(id), cs.signature_algorithm(), cb)
                .await?;
        }

        Ok(())
    }

    /// Generates a brand new client from scratch
    pub(crate) async fn generate(
        &self,
        identifier: ClientIdentifier,
        backend: &MlsCryptoProvider,
        ciphersuites: &[MlsCiphersuite],
        nb_key_package: usize,
    ) -> Result<()> {
        self.ensure_unready().await?;
        let id = identifier.get_id()?;
        let signature_schemes = ciphersuites
            .iter()
            .map(|cs| cs.signature_algorithm())
            .collect::<HashSet<_>>();
        self.replace_inner(ClientInner {
            id: id.into_owned(),
            identities: ClientIdentities::new(signature_schemes.len()),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
        .await;

        let identities = identifier.generate_credential_bundles(backend, signature_schemes)?;

        for (sc, id, cb) in identities {
            self.save_identity(&backend.keystore(), Some(&id), sc, cb).await?;
        }

        let identities = match self.state.read().await.deref() {
            None => return Err(Error::MlsNotInitialized),
            // Cloning is fine because identities is an arc internally.
            // We can't keep the lock for longer because requesting the key packages below will also
            // acquire it.
            Some(ClientInner { identities, .. }) => identities.clone(),
        };

        if nb_key_package != 0 {
            for cs in ciphersuites {
                let sc = cs.signature_algorithm();
                let identity = identities.iter().filter(|(id_sc, _)| id_sc == &sc);
                for (_, cb) in identity {
                    self.request_key_packages(nb_key_package, *cs, cb.credential.credential_type().into(), backend)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Loads the client from the keystore.
    pub(crate) async fn load(
        &self,
        backend: &MlsCryptoProvider,
        id: &ClientId,
        mut credentials: Vec<(Credential, u64)>,
        signature_schemes: HashSet<SignatureScheme>,
    ) -> Result<()> {
        self.ensure_unready().await?;
        let mut identities = ClientIdentities::new(signature_schemes.len());

        // ensures we load credentials in chronological order
        credentials.sort_by_key(|(_, timestamp)| *timestamp);

        let store_skps = backend
            .key_store()
            .find_all::<MlsSignatureKeyPair>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls signature keypairs"))?;

        for sc in signature_schemes {
            let kp = store_skps.iter().find(|skp| skp.signature_scheme == (sc as u16));

            let signature_key = if let Some(kp) = kp {
                SignatureKeyPair::tls_deserialize(&mut kp.keypair.as_slice())
                    .map_err(Error::tls_deserialize("signature keypair"))?
            } else {
                let (sk, pk) = backend
                    .crypto()
                    .signature_key_gen(sc)
                    .map_err(MlsError::wrap("generating signature key"))?;
                let keypair = SignatureKeyPair::from_raw(sc, sk, pk.clone());
                let raw_keypair = keypair
                    .tls_serialize_detached()
                    .map_err(Error::tls_serialize("raw keypair"))?;
                let store_keypair = MlsSignatureKeyPair::new(sc, pk, raw_keypair, id.as_slice().into());
                backend
                    .key_store()
                    .save(store_keypair.clone())
                    .await
                    .map_err(KeystoreError::wrap("storing keypairs in keystore"))?;
                SignatureKeyPair::tls_deserialize(&mut store_keypair.keypair.as_slice())
                    .map_err(Error::tls_deserialize("signature keypair"))?
            };

            for (credential, created_at) in &credentials {
                match credential.mls_credential() {
                    openmls::prelude::MlsCredentialType::Basic(_) => {
                        if id.as_slice() != credential.identity() {
                            return Err(Error::WrongCredential);
                        }
                    }
                    openmls::prelude::MlsCredentialType::X509(cert) => {
                        let spk = cert
                            .extract_public_key()
                            .map_err(RecursiveError::mls_credential("extracting public key"))?
                            .ok_or(LeafError::InternalMlsError)?;
                        if signature_key.public() != spk {
                            return Err(Error::WrongCredential);
                        }
                    }
                };
                let cb = CredentialBundle {
                    credential: credential.clone(),
                    signature_key: signature_key.clone(),
                    created_at: *created_at,
                };
                identities.push_credential_bundle(sc, cb).await?;
            }
        }
        self.replace_inner(ClientInner {
            id: id.clone(),
            identities,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
        .await;
        Ok(())
    }

    async fn find_all_basic_credentials(backend: &MlsCryptoProvider) -> Result<Vec<Credential>> {
        let store_credentials = backend
            .key_store()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls credentialss"))?;
        let mut credentials = Vec::with_capacity(store_credentials.len());
        for store_credential in store_credentials.into_iter() {
            let credential = Credential::tls_deserialize(&mut store_credential.credential.as_slice())
                .map_err(Error::tls_deserialize("credential"))?;
            if !matches!(credential.credential_type(), CredentialType::Basic) {
                continue;
            }
            credentials.push(credential);
        }

        Ok(credentials)
    }

    pub(crate) async fn save_identity(
        &self,
        keystore: &Connection,
        id: Option<&ClientId>,
        sc: SignatureScheme,
        mut cb: CredentialBundle,
    ) -> Result<CredentialBundle> {
        match self.state.write().await.deref_mut() {
            None => Err(Error::MlsNotInitialized),
            Some(ClientInner {
                id: existing_id,
                identities,
                ..
            }) => {
                let id = id.unwrap_or(existing_id);

                let credential = cb
                    .credential
                    .tls_serialize_detached()
                    .map_err(Error::tls_serialize("credential bundle"))?;
                let credential = MlsCredential {
                    id: id.clone().into(),
                    credential,
                    created_at: 0,
                };

                let credential = keystore
                    .save(credential)
                    .await
                    .map_err(KeystoreError::wrap("saving credential"))?;

                let sign_kp = MlsSignatureKeyPair::new(
                    sc,
                    cb.signature_key.to_public_vec(),
                    cb.signature_key
                        .tls_serialize_detached()
                        .map_err(Error::tls_serialize("signature keypair"))?,
                    id.clone().into(),
                );
                keystore.save(sign_kp).await.map_err(|e| match e {
                    CryptoKeystoreError::AlreadyExists => Error::CredentialBundleConflict,
                    _ => KeystoreError::wrap("saving mls signature key pair")(e).into(),
                })?;

                // set the creation date of the signature keypair which is the same for the CredentialBundle
                cb.created_at = credential.created_at;

                identities.push_credential_bundle(sc, cb.clone()).await?;

                Ok(cb)
            }
        }
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub async fn id(&self) -> Result<ClientId> {
        match self.state.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(ClientInner { id, .. }) => Ok(id.clone()),
        }
    }

    /// Returns whether this client is E2EI capable
    pub async fn is_e2ei_capable(&self) -> bool {
        match self.state.read().await.deref() {
            None => false,
            Some(ClientInner { identities, .. }) => identities
                .iter()
                .any(|(_, cred)| cred.credential().credential_type() == CredentialType::X509),
        }
    }

    pub(crate) async fn get_most_recent_or_create_credential_bundle(
        &self,
        backend: &MlsCryptoProvider,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Result<Arc<CredentialBundle>> {
        match ct {
            MlsCredentialType::Basic => {
                self.init_basic_credential_bundle_if_missing(backend, sc).await?;
                self.find_most_recent_credential_bundle(sc, ct).await
            }
            MlsCredentialType::X509 => self
                .find_most_recent_credential_bundle(sc, ct)
                .await
                .map_err(|e| match e {
                    Error::CredentialNotFound(_) => LeafError::E2eiEnrollmentNotDone.into(),
                    _ => e,
                }),
        }
    }

    pub(crate) async fn init_basic_credential_bundle_if_missing(
        &self,
        backend: &MlsCryptoProvider,
        sc: SignatureScheme,
    ) -> Result<()> {
        let existing_cb = self
            .find_most_recent_credential_bundle(sc, MlsCredentialType::Basic)
            .await;
        if matches!(existing_cb, Err(Error::CredentialNotFound(_))) {
            let id = self.id().await?;
            debug!(id:% = &id; "Initializing basic credential bundle");
            let cb = Self::new_basic_credential_bundle(&id, sc, backend)
                .map_err(RecursiveError::mls_credential("creating new basic credential bundle"))?;
            self.save_identity(&backend.keystore(), None, sc, cb).await?;
        }
        Ok(())
    }

    pub(crate) async fn save_new_x509_credential_bundle(
        &self,
        keystore: &Connection,
        sc: SignatureScheme,
        cb: CertificateBundle,
    ) -> Result<CredentialBundle> {
        let id = cb
            .get_client_id()
            .map_err(RecursiveError::mls_credential("getting client id"))?;
        let cb = Self::new_x509_credential_bundle(cb)
            .map_err(RecursiveError::mls_credential("creating new x509 credential bundle"))?;
        self.save_identity(keystore, Some(&id), sc, cb).await
    }
}

#[cfg(test)]
impl Client {
    // test functions are not held to the same documentation standard as proper functions
    #![allow(missing_docs)]

    pub async fn random_generate(
        case: &crate::test_utils::TestCase,
        backend: &MlsCryptoProvider,
        signer: Option<&crate::test_utils::x509::X509Certificate>,
        provision: bool,
    ) -> Result<Self> {
        let user_uuid = uuid::Uuid::new_v4();
        let rnd_id = rand::random::<usize>();
        let client_id = format!("{}:{rnd_id:x}@members.wire.com", user_uuid.hyphenated());
        let identity = match case.credential_type {
            MlsCredentialType::Basic => ClientIdentifier::Basic(client_id.as_str().into()),
            MlsCredentialType::X509 => {
                let signer = signer.expect("Missing intermediate CA");
                CertificateBundle::rand_identifier(&client_id, &[signer])
            }
        };
        let nb_key_package = if provision {
            crate::prelude::INITIAL_KEYING_MATERIAL_COUNT
        } else {
            0
        };
        let client = Self::default();
        client
            .generate(identity, backend, &[case.ciphersuite()], nb_key_package)
            .await?;
        Ok(client)
    }

    pub async fn find_keypackages(&self, backend: &MlsCryptoProvider) -> Result<Vec<openmls::prelude::KeyPackage>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let kps = backend
            .key_store()
            .mls_fetch_keypackages::<openmls::prelude::KeyPackage>(u32::MAX)
            .await
            .map_err(KeystoreError::wrap("fetching mls keypackages"))?;
        Ok(kps)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::ClientId;
    use crate::test_utils::*;
    use core_crypto_keystore::connection::FetchFromDatabase;
    use core_crypto_keystore::entities::{EntityFindParams, MlsSignatureKeyPair};
    use mls_crypto_provider::MlsCryptoProvider;
    use wasm_bindgen_test::*;

    use super::Client;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_generate_client(case: TestCase) {
        let backend = MlsCryptoProvider::try_new_in_memory("test").await.unwrap();
        let x509_test_chain = if case.is_x509() {
            let x509_test_chain = crate::test_utils::x509::X509TestChain::init_empty(case.signature_scheme());
            x509_test_chain.register_with_provider(&backend).await;
            Some(x509_test_chain)
        } else {
            None
        };
        backend.new_transaction().await.unwrap();
        let _ = Client::random_generate(
            &case,
            &backend,
            x509_test_chain.as_ref().map(|chain| chain.find_local_intermediate_ca()),
            false,
        )
        .await
        .unwrap();
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_externally_generate_client(case: TestCase) {
        if case.is_basic() {
            run_tests(move |[tmp_dir_argument]| {
                Box::pin(async move {
                    let backend = MlsCryptoProvider::try_new(tmp_dir_argument, "test").await.unwrap();
                    backend.new_transaction().await.unwrap();
                    // phase 1: generate standalone keypair
                    let client_id: ClientId = b"whatever:my:client:is@world.com".to_vec().into();
                    let alice = Client::default();
                    // TODO: test with multi-ciphersuite. Tracking issue: WPB-9601
                    let handles = alice
                        .generate_raw_keypairs(&[case.ciphersuite()], &backend)
                        .await
                        .unwrap();

                    let mut identities = backend
                        .keystore()
                        .find_all::<MlsSignatureKeyPair>(EntityFindParams::default())
                        .await
                        .unwrap();

                    assert_eq!(identities.len(), 1);

                    let prov_identity = identities.pop().unwrap();

                    // Make sure we are actually returning the clientId
                    // TODO: test with multi-ciphersuite. Tracking issue: WPB-9601
                    let prov_client_id: ClientId = prov_identity.credential_id.as_slice().into();
                    assert_eq!(&prov_client_id, handles.first().unwrap());

                    // phase 2: pretend we have a new client ID from the backend, and try to init the client this way
                    alice
                        .init_with_external_client_id(
                            client_id.clone(),
                            handles.clone(),
                            &[case.ciphersuite()],
                            &backend,
                        )
                        .await
                        .unwrap();

                    // Make sure both client id and PK are intact
                    assert_eq!(alice.id().await.unwrap(), client_id);
                    let cb = alice
                        .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
                        .await
                        .unwrap();
                    let client_id: ClientId = cb.credential().identity().into();
                    assert_eq!(&client_id, handles.first().unwrap());
                })
            })
            .await
        }
    }
}
