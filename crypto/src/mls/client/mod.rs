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
pub(crate) mod user_id;

use crate::{
    mls::credential::{ext::CredentialExt, CredentialBundle},
    prelude::{
        identifier::ClientIdentifier, key_package::KEYPACKAGE_DEFAULT_LIFETIME, CertificateBundle, ClientId,
        CryptoError, CryptoResult, MlsCentral, MlsCiphersuite, MlsCredentialType, MlsError,
    },
};
use async_lock::RwLockReadGuard;
use core_crypto_keystore::{connection::FetchFromDatabase, Connection, CryptoKeystoreError};
use openmls::prelude::{Credential, CredentialType};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, types::SignatureScheme, OpenMlsCryptoProvider};
use std::collections::HashSet;
use tls_codec::{Deserialize, Serialize};

use core_crypto_keystore::entities::{EntityFindParams, MlsCredential, MlsSignatureKeyPair};
use identities::ClientIdentities;
use mls_crypto_provider::TransactionalCryptoProvider;
use tracing::{debug, Instrument};

impl MlsCentral {
    pub(crate) async fn mls_client(&self) -> RwLockReadGuard<'_, Option<Client>> {
        self.mls_client.read().await
    }
}

/// Represents a MLS client which in our case is the equivalent of a device.
///
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
    #[cfg_attr(not(test), tracing::instrument(err, skip(identifier, backend), fields(ciphersuites = ?ciphersuites)))]
    pub async fn init(
        identifier: ClientIdentifier,
        ciphersuites: &[MlsCiphersuite],
        backend: &TransactionalCryptoProvider,
        nb_key_package: usize,
    ) -> CryptoResult<Self> {
        let id = identifier.get_id()?;

        let credentials = backend
            .key_store()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .in_current_span()
            .await?;

        let credentials = credentials
            .into_iter()
            .filter(|c| &c.id[..] == id.as_slice())
            .try_fold(vec![], |mut acc, c| {
                let credential = Credential::tls_deserialize(&mut c.credential.as_slice()).map_err(MlsError::from)?;
                acc.push((credential, c.created_at));
                CryptoResult::Ok(acc)
            })?;

        let client = if !credentials.is_empty() {
            let signature_schemes = ciphersuites
                .iter()
                .map(|cs| cs.signature_algorithm())
                .collect::<HashSet<_>>();
            match Self::load(backend, id.as_ref(), credentials, signature_schemes).await {
                Ok(client) => client,
                Err(CryptoError::ClientSignatureNotFound) => {
                    debug!(nb_key_package, ciphersuites = ?ciphersuites, "Client signature not found. Generating client");
                    Self::generate(identifier, backend, ciphersuites, nb_key_package).await?
                }
                Err(e) => return Err(e),
            }
        } else {
            debug!(nb_key_package, ciphersuites = ?ciphersuites, "Generating client");
            Self::generate(identifier, backend, ciphersuites, nb_key_package).await?
        };

        Ok(client)
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
    #[cfg_attr(not(test), tracing::instrument(err, skip(backend), fields(ciphersuites = ?ciphersuites)))]
    pub async fn generate_raw_keypairs(
        ciphersuites: &[MlsCiphersuite],
        backend: &TransactionalCryptoProvider,
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

            let cb = Self::new_basic_credential_bundle(&tmp_client_id, cs.signature_algorithm(), backend)?;

            let sign_kp = MlsSignatureKeyPair::new(
                cs.signature_algorithm(),
                cb.signature_key.to_public_vec(),
                cb.signature_key.tls_serialize_detached().map_err(MlsError::from)?,
                tmp_client_id.clone().into(),
            );
            backend.key_store().save(sign_kp).await?;

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
        client_id: ClientId,
        tmp_ids: Vec<ClientId>,
        ciphersuites: &[MlsCiphersuite],
        backend: &TransactionalCryptoProvider,
    ) -> CryptoResult<Self> {
        // Find all the keypairs, get the ones that exist (or bail), then insert new ones + delete the provisional ones
        let stored_skp = backend
            .key_store()
            .find_all::<MlsSignatureKeyPair>(EntityFindParams::default())
            .await?;

        match stored_skp.len() {
            i if i < tmp_ids.len() => return Err(CryptoError::NoProvisionalIdentityFound),
            i if i > tmp_ids.len() => return Err(CryptoError::TooManyIdentitiesPresent),
            _ => {}
        }

        // we verify that the supplied temporary ids are all present in the keypairs we have in store
        let all_tmp_ids_exist = stored_skp
            .iter()
            .all(|kp| tmp_ids.contains(&kp.credential_id.as_slice().into()));
        if !all_tmp_ids_exist {
            return Err(CryptoError::NoProvisionalIdentityFound);
        }

        let identities = stored_skp.iter().zip(ciphersuites);

        let mut client = Self {
            id: client_id.clone(),
            identities: ClientIdentities::new(stored_skp.len()),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        };

        let id = &client_id;

        for (tmp_kp, &cs) in identities {
            let scheme = tmp_kp
                .signature_scheme
                .try_into()
                .map_err(|_| CryptoError::ImplementationError)?;
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
                .await?;

            let signature_key =
                SignatureKeyPair::tls_deserialize(&mut new_keypair.keypair.as_slice()).map_err(MlsError::from)?;
            let cb = CredentialBundle {
                credential: Credential::new_basic(new_credential.credential.clone()),
                signature_key,
                created_at: 0, // this is fine setting a default value here, this will be set in `save_identity` to the current timestamp
            };

            // And now we save the new one
            client
                .save_identity(&backend.keystore(), Some(id), cs.signature_algorithm(), cb)
                .await?;
        }

        Ok(client)
    }

    /// Generates a brand new client from scratch
    pub(crate) async fn generate(
        identifier: ClientIdentifier,
        backend: &TransactionalCryptoProvider,
        ciphersuites: &[MlsCiphersuite],
        nb_key_package: usize,
    ) -> CryptoResult<Self> {
        let id = identifier.get_id()?;
        let signature_schemes = ciphersuites
            .iter()
            .map(|cs| cs.signature_algorithm())
            .collect::<HashSet<_>>();
        let mut client = Self {
            id: id.into_owned(),
            identities: ClientIdentities::new(signature_schemes.len()),
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        };

        let identities = identifier.generate_credential_bundles(backend, signature_schemes)?;

        for (sc, id, cb) in identities {
            client.save_identity(&backend.keystore(), Some(&id), sc, cb).await?;
        }

        if nb_key_package != 0 {
            for cs in ciphersuites {
                let sc = cs.signature_algorithm();
                let identities = client.identities.as_vec().await;
                let identity = identities.iter().filter(|(id_sc, _)| id_sc == &sc);
                for (_, cb) in identity {
                    client
                        .request_key_packages(nb_key_package, *cs, cb.credential.credential_type().into(), backend)
                        .await?;
                }
            }
        }

        Ok(client)
    }

    /// Loads the client from the keystore.
    #[cfg_attr(not(test), tracing::instrument(err, skip(backend, credentials), fields(id = %id)))]
    pub(crate) async fn load(
        backend: &TransactionalCryptoProvider,
        id: &ClientId,
        mut credentials: Vec<(Credential, u64)>,
        signature_schemes: HashSet<SignatureScheme>,
    ) -> CryptoResult<Self> {
        let mut identities = ClientIdentities::new(signature_schemes.len());

        // ensures we load credentials in chronological order
        credentials.sort_by(|(_, a), (_, b)| a.cmp(b));

        let store_skps = backend
            .key_store()
            .find_all::<MlsSignatureKeyPair>(EntityFindParams::default())
            .await?;

        for sc in signature_schemes {
            let kp = store_skps.iter().find(|skp| skp.signature_scheme == (sc as u16));

            let signature_key = if let Some(kp) = kp {
                SignatureKeyPair::tls_deserialize(&mut kp.keypair.as_slice()).map_err(MlsError::from)?
            } else {
                let (sk, pk) = backend.crypto().signature_key_gen(sc).map_err(MlsError::from)?;
                let keypair = SignatureKeyPair::from_raw(sc, sk, pk.clone());
                let raw_keypair = keypair.tls_serialize_detached().map_err(MlsError::from)?;
                let store_keypair = MlsSignatureKeyPair::new(sc, pk, raw_keypair, id.as_slice().into());
                backend.key_store().save(store_keypair.clone()).await?;
                SignatureKeyPair::tls_deserialize(&mut store_keypair.keypair.as_slice()).map_err(MlsError::from)?
            };

            for (credential, created_at) in &credentials {
                match credential.mls_credential() {
                    openmls::prelude::MlsCredentialType::Basic(_) => {
                        if id.as_slice() != credential.identity() {
                            return Err(CryptoError::ImplementationError);
                        }
                    }
                    openmls::prelude::MlsCredentialType::X509(cert) => {
                        let spk = cert.extract_public_key()?.ok_or(CryptoError::InternalMlsError)?;
                        if signature_key.public() != spk {
                            return Err(CryptoError::ImplementationError);
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

        Ok(Self {
            id: id.clone(),
            identities,
            keypackage_lifetime: KEYPACKAGE_DEFAULT_LIFETIME,
        })
    }

    #[cfg_attr(not(test), tracing::instrument(err, skip(backend)))]
    async fn find_all_basic_credentials(backend: &TransactionalCryptoProvider) -> CryptoResult<Vec<Credential>> {
        let store_credentials = backend
            .key_store()
            .find_all::<MlsCredential>(EntityFindParams::default())
            .await?;
        let mut credentials = Vec::with_capacity(store_credentials.len());
        for store_credential in store_credentials.into_iter() {
            let credential =
                Credential::tls_deserialize(&mut store_credential.credential.as_slice()).map_err(MlsError::from)?;
            if !matches!(credential.credential_type(), CredentialType::Basic) {
                continue;
            }
            credentials.push(credential);
        }

        Ok(credentials)
    }

    #[cfg_attr(not(test), tracing::instrument(err, skip(self, keystore, cb), fields(id = id.as_ref().map(|id| id.to_string()))))]
    pub(crate) async fn save_identity(
        &mut self,
        keystore: &Connection,
        id: Option<&ClientId>,
        sc: SignatureScheme,
        mut cb: CredentialBundle,
    ) -> CryptoResult<CredentialBundle> {
        let id = id.unwrap_or_else(|| self.id());

        let credential = cb.credential.tls_serialize_detached().map_err(MlsError::from)?;
        let credential = MlsCredential {
            id: id.clone().into(),
            credential,
            created_at: 0,
        };

        let credential = keystore.save(credential).await?;

        let sign_kp = MlsSignatureKeyPair::new(
            sc,
            cb.signature_key.to_public_vec(),
            cb.signature_key.tls_serialize_detached().map_err(MlsError::from)?,
            id.clone().into(),
        );
        keystore.save(sign_kp).await.map_err(|e| match e {
            CryptoKeystoreError::AlreadyExists => CryptoError::CredentialBundleConflict,
            _ => e.into(),
        })?;

        // set the creation date of the signature keypair which is the same for the CredentialBundle
        cb.created_at = credential.created_at;

        self.identities.push_credential_bundle(sc, cb.clone()).await?;

        Ok(cb)
    }

    /// Retrieves the client's client id. This is free-form and not inspected.
    pub fn id(&self) -> &ClientId {
        &self.id
    }

    /// Returns whether this client is E2EI capable
    pub async fn is_e2ei_capable(&self) -> bool {
        let identities = self.identities.as_vec().await;
        identities
            .iter()
            .any(|(_, cred)| cred.credential().credential_type() == CredentialType::X509)
    }

    #[cfg_attr(not(test), tracing::instrument(err, skip(self, backend)))]
    pub(crate) async fn get_most_recent_or_create_credential_bundle(
        &mut self,
        backend: &TransactionalCryptoProvider,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> CryptoResult<CredentialBundle> {
        match ct {
            MlsCredentialType::Basic => {
                self.init_basic_credential_bundle_if_missing(backend, sc)
                    .in_current_span()
                    .await?;
                self.find_most_recent_credential_bundle(sc, ct).await
                    .ok_or(CryptoError::CredentialNotFound(ct))
            }
            MlsCredentialType::X509 => self
                .find_most_recent_credential_bundle(sc, ct).await
                .ok_or(CryptoError::E2eiEnrollmentNotDone),
        }
    }

    #[cfg_attr(not(test), tracing::instrument(err, skip(self, backend)))]
    pub(crate) async fn init_basic_credential_bundle_if_missing(
        &mut self,
        backend: &TransactionalCryptoProvider,
        sc: SignatureScheme,
    ) -> CryptoResult<()> {
        let existing_cb = self.find_most_recent_credential_bundle(sc, MlsCredentialType::Basic).await;
        if existing_cb.is_none() {
            debug!(id = %self.id(), "Initializing basic credential bundle");
            let cb = Self::new_basic_credential_bundle(self.id(), sc, backend)?;
            self.save_identity(&backend.keystore(), None, sc, cb).await?;
        }
        Ok(())
    }

    pub(crate) async fn save_new_x509_credential_bundle(
        &mut self,
        keystore: &Connection,
        sc: SignatureScheme,
        cb: CertificateBundle,
    ) -> CryptoResult<CredentialBundle> {
        let id = cb.get_client_id()?;
        let cb = Self::new_x509_credential_bundle(cb)?;
        self.save_identity(keystore, Some(&id), sc, cb).await
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
        backend: &TransactionalCryptoProvider,
        signer: Option<&crate::test_utils::x509::X509Certificate>,
        provision: bool,
    ) -> CryptoResult<Self> {
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
        Self::generate(identity, backend, &[case.ciphersuite()], nb_key_package).await
    }

    pub async fn find_keypackages(
        &self,
        backend: &TransactionalCryptoProvider,
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
mod tests {
    use core_crypto_keystore::entities::{EntityFindParams, MlsSignatureKeyPair};
    use wasm_bindgen_test::*;
    use core_crypto_keystore::connection::FetchFromDatabase;
    use crate::prelude::ClientId;
    use crate::test_utils::*;
    use mls_crypto_provider::MlsCryptoProvider;

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
                    // TODO: test with multi-ciphersuite. Tracking issue: WPB-9601
                    let handles = Client::generate_raw_keypairs(&[case.ciphersuite()], &backend)
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
                    let client_id: ClientId = b"whatever:my:client:is@world.com".to_vec().into();
                    let alice = Client::init_with_external_client_id(
                        client_id.clone(),
                        handles.clone(),
                        &[case.ciphersuite()],
                        &backend,
                    )
                    .await
                    .unwrap();

                    // Make sure both client id and PK are intact
                    assert_eq!(alice.id(), &client_id);
                    let cb = alice
                        .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type).await
                        .unwrap();
                    let client_id: ClientId = cb.credential().identity().into();
                    assert_eq!(&client_id, handles.first().unwrap());
                })
            })
            .await
        }
    }
}
