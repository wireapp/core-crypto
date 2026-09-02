use openmls::prelude::Ciphersuite;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};
use rusqlite::Connection;

use crate::{
    CryptoKeystoreError, Sha256Hash, Transaction, deser,
    entities::{
        PersistedMlsGroup, StoredCredential, StoredEncryptionKeyPair, StoredEpochEncryptionKeypair,
        StoredEpochEncryptionKeypairPkRef, StoredHpkePrivateKey, StoredKeyPackage, StoredPskBundle,
    },
    ser,
    traits::{Entity as _, EntityDatabaseMutation as _, EntityDeleteBorrowed as _, EntityGetBorrowed as _},
};

/// Implementation of the `MlsEntity::read` function; we want to share this elsewhere.
pub(crate) fn read_mls_entity<V: MlsEntity>(conn: &Connection, id: &[u8]) -> Option<V> {
    if id.is_empty() {
        return None;
    }

    match V::ID {
        MlsEntityId::GroupState => {
            let v = PersistedMlsGroup::get_borrowed(conn, id).ok().flatten()?;
            deser(&v.state).ok()
        }
        MlsEntityId::SignatureKeyPair => {
            let hash = Sha256Hash::from_existing_hash(id).ok()?;
            let stored_credential = StoredCredential::get(conn, &hash).ok().flatten()?;
            let ciphersuite = Ciphersuite::try_from(stored_credential.ciphersuite).ok()?;
            let signature_scheme = ciphersuite.signature_algorithm();

            let mls_keypair = SignatureKeyPair::from_raw(
                signature_scheme,
                stored_credential.private_key.to_vec(),
                stored_credential.public_key.to_vec(),
            );

            // In a well designed interface, something like this should not be necessary. However, we don't have
            // a well-designed interface.
            let data = ser(&mls_keypair).ok()?;
            deser(&data).ok()
        }
        MlsEntityId::KeyPackage => {
            let v = StoredKeyPackage::get_borrowed(conn, id).ok().flatten()?;
            deser(&v.key_package).ok()
        }
        MlsEntityId::HpkePrivateKey => {
            let v = StoredHpkePrivateKey::get_borrowed(conn, id).ok().flatten()?;
            deser(&v.sk).ok()
        }
        MlsEntityId::PskBundle => {
            let v = StoredPskBundle::get_borrowed(conn, id).ok().flatten()?;
            deser(&v.psk).ok()
        }
        MlsEntityId::EncryptionKeyPair => {
            let v = StoredEncryptionKeyPair::get_borrowed(conn, id).ok().flatten()?;
            deser(&v.sk).ok()
        }
        MlsEntityId::EpochEncryptionKeyPair => {
            let kp_ref = StoredEpochEncryptionKeypairPkRef::parse_bytes(id).ok()?;
            let v = StoredEpochEncryptionKeypair::get_borrowed(conn, kp_ref)
                .ok()
                .flatten()?;
            deser(&v.keypairs).ok()
        }
    }
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl openmls_traits::key_store::OpenMlsKeyStore for Transaction {
    type Error = CryptoKeystoreError;

    async fn store<V: MlsEntity + Sync>(&self, id: &[u8], value: &V) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        if id.is_empty() {
            return Err(CryptoKeystoreError::MlsKeyStoreError(
                "The provided key is empty".into(),
            ));
        }

        let data = ser(value)?;

        match V::ID {
            MlsEntityId::GroupState => {
                return Err(CryptoKeystoreError::IncorrectApiUsage(
                    "Groups must not be saved using OpenMLS's APIs. You should use the keystore's provided methods",
                ));
            }
            MlsEntityId::SignatureKeyPair => {
                return Err(CryptoKeystoreError::IncorrectApiUsage(
                    "Signature keys must not be saved using OpenMLS's APIs. Save a credential via the keystore API
                    instead.",
                ));
            }
            MlsEntityId::KeyPackage => {
                StoredKeyPackage {
                    key_package_ref: id.into(),
                    key_package: data,
                }
                .save(self)?;
            }
            MlsEntityId::HpkePrivateKey => {
                StoredHpkePrivateKey {
                    pk: id.into(),
                    sk: data,
                }
                .save(self)?;
            }
            MlsEntityId::PskBundle => {
                StoredPskBundle {
                    psk_id: id.into(),
                    psk: data,
                }
                .save(self)?;
            }
            MlsEntityId::EncryptionKeyPair => {
                StoredEncryptionKeyPair {
                    pk: id.into(),
                    sk: data,
                }
                .save(self)?;
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let StoredEpochEncryptionKeypairPkRef {
                    conversation_id,
                    own_leaf_idx,
                    epoch,
                } = StoredEpochEncryptionKeypairPkRef::parse_bytes(id)?;
                StoredEpochEncryptionKeypair {
                    conversation_id: conversation_id.bytes().into(),
                    own_leaf_idx,
                    epoch,
                    keypairs: data,
                }
                .save(self)?;
            }
        }

        Ok(())
    }

    async fn read<V: MlsEntity>(&self, id: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        let conn = self.conn().ok()?;
        read_mls_entity(&conn, id)
    }

    async fn delete<V: MlsEntity>(&self, id: &[u8]) -> Result<(), Self::Error> {
        match V::ID {
            MlsEntityId::SignatureKeyPair => unimplemented!(
                "Deleting a signature key pair should not be done through this API, any keypair should be deleted via
                deleting a credential."
            ),
            MlsEntityId::GroupState => PersistedMlsGroup::delete_borrowed(self, id)?,
            MlsEntityId::HpkePrivateKey => StoredHpkePrivateKey::delete_borrowed(self, id)?,
            MlsEntityId::KeyPackage => StoredKeyPackage::delete_borrowed(self, id)?,
            MlsEntityId::PskBundle => StoredPskBundle::delete_borrowed(self, id)?,
            MlsEntityId::EncryptionKeyPair => StoredEncryptionKeyPair::delete_borrowed(self, id)?,
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp_ref = StoredEpochEncryptionKeypairPkRef::parse_bytes(id)?;
                StoredEpochEncryptionKeypair::delete_borrowed(self, kp_ref)?
            }
        };

        Ok(())
    }
}
