use std::sync::Arc;

#[cfg(target_family = "wasm")]
use crate::entities::E2eiRefreshToken;
#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};
use crate::{
    CryptoKeystoreResult,
    connection::TransactionWrapper,
    entities::{
        ConsumerData, E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup,
        PersistedMlsPendingGroup, StoredBufferedCommit, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::{EntityBase, EntityDatabaseMutation as _, UniqueEntityExt as _},
};

#[derive(Debug)]
pub enum Entity {
    ConsumerData(Arc<ConsumerData>),
    HpkePrivateKey(Arc<StoredHpkePrivateKey>),
    StoredKeypackage(Arc<StoredKeypackage>),
    PskBundle(Arc<StoredPskBundle>),
    EncryptionKeyPair(Arc<StoredEncryptionKeyPair>),
    StoredEpochEncryptionKeypair(Arc<StoredEpochEncryptionKeypair>),
    StoredCredential(Arc<StoredCredential>),
    StoredBufferedCommit(Arc<StoredBufferedCommit>),
    PersistedMlsGroup(Arc<PersistedMlsGroup>),
    PersistedMlsPendingGroup(Arc<PersistedMlsPendingGroup>),
    MlsPendingMessage(Arc<MlsPendingMessage>),
    StoredE2eiEnrollment(Arc<StoredE2eiEnrollment>),
    #[cfg(target_family = "wasm")]
    E2eiRefreshToken(Arc<E2eiRefreshToken>),
    E2eiAcmeCA(Arc<E2eiAcmeCA>),
    E2eiIntermediateCert(Arc<E2eiIntermediateCert>),
    E2eiCrl(Arc<E2eiCrl>),
    #[cfg(feature = "proteus-keystore")]
    ProteusIdentity(Arc<ProteusIdentity>),
    #[cfg(feature = "proteus-keystore")]
    ProteusPrekey(Arc<ProteusPrekey>),
    #[cfg(feature = "proteus-keystore")]
    ProteusSession(Arc<ProteusSession>),
}

impl Entity {
    /// Downcast this entity to an instance of the requested type.
    ///
    /// This increments the smart pointer counter instead of cloning the potentially large item instance.
    pub(crate) fn downcast<E>(&self) -> Option<Arc<E>>
    where
        E: EntityBase + Send + Sync,
    {
        match self {
            Entity::ConsumerData(consumer_data) => consumer_data.clone().downcast_arc(),
            Entity::HpkePrivateKey(stored_hpke_private_key) => stored_hpke_private_key.clone().downcast_arc(),
            Entity::StoredKeypackage(stored_keypackage) => stored_keypackage.clone().downcast_arc(),
            Entity::PskBundle(stored_psk_bundle) => stored_psk_bundle.clone().downcast_arc(),
            Entity::EncryptionKeyPair(stored_encryption_key_pair) => stored_encryption_key_pair.clone().downcast_arc(),
            Entity::StoredEpochEncryptionKeypair(stored_epoch_encryption_keypair) => {
                stored_epoch_encryption_keypair.clone().downcast_arc()
            }
            Entity::StoredCredential(stored_credential) => stored_credential.clone().downcast_arc(),
            Entity::StoredBufferedCommit(stored_buffered_commit) => stored_buffered_commit.clone().downcast_arc(),
            Entity::PersistedMlsGroup(persisted_mls_group) => persisted_mls_group.clone().downcast_arc(),
            Entity::PersistedMlsPendingGroup(persisted_mls_pending_group) => {
                persisted_mls_pending_group.clone().downcast_arc()
            }
            Entity::MlsPendingMessage(mls_pending_message) => mls_pending_message.clone().downcast_arc(),
            Entity::StoredE2eiEnrollment(stored_e2ei_enrollment) => stored_e2ei_enrollment.clone().downcast_arc(),
            Entity::E2eiAcmeCA(e2ei_acme_ca) => e2ei_acme_ca.clone().downcast_arc(),
            Entity::E2eiIntermediateCert(e2ei_intermediate_cert) => e2ei_intermediate_cert.clone().downcast_arc(),
            Entity::E2eiCrl(e2ei_crl) => e2ei_crl.clone().downcast_arc(),
            #[cfg(target_family = "wasm")]
            Entity::E2eiRefreshToken(e2ei_refresh_token) => e2ei_refresh_token.clone().downcast_arc(),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusIdentity(proteus_identity) => proteus_identity.clone().downcast_arc(),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusPrekey(proteus_prekey) => proteus_prekey.clone().downcast_arc(),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusSession(proteus_session) => proteus_session.clone().downcast_arc(),
        }
    }

    pub(crate) fn downcast_option_mut<E>(option: &mut Option<Self>) -> &mut Option<E>
    where
        E: EntityBase + Send + Sync,
    {
        let is_some_of_e = match option {
            Some(Entity::ConsumerData(consumer_data)) => consumer_data.is::<E>(),
            Some(Entity::HpkePrivateKey(stored_hpke_private_key)) => stored_hpke_private_key.is::<E>(),
            Some(Entity::StoredKeypackage(stored_keypackage)) => stored_keypackage.is::<E>(),
            Some(Entity::PskBundle(stored_psk_bundle)) => stored_psk_bundle.is::<E>(),
            Some(Entity::EncryptionKeyPair(stored_encryption_key_pair)) => stored_encryption_key_pair.is::<E>(),
            Some(Entity::StoredEpochEncryptionKeypair(stored_epoch_encryption_keypair)) => {
                stored_epoch_encryption_keypair.is::<E>()
            }
            Some(Entity::StoredCredential(stored_credential)) => stored_credential.is::<E>(),
            Some(Entity::StoredBufferedCommit(stored_buffered_commit)) => stored_buffered_commit.is::<E>(),
            Some(Entity::PersistedMlsGroup(persisted_mls_group)) => persisted_mls_group.is::<E>(),
            Some(Entity::PersistedMlsPendingGroup(persisted_mls_pending_group)) => {
                persisted_mls_pending_group.is::<E>()
            }
            Some(Entity::MlsPendingMessage(mls_pending_message)) => mls_pending_message.is::<E>(),
            Some(Entity::StoredE2eiEnrollment(stored_e2ei_enrollment)) => stored_e2ei_enrollment.is::<E>(),
            Some(Entity::E2eiAcmeCA(e2ei_acme_ca)) => e2ei_acme_ca.is::<E>(),
            Some(Entity::E2eiIntermediateCert(e2ei_intermediate_cert)) => e2ei_intermediate_cert.is::<E>(),
            Some(Entity::E2eiCrl(e2ei_crl)) => e2ei_crl.is::<E>(),
            #[cfg(target_family = "wasm")]
            Some(Entity::E2eiRefreshToken(e2ei_refresh_token)) => e2ei_refresh_token.is::<E>(),
            #[cfg(feature = "proteus-keystore")]
            Some(Entity::ProteusIdentity(proteus_identity)) => proteus_identity.is::<E>(),
            #[cfg(feature = "proteus-keystore")]
            Some(Entity::ProteusPrekey(proteus_prekey)) => proteus_prekey.is::<E>(),
            #[cfg(feature = "proteus-keystore")]
            Some(Entity::ProteusSession(proteus_session)) => proteus_session.is::<E>(),
            None => false,
        };
        if is_some_of_e {
            unsafe { std::mem::transmute(option) }
        } else {
            unsafe { std::mem::transmute(std::ptr::null::<E>()) }
        }
    }

    pub(crate) async fn execute_save(&self, tx: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        match self {
            Entity::ConsumerData(consumer_data) => consumer_data.set_and_replace(tx).await.map(|_| ()),
            Entity::HpkePrivateKey(mls_hpke_private_key) => mls_hpke_private_key.save(tx).await,
            Entity::StoredKeypackage(mls_key_package) => mls_key_package.save(tx).await,
            Entity::PskBundle(mls_psk_bundle) => mls_psk_bundle.save(tx).await,
            Entity::EncryptionKeyPair(mls_encryption_key_pair) => mls_encryption_key_pair.save(tx).await,
            Entity::StoredEpochEncryptionKeypair(mls_epoch_encryption_key_pair) => {
                mls_epoch_encryption_key_pair.save(tx).await
            }
            Entity::StoredCredential(mls_credential) => mls_credential.save(tx).await,
            Entity::StoredBufferedCommit(mls_pending_commit) => mls_pending_commit.save(tx).await,
            Entity::PersistedMlsGroup(persisted_mls_group) => persisted_mls_group.save(tx).await,
            Entity::PersistedMlsPendingGroup(persisted_mls_pending_group) => persisted_mls_pending_group.save(tx).await,
            Entity::MlsPendingMessage(mls_pending_message) => mls_pending_message.save(tx).await,
            Entity::StoredE2eiEnrollment(e2ei_enrollment) => e2ei_enrollment.save(tx).await,
            Entity::E2eiAcmeCA(e2ei_acme_ca) => e2ei_acme_ca.set_and_replace(tx).await.map(|_| ()),
            Entity::E2eiIntermediateCert(e2ei_intermediate_cert) => e2ei_intermediate_cert.save(tx).await,
            #[cfg(target_family = "wasm")]
            Entity::E2eiRefreshToken(e2ei_refresh_token) => e2ei_refresh_token.set_and_replace(tx).await.map(|_| ()),
            Entity::E2eiCrl(e2ei_crl) => e2ei_crl.save(tx).await,
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusSession(record) => record.save(tx).await,
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusIdentity(record) => record.save(tx).await,
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusPrekey(record) => record.save(tx).await,
        }
    }
}
