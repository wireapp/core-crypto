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
    traits::{EntityDatabaseMutation as _, UniqueEntityExt as _},
};

#[derive(Debug)]
pub(crate) enum Entity<'a> {
    ConsumerData(&'a ConsumerData),
    HpkePrivateKey(&'a StoredHpkePrivateKey),
    StoredKeypackage(&'a StoredKeypackage),
    PskBundle(&'a StoredPskBundle),
    EncryptionKeyPair(&'a StoredEncryptionKeyPair),
    StoredEpochEncryptionKeypair(&'a StoredEpochEncryptionKeypair),
    StoredCredential(&'a StoredCredential),
    StoredBufferedCommit(&'a StoredBufferedCommit),
    PersistedMlsGroup(&'a PersistedMlsGroup),
    PersistedMlsPendingGroup(&'a PersistedMlsPendingGroup),
    MlsPendingMessage(&'a MlsPendingMessage),
    StoredE2eiEnrollment(&'a StoredE2eiEnrollment),
    #[cfg(target_family = "wasm")]
    E2eiRefreshToken(&'a E2eiRefreshToken),
    E2eiAcmeCA(&'a E2eiAcmeCA),
    E2eiIntermediateCert(&'a E2eiIntermediateCert),
    E2eiCrl(&'a E2eiCrl),
    #[cfg(feature = "proteus-keystore")]
    ProteusIdentity(&'a ProteusIdentity),
    #[cfg(feature = "proteus-keystore")]
    ProteusPrekey(&'a ProteusPrekey),
    #[cfg(feature = "proteus-keystore")]
    ProteusSession(&'a ProteusSession),
}

impl<'a, E> From<&'a E> for Entity<'a>
where
    E: crate::traits::Entity,
{
    #[inline]
    fn from(value: &'a E) -> Self {
        value.to_transaction_entity()
    }
}

impl Entity<'_> {
    pub(crate) async fn execute_save(&self, tx: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        match self {
            Entity::ConsumerData(consumer_data) => {
                consumer_data.set_and_replace(tx).await;
                Ok(())
            }
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
            #[cfg(target_family = "wasm")]
            Entity::E2eiRefreshToken(e2ei_refresh_token) => e2ei_refresh_token.replace(tx).await,
            Entity::E2eiAcmeCA(e2ei_acme_ca) => {
                e2ei_acme_ca.set_and_replace(tx).await;
                Ok(())
            }
            Entity::E2eiIntermediateCert(e2ei_intermediate_cert) => e2ei_intermediate_cert.save(tx).await,
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
