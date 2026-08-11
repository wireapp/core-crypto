use std::any::Any;
use std::sync::Arc;

use rusqlite::Transaction;

use crate::CryptoKeystoreResult;
use crate::entities::ConsumerData;
use crate::entities::MlsPendingMessage;
use crate::entities::PersistedMlsGroup;
use crate::entities::PersistedMlsPendingGroup;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusIdentity;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusPrekey;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusSession;
use crate::entities::StoredBufferedCommit;
use crate::entities::StoredCredential;
use crate::entities::StoredEncryptionKeyPair;
use crate::entities::StoredEpochEncryptionKeypair;
use crate::entities::StoredHpkePrivateKey;
use crate::entities::StoredKeyPackage;
use crate::entities::StoredPskBundle;
use crate::entities::X509Crl;
use crate::entities::X509IntermediateCert;
use crate::entities::X509TrustAnchor;
use crate::traits::EntityDatabaseMutation as _;
use crate::traits::UniqueEntityExt as _;

#[derive(Debug)]
pub enum Entity {
    ConsumerData(Arc<ConsumerData>),
    HpkePrivateKey(Arc<StoredHpkePrivateKey>),
    StoredKeyPackage(Arc<StoredKeyPackage>),
    PskBundle(Arc<StoredPskBundle>),
    EncryptionKeyPair(Arc<StoredEncryptionKeyPair>),
    StoredEpochEncryptionKeypair(Arc<StoredEpochEncryptionKeypair>),
    StoredCredential(Arc<StoredCredential>),
    StoredBufferedCommit(Arc<StoredBufferedCommit>),
    PersistedMlsGroup(Arc<PersistedMlsGroup>),
    PersistedMlsPendingGroup(Arc<PersistedMlsPendingGroup>),
    MlsPendingMessage(Arc<MlsPendingMessage>),
    X509TrustAnchor(Arc<X509TrustAnchor>),
    X509IntermediateCert(Arc<X509IntermediateCert>),
    X509Crl(Arc<X509Crl>),
    #[cfg(feature = "proteus-keystore")]
    ProteusIdentity(Arc<ProteusIdentity>),
    #[cfg(feature = "proteus-keystore")]
    ProteusPrekey(Arc<ProteusPrekey>),
    #[cfg(feature = "proteus-keystore")]
    ProteusSession(Arc<ProteusSession>),
}

macro_rules! impl_from {
    ($variant:ident => $t:ty) => {
        impl From<$t> for Entity {
            fn from(value: $t) -> Entity {
                Entity::$variant(Arc::new(value))
            }
        }
    };
    ($variant:ident) => {
        impl_from!($variant => $variant);
    }
}

impl_from!(ConsumerData);
impl_from!(HpkePrivateKey => StoredHpkePrivateKey);
impl_from!(StoredKeyPackage);
impl_from!(PskBundle => StoredPskBundle);
impl_from!(EncryptionKeyPair => StoredEncryptionKeyPair);
impl_from!(StoredEpochEncryptionKeypair);
impl_from!(StoredCredential);
impl_from!(StoredBufferedCommit);
impl_from!(PersistedMlsGroup);
impl_from!(PersistedMlsPendingGroup);
impl_from!(MlsPendingMessage);
impl_from!(X509TrustAnchor);
impl_from!(X509IntermediateCert);
impl_from!(X509Crl);
#[cfg(feature = "proteus-keystore")]
impl_from!(ProteusIdentity);
#[cfg(feature = "proteus-keystore")]
impl_from!(ProteusPrekey);
#[cfg(feature = "proteus-keystore")]
impl_from!(ProteusSession);

fn downcast<E, T>(input: &Arc<E>) -> Option<Arc<T>>
where
    E: 'static + Send + Sync,
    T: 'static + Send + Sync,
{
    let dynamic = input.clone() as Arc<dyn Any + Send + Sync>;
    dynamic.downcast().ok()
}

impl Entity {
    /// Downcast this entity to an instance of the requested type.
    ///
    /// This increments the smart pointer counter instead of cloning the potentially large item instance.
    pub(crate) fn downcast<E>(&self) -> Option<Arc<E>>
    where
        E: 'static + Send + Sync,
    {
        match self {
            Entity::ConsumerData(consumer_data) => downcast(consumer_data),
            Entity::HpkePrivateKey(stored_hpke_private_key) => downcast(stored_hpke_private_key),
            Entity::StoredKeyPackage(stored_keypackage) => downcast(stored_keypackage),
            Entity::PskBundle(stored_psk_bundle) => downcast(stored_psk_bundle),
            Entity::EncryptionKeyPair(stored_encryption_key_pair) => downcast(stored_encryption_key_pair),
            Entity::StoredEpochEncryptionKeypair(stored_epoch_encryption_keypair) => {
                downcast(stored_epoch_encryption_keypair)
            }
            Entity::StoredCredential(stored_credential) => downcast(stored_credential),
            Entity::StoredBufferedCommit(stored_buffered_commit) => downcast(stored_buffered_commit),
            Entity::PersistedMlsGroup(persisted_mls_group) => downcast(persisted_mls_group),
            Entity::PersistedMlsPendingGroup(persisted_mls_pending_group) => downcast(persisted_mls_pending_group),
            Entity::MlsPendingMessage(mls_pending_message) => downcast(mls_pending_message),
            Entity::X509TrustAnchor(e2ei_acme_ca) => downcast(e2ei_acme_ca),
            Entity::X509IntermediateCert(e2ei_intermediate_cert) => downcast(e2ei_intermediate_cert),
            Entity::X509Crl(e2ei_crl) => downcast(e2ei_crl),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusIdentity(proteus_identity) => downcast(proteus_identity),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusPrekey(proteus_prekey) => downcast(proteus_prekey),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusSession(proteus_session) => downcast(proteus_session),
        }
    }

    pub(crate) fn execute_save(&self, tx: &Transaction<'_>) -> CryptoKeystoreResult<()> {
        match self {
            Entity::ConsumerData(consumer_data) => consumer_data.set_and_replace(tx).map(|_| ()),
            Entity::HpkePrivateKey(mls_hpke_private_key) => mls_hpke_private_key.save(tx),
            Entity::StoredKeyPackage(mls_key_package) => mls_key_package.save(tx),
            Entity::PskBundle(mls_psk_bundle) => mls_psk_bundle.save(tx),
            Entity::EncryptionKeyPair(mls_encryption_key_pair) => mls_encryption_key_pair.save(tx),
            Entity::StoredEpochEncryptionKeypair(mls_epoch_encryption_key_pair) => {
                mls_epoch_encryption_key_pair.save(tx)
            }
            Entity::StoredCredential(mls_credential) => mls_credential.save(tx),
            Entity::StoredBufferedCommit(mls_pending_commit) => mls_pending_commit.save(tx),
            Entity::PersistedMlsGroup(persisted_mls_group) => persisted_mls_group.save(tx),
            Entity::PersistedMlsPendingGroup(persisted_mls_pending_group) => persisted_mls_pending_group.save(tx),
            Entity::MlsPendingMessage(mls_pending_message) => mls_pending_message.save(tx),
            Entity::X509TrustAnchor(x509_trust_anchor) => x509_trust_anchor.save(tx),
            Entity::X509IntermediateCert(e2ei_intermediate_cert) => e2ei_intermediate_cert.save(tx),
            Entity::X509Crl(e2ei_crl) => e2ei_crl.save(tx),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusSession(record) => record.save(tx),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusIdentity(record) => record.save(tx),
            #[cfg(feature = "proteus-keystore")]
            Entity::ProteusPrekey(record) => record.save(tx),
        }
    }
}
