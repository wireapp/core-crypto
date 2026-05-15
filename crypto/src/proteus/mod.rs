mod conversation_session;
mod core_crypto;
mod message;
mod prekey;
mod session;
mod session_cache;

use std::sync::Arc;

pub use conversation_session::{ProteusConversationSession, SessionIdentifier};
use core_crypto_keystore::{Database, entities::ProteusIdentity, traits::FetchFromDatabase as _};
use proteus_wasm::keys::IdentityKeyPair;
pub(crate) use session_cache::ProteusSessionCache;

use crate::{KeystoreError, ProteusError, Result};

/// Proteus counterpart of [crate::mls::session::Session]
///
/// The big difference is that [ProteusCentral] doesn't *own* its own keystore but must borrow it from the outside.
/// Whether it's exclusively for this struct's purposes or it's shared with our main struct,
/// [crate::mls::session::Session]
#[derive(Debug)]
pub struct ProteusCentral {
    proteus_identity: Arc<IdentityKeyPair>,
    proteus_sessions: ProteusSessionCache,
}

impl ProteusCentral {
    /// Initializes the [ProteusCentral]
    pub async fn try_new(keystore: &Database) -> Result<Self> {
        let proteus_identity: Arc<IdentityKeyPair> = Arc::new(Self::load_or_create_identity(keystore).await?);
        let proteus_sessions = ProteusSessionCache::new(proteus_identity.clone());

        Ok(Self {
            proteus_identity,
            proteus_sessions,
        })
    }

    /// This function will try to load a proteus Identity from our keystore; If it cannot, it will create a new one
    /// This means this function doesn't fail except in cases of deeper errors (such as in the Keystore and other crypto
    /// errors)
    async fn load_or_create_identity(keystore: &Database) -> Result<IdentityKeyPair> {
        let Some(identity) = keystore
            .get_unique::<ProteusIdentity>()
            .await
            .map_err(KeystoreError::wrap("finding proteus identity"))?
        else {
            return Self::create_identity(keystore).await;
        };

        let sk = identity.sk_raw();
        let pk = identity.pk_raw();

        // SAFETY: Byte lengths are ensured at the keystore level so this function is safe to call, despite being cursed
        IdentityKeyPair::from_raw_key_pair(*sk, *pk)
            .map_err(ProteusError::wrap("constructing identity keypair"))
            .map_err(Into::into)
    }

    /// Internal function to create and save a new Proteus Identity
    async fn create_identity(keystore: &Database) -> Result<IdentityKeyPair> {
        let kp = IdentityKeyPair::new();
        let pk = kp.public_key.public_key.as_slice().to_vec();

        let ks_identity = ProteusIdentity {
            sk: kp.secret_key.to_keypair_bytes().into(),
            pk,
        };
        keystore
            .save(ks_identity)
            .await
            .map_err(KeystoreError::wrap("saving new proteus identity"))?;

        Ok(kp)
    }

    /// Proteus identity keypair
    pub fn identity(&self) -> &IdentityKeyPair {
        self.proteus_identity.as_ref()
    }

    /// Proteus Public key hex-encoded fingerprint
    pub fn fingerprint(&self) -> String {
        self.proteus_identity.as_ref().public_key.fingerprint()
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{ConnectionType, DatabaseKey};

    use super::*;
    use crate::test_utils::*;

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn can_init() {
        #[cfg(not(target_os = "unknown"))]
        let (path, db_file) = tmp_db_file();
        #[cfg(target_os = "unknown")]
        let (path, _) = tmp_db_file();
        let key = DatabaseKey::generate();
        let keystore = core_crypto_keystore::Database::open(ConnectionType::Persistent(&path), &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();
        let central = ProteusCentral::try_new(&keystore).await.unwrap();
        let identity = (*central.proteus_identity).clone();
        keystore.commit_transaction().await.unwrap();

        let keystore = core_crypto_keystore::Database::open(ConnectionType::Persistent(&path), &key)
            .await
            .unwrap();
        keystore.new_transaction().await.unwrap();
        let central = ProteusCentral::try_new(&keystore).await.unwrap();
        keystore.commit_transaction().await.unwrap();
        assert_eq!(identity, *central.proteus_identity);

        keystore.wipe().await.unwrap();
        #[cfg(not(target_os = "unknown"))]
        drop(db_file);
    }
}
