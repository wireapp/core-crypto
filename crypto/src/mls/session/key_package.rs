use core_crypto_keystore::{entities::StoredKeypackage, traits::FetchFromDatabase};

use super::Result;
use crate::{Keypackage, KeypackageRef, KeystoreError, Session, mls::key_package::KeypackageExt};

fn from_stored(stored_keypackage: &StoredKeypackage) -> Result<Keypackage> {
    core_crypto_keystore::deser::<Keypackage>(&stored_keypackage.keypackage)
        .map_err(KeystoreError::wrap("deserializing keypackage"))
        .map_err(Into::into)
}

impl<D> Session<D>
where
    D: FetchFromDatabase,
{
    /// Get all [`Keypackage`]s in the database.
    pub(crate) async fn get_keypackages(&self) -> Result<Vec<Keypackage>> {
        let stored_keypackages: Vec<StoredKeypackage> = self
            .database
            .load_all()
            .await
            .map_err(KeystoreError::wrap("finding all keypackages"))?;

        let keypackages = stored_keypackages
            .iter()
            .map(from_stored)
            // if any ref from loading all fails to load now, skip it
            // strictly we could panic, but this is safer--maybe someone removed it concurrently
            .filter_map(|kp| kp.ok())
            .collect();

        Ok(keypackages)
    }

    /// Get all [`KeypackageRef`]s in the database.
    pub async fn get_keypackage_refs(&self) -> Result<Vec<KeypackageRef>> {
        self.get_keypackages()
            .await?
            .iter()
            .map(|keypackage| keypackage.make_ref().map_err(Into::into))
            .collect()
    }

    /// Load one [`Keypackage`] from its [`KeypackageRef`]
    pub(crate) async fn load_keypackage(&self, kp_ref: &KeypackageRef) -> Result<Option<Keypackage>> {
        self.database
            .get_borrowed::<StoredKeypackage>(kp_ref.hash_ref())
            .await
            .map_err(KeystoreError::wrap("loading keypackage from database"))?
            .map(|stored_keypackage| from_stored(&stored_keypackage))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use openmls::prelude::{KeyPackageIn, ProtocolVersion};
    use openmls_traits::types::VerifiableCiphersuite;

    use crate::{MlsConversationConfiguration, mls::key_package::KeypackageExt as _, test_utils::*};

    #[apply(all_cred_cipher)]
    async fn can_assess_keypackage_expiration(case: TestContext) {
        let [session] = case.sessions().await;

        // 90-day standard expiration
        let kp_std_exp = session.new_keypackage(&case).await;
        assert!(kp_std_exp.is_valid());

        // 1-second expiration
        let kp_1s_exp = session
            .new_keypackage_with_lifetime(&case, Some(Duration::from_secs(1)))
            .await;

        // Sleep 2 seconds to make sure we make the kp expire
        smol::Timer::after(std::time::Duration::from_secs(2)).await;
        assert!(!kp_1s_exp.is_valid());
    }

    #[apply(all_cred_cipher)]
    async fn new_keypackage_has_correct_extensions(case: TestContext) {
        let [cc] = case.sessions().await;
        Box::pin(async move {
            let kp = cc.new_keypackage(&case).await;

            // make sure it's valid
            let _ = KeyPackageIn::from(kp.clone())
                .standalone_validate(
                    &cc.transaction.mls_provider().await.unwrap(),
                    ProtocolVersion::Mls10,
                    true,
                )
                .await
                .unwrap();

            // see https://www.rfc-editor.org/rfc/rfc9420.html#section-10-10
            assert!(kp.extensions().is_empty());

            assert_eq!(kp.leaf_node().capabilities().versions(), &[ProtocolVersion::Mls10]);
            assert_eq!(
                kp.leaf_node().capabilities().ciphersuites().to_vec(),
                MlsConversationConfiguration::DEFAULT_SUPPORTED_CIPHERSUITES
                    .iter()
                    .map(|c| VerifiableCiphersuite::from(*c))
                    .collect::<Vec<_>>()
            );
            assert!(kp.leaf_node().capabilities().proposals().is_empty());
            assert!(kp.leaf_node().capabilities().extensions().is_empty());
            assert_eq!(
                kp.leaf_node().capabilities().credentials(),
                MlsConversationConfiguration::DEFAULT_SUPPORTED_CREDENTIALS
            );
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn can_store_and_load_key_packages(case: TestContext) {
        let [cc] = case.sessions().await;

        // generate a keypackage; automatically saves it
        let kp = cc.new_keypackage(&case).await;

        let all_keypackages = cc.session.read().await.get_keypackages().await.unwrap();
        assert_eq!(all_keypackages[0], kp);

        let kp_ref = kp.make_ref().unwrap();
        let by_ref = cc.session.read().await.load_keypackage(&kp_ref).await.unwrap().unwrap();
        assert_eq!(kp, by_ref);
    }
}
