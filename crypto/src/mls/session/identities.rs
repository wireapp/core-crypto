use std::{
    collections::{BTreeSet, HashMap},
    ops::Deref,
    sync::Arc,
};

use openmls::prelude::{Credential as MlsCredential, SignaturePublicKey};
use openmls_traits::types::SignatureScheme;

use crate::{
    Credential, CredentialType, Session,
    mls::session::{
        SessionInner,
        error::{Error, Result},
    },
};

/// Each session has a set of credentials per signature scheme: they can have various properties, but typically
/// we want to find the most recent of a particular type.
///
/// We use this data structure to make that easy. The outer map filters by signature scheme. The inner set lets us
/// quickly find the most recent.
///
/// This depends on the fact that in `Credential`'s `Ord` impl, the first comparison is by the credential's `earliest_validity`.
/// However, by structuring things like this, we do not need to care about insertion order.
///
/// We keep each credential inside an arc to avoid cloning them, as X509 credentials can get quite large.
#[derive(Debug, Clone)]
pub(crate) struct Identities(HashMap<SignatureScheme, BTreeSet<Arc<Credential>>>);

impl Identities {
    pub(crate) fn new(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    pub(crate) async fn find_credential_by_public_key(
        &self,
        sc: SignatureScheme,
        ct: CredentialType,
        pk: &SignaturePublicKey,
    ) -> Option<Arc<Credential>> {
        self.0
            .get(&sc)?
            .iter()
            .find(|c| {
                let ct_match = ct == c.mls_credential.credential_type();
                let pk_match = c.signature_key_pair.public() == pk.as_slice();
                ct_match && pk_match
            })
            .cloned()
    }

    pub(crate) async fn find_most_recent_credential(
        &self,
        sc: SignatureScheme,
        ct: CredentialType,
    ) -> Option<Arc<Credential>> {
        self.0
            .get(&sc)?
            .iter()
            .rfind(|c| ct == c.mls_credential.credential_type())
            .cloned()
    }

    /// Raise an error if the database cannot handle adding a credential with these details.
    pub(crate) fn ensure_distinct(
        &self,
        signature_scheme: SignatureScheme,
        credential_type: CredentialType,
        earliest_validity: u64,
    ) -> Result<()> {
        if self.0.values().flat_map(|set| set.iter()).any(|existing_credential| {
            existing_credential.signature_scheme() == signature_scheme
                && existing_credential.credential_type() == credential_type
                && existing_credential.earliest_validity == earliest_validity
        }) {
            return Err(Error::CredentialConflict);
        }
        Ok(())
    }

    /// Add this credential to the identities.
    ///
    /// If there already exists a credential whose signature scheme, credential type, and timestamp of creation
    /// match those of an existing credential, this will return a `CredentialConflict`. This is because our code
    /// relies on `find_most_recent_credential` which can only distinguish credentials by those factors.
    pub(crate) async fn push_credential(&mut self, credential: Credential) -> Result<()> {
        debug_assert_ne!(
            credential.earliest_validity, 0,
            "this credential must have been persisted/updated in the keystore, which sets this to the current timestamp"
        );

        self.ensure_distinct(
            credential.signature_scheme(),
            credential.credential_type(),
            credential.earliest_validity,
        )?;

        let _already_existed = !self
            .0
            .entry(credential.signature_scheme())
            .or_default()
            .insert(Arc::new(credential));

        debug_assert!(
            !_already_existed,
            "we've alredy deconflicted by signature scheme, type, and timestamp, so there can't be a matching credential present"
        );

        Ok(())
    }

    pub(crate) fn remove(&mut self, mls_credential: &MlsCredential) {
        for credential_set in self.0.values_mut() {
            credential_set.retain(|credential| credential.mls_credential() != mls_credential);
        }
    }

    pub(crate) fn iter(&self) -> impl '_ + Iterator<Item = Arc<Credential>> {
        self.0.values().flatten().cloned()
    }
}

impl Session {
    pub(crate) async fn find_most_recent_credential(
        &self,
        sc: SignatureScheme,
        ct: CredentialType,
    ) -> Result<Arc<Credential>> {
        match self.inner.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { identities, .. }) => identities
                .find_most_recent_credential(sc, ct)
                .await
                .ok_or(Error::CredentialNotFound(ct)),
        }
    }

    pub(crate) async fn find_credential_by_public_key(
        &self,
        sc: SignatureScheme,
        ct: CredentialType,
        pk: &SignaturePublicKey,
    ) -> Result<Arc<Credential>> {
        match self.inner.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { identities, .. }) => identities
                .find_credential_by_public_key(sc, ct, pk)
                .await
                .ok_or(Error::CredentialNotFound(ct)),
        }
    }

    #[cfg(test)]
    pub(crate) async fn identities_count(&self) -> Result<usize> {
        match self.inner.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { identities, .. }) => Ok(identities.iter().count()),
        }
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::SignaturePublicKey;
    use rand::Rng;

    use crate::test_utils::*;

    mod find {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_find_most_recent(case: TestContext) {
            let [mut central] = case.sessions().await;
            Box::pin(async move {
                let cert = central.get_intermediate_ca().cloned();

                // all credentials need to be distinguishable by type, scheme, and timestamp
                // we need to wait a second so the new credential has a distinct timestamp
                // (our DB has a timestamp resolution of 1s)
                smol::Timer::after(std::time::Duration::from_secs(1)).await;

                let old = central.new_credential(&case, cert.as_ref()).await;

                // again here
                smol::Timer::after(std::time::Duration::from_secs(1)).await;

                let new = central.new_credential(&case, cert.as_ref()).await;
                assert_ne!(old, new);

                let found = central
                    .find_most_recent_credential(case.signature_scheme(), case.credential_type)
                    .await
                    .unwrap();
                assert_eq!(found.as_ref(), &new);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_find_by_public_key(case: TestContext) {
            let [mut central] = case.sessions().await;
            Box::pin(async move {
                const N: usize = 15;

                let r = rand::thread_rng().gen_range(0..N);
                let mut to_search = None;
                let cert = central.get_intermediate_ca().cloned();

                for i in 0..N {
                    // all credentials need to be distinguishable by type, scheme, and timestamp
                    // we need to wait a second so the new credential has a distinct timestamp
                    // (our DB has a timestamp resolution of 1s)
                    smol::Timer::after(std::time::Duration::from_secs(1)).await;

                    let cb = central.new_credential(&case, cert.as_ref()).await;
                    if i == r {
                        to_search = Some(cb.clone());
                    }
                }
                let to_search = to_search.unwrap();
                let pk = SignaturePublicKey::from(to_search.signature_key_pair.public());
                let client = central.transaction.session().await.unwrap();
                let found = client
                    .find_credential_by_public_key(case.signature_scheme(), case.credential_type, &pk)
                    .await
                    .unwrap();
                assert_eq!(&to_search, found.as_ref());
            })
            .await
        }
    }

    mod push {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_add_credential(case: TestContext) {
            let [mut central] = case.sessions().await;
            Box::pin(async move {
                let client = central.session().await;
                let prev_count = client.identities_count().await.unwrap();
                let cert = central.get_intermediate_ca().cloned();

                // all credentials need to be distinguishable by type, scheme, and timestamp
                // we need to wait a second so the new credential has a distinct timestamp
                // (our DB has a timestamp resolution of 1s)
                smol::Timer::after(std::time::Duration::from_secs(1)).await;

                // this calls 'push_credential' under the hood
                central.new_credential(&case, cert.as_ref()).await;
                let next_count = client.identities_count().await.unwrap();
                assert_eq!(next_count, prev_count + 1);
            })
            .await
        }
    }
}
