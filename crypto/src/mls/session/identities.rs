use std::{collections::HashMap, sync::Arc};

use openmls::prelude::{Credential as MlsCredential, SignaturePublicKey};
use openmls_traits::types::SignatureScheme;

use crate::{
    Credential, CredentialFindFilters, CredentialType, Session,
    mls::session::error::{Error, Result},
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
pub(crate) struct Identities {
    // u16 because `CredentialType: !Hash` for Reasons
    credentials: HashMap<(SignatureScheme, u16), Vec<Arc<Credential>>>,
}

impl Identities {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            credentials: HashMap::with_capacity(capacity),
        }
    }

    // not the real trait because we don't want to make the method public
    fn index(
        &self,
        signature_scheme: SignatureScheme,
        credential_type: CredentialType,
    ) -> Option<&Vec<Arc<Credential>>> {
        self.credentials.get(&(signature_scheme, credential_type.into()))
    }

    /// Return an iterator over all credentials matching the given filters.
    pub(crate) fn find_credential(&self, filters: CredentialFindFilters<'_>) -> impl Iterator<Item = Arc<Credential>> {
        let CredentialFindFilters {
            client_id,
            public_key,
            ciphersuite,
            credential_type,
            earliest_validity,
        } = filters;

        // we have an easy way to filter out a bunch of credentials if the right filters are set,
        // but we have to search through all of them if it is not.
        let values: Box<dyn Iterator<Item = Arc<Credential>>> = match ciphersuite.zip(credential_type) {
            Some((ciphersuite, credential_type)) => {
                match self.index(ciphersuite.signature_algorithm(), credential_type) {
                    Some(set) => Box::new(set.iter().cloned()),
                    None => Box::new(std::iter::empty()),
                }
            }
            None => Box::new(self.credentials.values().flatten().cloned()),
        };

        values.filter(move |credential| {
            ciphersuite.is_none_or(|ciphersuite| credential.signature_scheme() == ciphersuite.signature_algorithm())
                && credential_type.is_none_or(|credential_type| credential.credential_type() == credential_type)
                && earliest_validity.is_none_or(|earliest_validity| credential.earliest_validity == earliest_validity)
                && client_id.is_none_or(|client_id| credential.client_id() == client_id)
                && public_key.is_none_or(|public_key| credential.signature_key_pair.public() == public_key)
        })
    }

    /// Return the first credential matching the supplied fields
    ///
    /// Note that other credentials could in theory also match if they share the same public key.
    pub(crate) async fn find_credential_by_public_key(
        &self,
        signature_scheme: SignatureScheme,
        credential_type: CredentialType,
        public_key: &SignaturePublicKey,
    ) -> Option<Arc<Credential>> {
        self.index(signature_scheme, credential_type)?
            .iter()
            .find(|credential| credential.signature_key_pair.public() == public_key.as_slice())
            .cloned()
    }

    pub(crate) async fn find_most_recent_credential(
        &self,
        signature_scheme: SignatureScheme,
        credential_type: CredentialType,
    ) -> Option<Arc<Credential>> {
        self.index(signature_scheme, credential_type)?.last().cloned()
    }

    /// Raise an error if the database cannot handle adding a credential with these details.
    pub(crate) fn ensure_distinct(
        &self,
        signature_scheme: SignatureScheme,
        credential_type: CredentialType,
        earliest_validity: u64,
    ) -> Result<()> {
        let Some(credentials) = self.index(signature_scheme, credential_type) else {
            return Ok(());
        };

        debug_assert!(
            credentials.is_sorted_by_key(|credential| credential.earliest_validity),
            "can't binary search if credentials are not sorted by validity"
        );
        debug_assert_eq!(
            credentials
                .iter()
                .map(|credential| credential.earliest_validity)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            credentials.len(),
            "credentials must be distinct by earliest validity"
        );

        match credentials.binary_search_by_key(&earliest_validity, |credential| credential.earliest_validity) {
            // found a matching key i.e. not distinct
            Ok(_) => Err(Error::CredentialConflict),
            // no match i.e. distinct
            Err(_) => Ok(()),
        }
    }

    /// Add this credential to the identities.
    ///
    /// If there already exists a credential whose signature scheme, credential type, and timestamp of creation
    /// match those of an existing credential, this will return a `CredentialConflict`. This is because our code
    /// relies on `find_most_recent_credential` which can only distinguish credentials by those factors.
    ///
    /// Returns an `Arc<Credential>` which is a smart pointer to the credential within this data structure.
    pub(crate) async fn push_credential(&mut self, credential: Credential) -> Result<Arc<Credential>> {
        debug_assert_ne!(
            credential.earliest_validity, 0,
            "this credential must have been persisted/updated in the keystore, which sets this to the current timestamp"
        );

        let credential = Arc::new(credential);

        let credentials = self
            .credentials
            .entry((credential.signature_scheme(), credential.credential_type().into()))
            .or_default();

        debug_assert!(
            credentials.is_sorted_by_key(|credential| credential.earliest_validity),
            "can't binary search if credentials are not sorted by validity"
        );
        // if binary search returns ok, it was not distinct by earliest validity, therefore we have a conflict
        // normally we expect that the new credential has the most recent earliest_validity therefore adding the credential is
        // as cheap as pushing to the end of the vector, but just in case of random insertion order, do the right thing
        let Err(insertion_point) =
            credentials.binary_search_by_key(&credential.earliest_validity, |credential| credential.earliest_validity)
        else {
            return Err(Error::CredentialConflict);
        };
        credentials.insert(insertion_point, credential.clone());

        debug_assert!(
            credentials.is_sorted_by_key(|credential| credential.earliest_validity),
            "we must have inserted at the proper insertion point"
        );
        debug_assert_eq!(
            credentials
                .iter()
                .map(|credential| credential.earliest_validity)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            credentials.len(),
            "credentials must still be distinct by earliest validity"
        );

        Ok(credential)
    }

    pub(crate) fn remove_by_mls_credential(&mut self, mls_credential: &MlsCredential) {
        for credential_set in self.credentials.values_mut() {
            credential_set.retain(|credential| credential.mls_credential() != mls_credential);
        }
    }

    pub(crate) fn iter(&self) -> impl '_ + Iterator<Item = Arc<Credential>> {
        self.credentials.values().flatten().cloned()
    }
}

impl Session {
    #[cfg(test)]
    pub(crate) async fn identities_count(&self) -> Result<usize> {
        match &*self.inner.read().await {
            None => Err(Error::MlsNotInitialized),
            Some(super::SessionInner { identities, .. }) => Ok(identities.iter().count()),
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
                assert_eq!(found, new);
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

                assert_eq!(to_search, found);
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
