use std::{collections::HashMap, ops::Deref, sync::Arc};

use openmls::prelude::{Credential as MlsCredential, SignaturePublicKey};
use openmls_traits::types::SignatureScheme;

use crate::{
    Session,
    mls::{
        credential::{Credential, typ::CredentialType},
        session::{
            SessionInner,
            error::{Error, Result},
        },
    },
};

/// In memory Map of a Session's identities: one per SignatureScheme.
/// We need `indexmap::IndexSet` because each `Credential` has to be unique and insertion
/// order matters in order to keep values sorted by time `created_at` so that we can identify most recent ones.
///
/// We keep each credential inside an arc to avoid cloning them, as X509 credentials can get quite large.
#[derive(Debug, Clone)]
pub(crate) struct Identities(HashMap<SignatureScheme, indexmap::IndexSet<Arc<Credential>>>);

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
                let ct_match = ct == c.mls_credential.credential_type().into();
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
            .rfind(|c| ct == c.mls_credential.credential_type().into())
            .cloned()
    }

    /// Having `cb` requiring ownership kinda forces the caller to first persist it in the keystore and
    /// only then store it in this in-memory map
    pub(crate) async fn push_credential(&mut self, sc: SignatureScheme, cb: Credential) -> Result<()> {
        // this would mean we have messed something up and that we do no init this Credential from a keypair just inserted in the keystore
        debug_assert_ne!(cb.created_at, 0);

        match self.0.get_mut(&sc) {
            Some(cbs) => {
                let already_exists = !cbs.insert(Arc::new(cb));
                if already_exists {
                    return Err(Error::CredentialConflict);
                }
            }
            None => {
                self.0.insert(sc, indexmap::IndexSet::from([Arc::new(cb)]));
            }
        }
        Ok(())
    }

    pub(crate) async fn remove(&mut self, credential: &MlsCredential) -> Result<()> {
        self.0.iter_mut().for_each(|(_, cbs)| {
            cbs.retain(|c| c.credential() != credential);
        });
        Ok(())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (SignatureScheme, Arc<Credential>)> + '_ {
        self.0.iter().flat_map(|(sc, cb)| cb.iter().map(|c| (*sc, c.clone())))
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

    use crate::{mls, test_utils::*};

    mod find {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_find_most_recent(case: TestContext) {
            let [mut central] = case.sessions().await;
            Box::pin(async move {
                let cert = central.get_intermediate_ca().cloned();
                let old = central.new_credential(&case, cert.as_ref()).await;

                // wait to make sure we're not in the same second
                smol::Timer::after(core::time::Duration::from_secs(1)).await;

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
                const N: usize = 50;

                let r = rand::thread_rng().gen_range(0..N);
                let mut to_search = None;
                for i in 0..N {
                    let cert = central.get_intermediate_ca().cloned();
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
                // this calls 'push_credential' under the hood
                central.new_credential(&case, cert.as_ref()).await;
                let next_count = client.identities_count().await.unwrap();
                assert_eq!(next_count, prev_count + 1);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn pushing_duplicates_should_fail(case: TestContext) {
            let [mut central] = case.sessions().await;
            Box::pin(async move {
                let cert = central.get_intermediate_ca().cloned();
                let cb = central.new_credential(&case, cert.as_ref()).await;
                let client = central.transaction.session().await.unwrap();
                let push = client
                    .save_identity(
                        &central.transaction.keystore().await.unwrap(),
                        None,
                        case.signature_scheme(),
                        cb,
                    )
                    .await;
                assert!(matches!(push.unwrap_err(), mls::session::Error::CredentialConflict));
            })
            .await
        }
    }
}
