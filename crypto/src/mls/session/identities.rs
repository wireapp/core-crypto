use std::{collections::HashMap, sync::Arc};

use openmls::prelude::Credential as MlsCredential;
use openmls_traits::types::SignatureScheme;

use crate::{Credential, Session};

/// Each session has a set of credentials per signature scheme: they can have various properties, but typically
/// we want to find the most recent of a particular type.
///
/// We use this data structure to make that easy. The outer map filters by signature scheme. The inner set lets us
/// quickly find the most recent.
///
/// This depends on the fact that in `Credential`'s `Ord` impl, the first comparison is by the credential's
/// `earliest_validity`. However, by structuring things like this, we do not need to care about insertion order.
///
/// We keep each credential inside an arc to avoid cloning them, as X509 credentials can get quite large.
#[derive(Debug, Clone)]
pub struct Identities {
    // u16 because `CredentialType: !Hash` for Reasons
    credentials: HashMap<(SignatureScheme, u16), Vec<Arc<Credential>>>,
}

impl Identities {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            credentials: HashMap::with_capacity(capacity),
        }
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
    pub(crate) async fn identities_count(&self) -> usize {
        let guard = self.identities.read().await;
        guard.iter().count()
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

                let found = client.find_credential_by_public_key(&pk).await.unwrap();

                assert_eq!(to_search, found);
            })
            .await
        }
    }
}
