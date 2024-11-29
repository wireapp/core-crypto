use crate::mls::client::{
    error::{Error, Result},
    ClientInner,
};
use crate::{
    mls::credential::{typ::MlsCredentialType, CredentialBundle},
    prelude::{Client, CryptoError, MlsConversation},
};
use openmls::prelude::{Credential, SignaturePublicKey};
use openmls_traits::types::SignatureScheme;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

/// In memory Map of a Client's identities: one per SignatureScheme.
/// We need `indexmap::IndexSet` because each `CredentialBundle` has to be unique and insertion
/// order matters in order to keep values sorted by time `created_at` so that we can identify most recent ones.
///
/// We keep each credential bundle inside an arc to avoid cloning them, as X509 credentials can get quite large.
#[derive(Debug, Clone)]
pub(crate) struct ClientIdentities(HashMap<SignatureScheme, indexmap::IndexSet<Arc<CredentialBundle>>>);

impl ClientIdentities {
    pub(crate) fn new(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    pub(crate) async fn find_credential_bundle_by_public_key(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
        pk: &SignaturePublicKey,
    ) -> Option<Arc<CredentialBundle>> {
        self.0
            .get(&sc)?
            .iter()
            .find(|c| {
                let ct_match = ct == c.credential.credential_type().into();
                let pk_match = c.signature_key.public() == pk.as_slice();
                ct_match && pk_match
            })
            .cloned()
    }

    pub(crate) async fn find_most_recent_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Option<Arc<CredentialBundle>> {
        self.0
            .get(&sc)?
            .iter()
            .rfind(|c| ct == c.credential.credential_type().into())
            .cloned()
    }

    /// Having `cb` requiring ownership kinda forces the caller to first persist it in the keystore and
    /// only then store it in this in-memory map
    pub(crate) async fn push_credential_bundle(&mut self, sc: SignatureScheme, cb: CredentialBundle) -> Result<()> {
        // this would mean we have messed something up and that we do no init this CredentialBundle from a keypair just inserted in the keystore
        debug_assert_ne!(cb.created_at, 0);

        match self.0.get_mut(&sc) {
            Some(cbs) => {
                let already_exists = !cbs.insert(Arc::new(cb));
                if already_exists {
                    return Err(Error::CredentialBundleConflict);
                }
            }
            None => {
                self.0.insert(sc, indexmap::IndexSet::from([Arc::new(cb)]));
            }
        }
        Ok(())
    }

    pub(crate) async fn remove(&mut self, credential: &Credential) -> Result<()> {
        self.0.iter_mut().for_each(|(_, cbs)| {
            cbs.retain(|c| c.credential() != credential);
        });
        Ok(())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (SignatureScheme, Arc<CredentialBundle>)> + '_ {
        self.0.iter().flat_map(|(sc, cb)| cb.iter().map(|c| (*sc, c.clone())))
    }
}

impl MlsConversation {
    pub(crate) async fn find_current_credential_bundle(&self, client: &Client) -> Result<Arc<CredentialBundle>> {
        let own_leaf = self.group.own_leaf().ok_or(CryptoError::InternalMlsError)?;
        let sc = self.ciphersuite().signature_algorithm();
        let ct = self
            .own_credential_type()
            .map_err(Error::conversation("getting own credential type"))?;

        client
            .find_credential_bundle_by_public_key(sc, ct, own_leaf.signature_key())
            .await
    }

    pub(crate) async fn find_most_recent_credential_bundle(&self, client: &Client) -> Result<Arc<CredentialBundle>> {
        let sc = self.ciphersuite().signature_algorithm();
        let ct = self
            .own_credential_type()
            .map_err(Error::conversation("getting own credential type"))?;

        client.find_most_recent_credential_bundle(sc, ct).await
    }
}

impl Client {
    pub(crate) async fn find_most_recent_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Result<Arc<CredentialBundle>> {
        match self.state.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(ClientInner { identities, .. }) => identities
                .find_most_recent_credential_bundle(sc, ct)
                .await
                .ok_or(Error::CredentialNotFound(ct)),
        }
    }

    pub(crate) async fn find_credential_bundle_by_public_key(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
        pk: &SignaturePublicKey,
    ) -> Result<Arc<CredentialBundle>> {
        match self.state.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(ClientInner { identities, .. }) => identities
                .find_credential_bundle_by_public_key(sc, ct, pk)
                .await
                .ok_or(Error::CredentialNotFound(ct)),
        }
    }

    #[cfg(test)]
    pub(crate) async fn identities_count(&self) -> Result<usize> {
        match self.state.read().await.deref() {
            None => Err(Error::MlsNotInitialized),
            Some(ClientInner { identities, .. }) => Ok(identities.iter().count()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;
    use openmls::prelude::SignaturePublicKey;
    use rand::Rng;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod find {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_find_most_recent(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut central]| {
                Box::pin(async move {
                    let cert = central.get_intermediate_ca().cloned();
                    let old = central.new_credential_bundle(&case, cert.as_ref()).await;

                    // wait to make sure we're not in the same second
                    async_std::task::sleep(core::time::Duration::from_secs(1)).await;

                    let new = central.new_credential_bundle(&case, cert.as_ref()).await;
                    assert_ne!(old, new);

                    let found = central
                        .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
                        .await
                        .unwrap();
                    assert_eq!(found.as_ref(), &new);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_find_by_public_key(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut central]| {
                Box::pin(async move {
                    const N: usize = 50;

                    let r = rand::thread_rng().gen_range(0..N);
                    let mut to_search = None;
                    for i in 0..N {
                        let cert = central.get_intermediate_ca().cloned();
                        let cb = central.new_credential_bundle(&case, cert.as_ref()).await;
                        if i == r {
                            to_search = Some(cb.clone());
                        }
                    }
                    let to_search = to_search.unwrap();
                    let pk = SignaturePublicKey::from(to_search.signature_key.public());
                    let client = central.context.mls_client().await.unwrap();
                    let found = client
                        .find_credential_bundle_by_public_key(case.signature_scheme(), case.credential_type, &pk)
                        .await
                        .unwrap();
                    assert_eq!(&to_search, found.as_ref());
                })
            })
            .await
        }
    }

    mod push {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_add_credential(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut central]| {
                Box::pin(async move {
                    let client = central.client().await;
                    let prev_count = client.identities_count().await.unwrap();
                    let cert = central.get_intermediate_ca().cloned();
                    // this calls 'push_credential_bundle' under the hood
                    central.new_credential_bundle(&case, cert.as_ref()).await;
                    let next_count = client.identities_count().await.unwrap();
                    assert_eq!(next_count, prev_count + 1);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn pushing_duplicates_should_fail(case: TestCase) {
            use crate::mls::client::error::Error;
            use crate::CryptoError;

            run_test_with_client_ids(case.clone(), ["alice"], move |[mut central]| {
                Box::pin(async move {
                    let cert = central.get_intermediate_ca().cloned();
                    let cb = central.new_credential_bundle(&case, cert.as_ref()).await;
                    let client = central.context.mls_client().await.unwrap();
                    let push = client
                        .save_identity(
                            &central.context.keystore().await.unwrap(),
                            None,
                            case.signature_scheme(),
                            cb,
                        )
                        .await;
                    assert!(matches!(push.unwrap_err(), Error::CryptoError(boxed) if matches!(*boxed, CryptoError::CredentialBundleConflict)));
                })
            })
            .await
        }
    }
}
