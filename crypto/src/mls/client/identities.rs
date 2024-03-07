use crate::{
    mls::credential::{typ::MlsCredentialType, CredentialBundle},
    prelude::{Client, CryptoError, CryptoResult, MlsConversation},
};
use openmls::prelude::{Credential, SignaturePublicKey};
use openmls_traits::types::SignatureScheme;
use std::collections::HashMap;

/// In memory Map of a Client's identities: one per SignatureScheme.
/// We need `indexmap::IndexSet` because each `CredentialBundle` has to be unique and insertion
/// order matters in order to keep values sorted by time `created_at` so that we can identify most recent ones.
#[derive(Debug, Clone)]
pub(crate) struct ClientIdentities(HashMap<SignatureScheme, indexmap::IndexSet<CredentialBundle>>);

impl ClientIdentities {
    pub(crate) fn new(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    pub(crate) fn find_credential_bundle_by_public_key(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
        pk: &SignaturePublicKey,
    ) -> Option<&CredentialBundle> {
        self.0.get(&sc)?.iter().find(|c| {
            let ct_match = ct == c.credential.credential_type().into();
            let pk_match = c.signature_key.public() == pk.as_slice();
            ct_match && pk_match
        })
    }

    pub(crate) fn find_most_recent_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Option<&CredentialBundle> {
        self.0
            .get(&sc)?
            .iter()
            .rfind(|c| ct == c.credential.credential_type().into())
    }

    /// Having `cb` requiring ownership kinda forces the caller to first persist it in the keystore and
    /// only then store it in this in-memory map
    pub(crate) fn push_credential_bundle(&mut self, sc: SignatureScheme, cb: CredentialBundle) -> CryptoResult<()> {
        // this would mean we have messed something up and that we do no init this CredentialBundle from a keypair just inserted in the keystore
        debug_assert_ne!(cb.created_at, 0);

        match self.0.get_mut(&sc) {
            Some(cbs) => {
                let already_exists = !cbs.insert(cb);
                if already_exists {
                    return Err(CryptoError::CredentialBundleConflict);
                }
            }
            None => {
                self.0.insert(sc, indexmap::IndexSet::from([cb]));
            }
        }
        Ok(())
    }

    pub(crate) fn remove(&mut self, credential: &Credential) -> CryptoResult<()> {
        self.0.iter_mut().for_each(|(_, cbs)| {
            cbs.retain(|c| c.credential() != credential);
        });
        Ok(())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (SignatureScheme, &CredentialBundle)> {
        self.0.iter().flat_map(|(sc, cb)| cb.iter().map(|c| (*sc, c)))
    }
}

impl MlsConversation {
    pub(crate) fn find_current_credential_bundle<'a>(
        &self,
        client: &'a Client,
    ) -> CryptoResult<Option<&'a CredentialBundle>> {
        let own_leaf = self.group.own_leaf().ok_or(CryptoError::InternalMlsError)?;
        let sc = self.ciphersuite().signature_algorithm();
        let ct = self.own_credential_type()?;

        Ok(client
            .identities
            .find_credential_bundle_by_public_key(sc, ct, own_leaf.signature_key()))
    }

    pub(crate) fn find_most_recent_credential_bundle<'a>(
        &self,
        client: &'a Client,
    ) -> CryptoResult<Option<&'a CredentialBundle>> {
        let sc = self.ciphersuite().signature_algorithm();
        let ct = self.own_credential_type()?;

        Ok(client.identities.find_most_recent_credential_bundle(sc, ct))
    }
}

impl Client {
    pub(crate) fn find_most_recent_credential_bundle(
        &self,
        sc: SignatureScheme,
        ct: MlsCredentialType,
    ) -> Option<&CredentialBundle> {
        self.identities.find_most_recent_credential_bundle(sc, ct)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::test_utils::*;
    use openmls::prelude::SignaturePublicKey;
    use rand::Rng;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod find {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_find_most_recent(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut central]| {
                Box::pin(async move {
                    let old = central
                        .mls_central
                        .new_credential_bundle(
                            &case,
                            central
                                .x509_test_chain
                                .as_ref()
                                .as_ref()
                                .map(|chain| chain.find_local_intermediate_ca()),
                        )
                        .await;

                    // wait to make sure we're not in the same second
                    async_std::task::sleep(core::time::Duration::from_secs(1)).await;

                    let new = central
                        .mls_central
                        .new_credential_bundle(
                            &case,
                            central
                                .x509_test_chain
                                .as_ref()
                                .as_ref()
                                .map(|chain| chain.find_local_intermediate_ca()),
                        )
                        .await;
                    assert_ne!(old, new);

                    let found = central
                        .mls_central
                        .mls_client
                        .as_ref()
                        .unwrap()
                        .identities
                        .find_most_recent_credential_bundle(case.signature_scheme(), case.credential_type)
                        .unwrap();
                    assert_eq!(found, &new);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_find_by_public_key(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut central]| {
                Box::pin(async move {
                    const N: usize = 50;

                    let r = rand::thread_rng().gen_range(0..N);
                    let mut to_search = None;
                    for i in 0..N {
                        let cb = central
                            .mls_central
                            .new_credential_bundle(
                                &case,
                                central
                                    .x509_test_chain
                                    .as_ref()
                                    .as_ref()
                                    .map(|chain| chain.find_local_intermediate_ca()),
                            )
                            .await;
                        if i == r {
                            to_search = Some(cb.clone());
                        }
                    }
                    let to_search = to_search.unwrap();
                    let pk = SignaturePublicKey::from(to_search.signature_key.public());
                    let client = central.mls_central.mls_client.as_ref().unwrap();
                    let found = client
                        .identities
                        .find_credential_bundle_by_public_key(case.signature_scheme(), case.credential_type, &pk)
                        .unwrap();
                    assert_eq!(&to_search, found);
                })
            })
            .await
        }
    }

    pub mod push {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_add_credential(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut central]| {
                Box::pin(async move {
                    let prev_count = central
                        .mls_central
                        .mls_client
                        .as_ref()
                        .unwrap()
                        .identities
                        .iter()
                        .count();

                    // this calls 'push_credential_bundle' under the hood
                    central
                        .mls_central
                        .new_credential_bundle(
                            &case,
                            central
                                .x509_test_chain
                                .as_ref()
                                .as_ref()
                                .map(|chain| chain.find_local_intermediate_ca()),
                        )
                        .await;

                    let next_count = central
                        .mls_central
                        .mls_client
                        .as_ref()
                        .unwrap()
                        .identities
                        .iter()
                        .count();
                    assert_eq!(next_count, prev_count + 1);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn pushing_duplicates_should_fail(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut central]| {
                Box::pin(async move {
                    let cb = central
                        .mls_central
                        .new_credential_bundle(
                            &case,
                            central
                                .x509_test_chain
                                .as_ref()
                                .as_ref()
                                .map(|chain| chain.find_local_intermediate_ca()),
                        )
                        .await;
                    let client = central.mls_central.mls_client.as_mut().unwrap();
                    let push = client.identities.push_credential_bundle(case.signature_scheme(), cb);
                    assert!(matches!(
                        push.unwrap_err(),
                        crate::CryptoError::CredentialBundleConflict
                    ));
                })
            })
            .await
        }
    }
}
