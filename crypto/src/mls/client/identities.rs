use crate::mls::credential::CredentialBundle;
use crate::{mls::credential::typ::MlsCredentialType, prelude::MlsCiphersuite, CryptoResult};
use std::collections::HashMap;
use strum::EnumCount as _;

#[derive(Debug, Clone)]
pub(crate) struct ClientIdentities(HashMap<MlsCiphersuite, Vec<CredentialBundle>>);

impl ClientIdentities {
    /// Maximal number of distinct [Ciphersuite ; CredentialBundle] this struct can hold
    pub(crate) const MAX_DISTINCT_SIZE: usize = MlsCiphersuite::SIZE * MlsCredentialType::COUNT;
    /// Because some identities can be duplicated while we are rotating them
    #[allow(dead_code)]
    pub(crate) const MAX_SIZE: usize = Self::MAX_DISTINCT_SIZE * 2;

    pub(crate) fn new(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    pub(crate) fn find_credential_bundle(
        &self,
        cs: MlsCiphersuite,
        ct: MlsCredentialType,
    ) -> Option<&CredentialBundle> {
        self.0.get(&cs)?.iter().find(|c| {
            matches!(
                (ct, &c.credential.credential_type()),
                (MlsCredentialType::Basic, openmls::prelude::CredentialType::Basic)
                    | (MlsCredentialType::X509, openmls::prelude::CredentialType::X509)
            )
        })
    }

    pub(crate) fn push_credential_bundle(&mut self, cs: MlsCiphersuite, cb: CredentialBundle) -> CryptoResult<()> {
        match self.0.get_mut(&cs) {
            Some(cbs) => {
                // TODO: review controls here since many CredentialBundle for the same Ciphersuite/CredentialType can coexist
                cbs.push(cb);
            }
            None => {
                self.0.insert(cs, vec![cb]);
            }
        }
        Ok(())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (MlsCiphersuite, &CredentialBundle)> {
        self.0.iter().flat_map(|(cs, cb)| cb.iter().map(|c| (*cs, c)))
    }
}

// TODO: this class will really come into action when we'll have to deal with credential rotation (evict unused credentials, manage simultaneity).
// Let's add a complete test suite when we'll have the whole picture
#[cfg(test)]
mod tests {
    // use wasm_bindgen_test::*;
    // use crate::test_utils::*;
    // wasm_bindgen_test_configure!(run_in_browser);
}
