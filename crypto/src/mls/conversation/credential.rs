use std::collections::HashMap;

use openmls::prelude::{Credential as MlsCredential, CredentialType, CredentialWithKey, SignaturePublicKey};

use super::{Error, Result};
use crate::MlsConversation;

impl MlsConversation {
    /// Returns all members credentials from the group/conversation
    pub fn members(&self) -> HashMap<Vec<u8>, MlsCredential> {
        self.group.members().fold(HashMap::new(), |mut acc, kp| {
            let credential = kp.credential;
            let id = credential.identity().to_vec();
            acc.entry(id).or_insert(credential);
            acc
        })
    }

    /// Returns all members credentials with their signature public key from the group/conversation
    pub fn members_with_key(&self) -> HashMap<Vec<u8>, CredentialWithKey> {
        self.group.members().fold(HashMap::new(), |mut acc, kp| {
            let credential = kp.credential;
            let id = credential.identity().to_vec();
            let signature_key = SignaturePublicKey::from(kp.signature_key);
            let credential = CredentialWithKey {
                credential,
                signature_key,
            };
            acc.entry(id).or_insert(credential);
            acc
        })
    }

    pub(crate) fn own_mls_credential(&self) -> Result<&MlsCredential> {
        let credential = self
            .group
            .own_leaf_node()
            .ok_or(Error::MlsGroupInvalidState("own_leaf_node not present in group"))?
            .credential();
        Ok(credential)
    }

    pub(crate) fn own_credential_type(&self) -> Result<CredentialType> {
        self.own_mls_credential().map(|credential| credential.credential_type())
    }
}
