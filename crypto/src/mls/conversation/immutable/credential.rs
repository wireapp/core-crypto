use std::{collections::HashMap, sync::Arc};

use openmls::prelude::{Credential as MlsCredential, CredentialWithKey, SignaturePublicKey};

use super::{Error, Result};
use crate::{ClientId, Credential, RecursiveError, mls::conversation::group_metadata};

impl super::Conversation {
    /// Find the current leaf node, then load it scredential.
    pub(crate) async fn find_current_credential(&self) -> Result<Arc<Credential>> {
        // if the group has pending proposals one of which is an own update proposal, we should take the credential from
        // there.
        let group = self.group().await;
        let own_leaf =
            group_metadata::current_own_leaf(&group).ok_or(Error::MlsGroupInvalidState("own leaf node not found"))?;
        let credential = self
            .session
            .load_credential(own_leaf.signature_key(), own_leaf.credential().credential_type())
            .await
            .map_err(RecursiveError::context("finding current credential"))?;
        Ok(credential)
    }

    /// Returns all members credentials from the group/conversation
    pub async fn members(&self) -> HashMap<Vec<u8>, MlsCredential> {
        // this fold is the compact way to express this:
        // a normal `.map().collect()` would preserve later instances of duplicated keys,
        // but this preserves the first instance of each key
        self.group().await.members().fold(HashMap::new(), |mut acc, kp| {
            let credential = kp.credential;
            let id = credential.identity().to_vec();
            acc.entry(id).or_insert(credential);
            acc
        })
    }

    /// Returns all members credentials with their signature public key from the group/conversation
    pub async fn members_with_key(&self) -> Result<HashMap<ClientId, CredentialWithKey>> {
        self.group()
            .await
            .members()
            .map(|member| {
                let credential = member.credential;
                let id: ClientId = credential
                    .identity()
                    .try_into()
                    .map_err(RecursiveError::context("client id from bytes"))?;

                let credential = CredentialWithKey {
                    credential,
                    signature_key: SignaturePublicKey::from(member.signature_key),
                };

                Ok((id, credential))
            })
            .collect()
    }

    pub(crate) async fn own_mls_credential(&self) -> Result<MlsCredential> {
        let credential = self
            .group()
            .await
            .own_leaf_node()
            .ok_or(Error::MlsGroupInvalidState("own_leaf_node not present in group"))?
            .credential()
            .to_owned();
        Ok(credential)
    }
}
