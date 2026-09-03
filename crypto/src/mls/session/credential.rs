use std::sync::Arc;

use openmls::prelude::{CredentialType, SignaturePublicKey};

use super::Result;
use crate::{Credential, RecursiveError, Session};

impl Session {
    /// convenience function deferring to the implementation on the inner type
    pub(crate) async fn load_credential(
        &self,
        public_key: &SignaturePublicKey,
        credential_type: CredentialType,
    ) -> Result<Arc<Credential>> {
        let credential = Credential::load(&self.database, public_key, credential_type)
            .await
            .map_err(RecursiveError::mls_credential("getting credential by public key"))?;
        Ok(Arc::new(credential))
    }
}
