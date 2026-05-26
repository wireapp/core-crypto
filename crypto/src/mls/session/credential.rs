use std::sync::Arc;

use openmls::prelude::SignaturePublicKey;

use super::Result;
use crate::{Credential, RecursiveError, Session};

impl Session {
    /// convenience function deferring to the implementation on the inner type
    pub(crate) async fn find_credential_by_public_key(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Arc<Credential>> {
        let credential = Credential::find_by_public_key(&self.database, public_key)
            .await
            .map_err(RecursiveError::mls_credential("getting credential by public key"))?;
        Ok(Arc::new(credential))
    }
}
