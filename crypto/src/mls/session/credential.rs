use std::sync::Arc;

use openmls::prelude::{Credential as MlsCredential, SignaturePublicKey};

use super::Result;
use crate::{Credential, RecursiveError, Session};

impl Session {
    /// convenience function deferring to the implementation on the inner type
    pub(crate) async fn load_credential(
        &self,
        public_key: &SignaturePublicKey,
        mls_credential: &MlsCredential,
    ) -> Result<Arc<Credential>> {
        let credential = Credential::load(&self.database, public_key, mls_credential)
            .await
            .map_err(RecursiveError::context("getting credential by public key"))?;
        Ok(Arc::new(credential))
    }
}
