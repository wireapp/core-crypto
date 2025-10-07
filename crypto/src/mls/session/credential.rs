use openmls::prelude::{CredentialType, SignatureScheme};

use super::Result;
use crate::{ClientId, Credential, RecursiveError, Session};

impl Session {
    /// Find all credentials which match the specified conditions.
    ///
    /// If no conditions are set, this is equivalent to [`get_credentials`].
    pub async fn find_credentials(
        &self,
        client_id: Option<&ClientId>,
        signature_scheme: Option<SignatureScheme>,
        credential_type: Option<CredentialType>,
    ) -> Result<Vec<Credential>> {
        let database = self.crypto_provider.keystore();
        Credential::find(&database, client_id, signature_scheme, credential_type)
            .await
            .map_err(RecursiveError::mls_credential("finding credentials"))
            .map_err(Into::into)
    }

    /// Get all credentials
    pub async fn get_credentials(&self) -> Result<Vec<Credential>> {
        let database = self.crypto_provider.keystore();
        Credential::get_all(&database)
            .await
            .map_err(RecursiveError::mls_credential("getting all credentials"))
            .map_err(Into::into)
    }
}
