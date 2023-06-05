use openmls::credentials::MlsCredentialType;

use crate::{prelude::MlsConversation, CryptoError, CryptoResult};
use openmls::prelude::Credential;

/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
#[derive(Debug, Clone)]
pub struct WireIdentity {
    /// Unique client identifier e.g. `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ:6add501bacd1d90e@whitehouse.gov`
    pub client_id: String,
    /// user handle e.g. `john_wire`
    pub handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    pub display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    pub domain: String,
}

impl From<wire_e2e_identity::prelude::WireIdentity> for WireIdentity {
    fn from(i: wire_e2e_identity::prelude::WireIdentity) -> Self {
        Self {
            client_id: i.client_id,
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
        }
    }
}

impl MlsConversation {
    pub(crate) fn extract_identity(credential: &Credential) -> CryptoResult<Option<WireIdentity>> {
        match credential.mls_credential() {
            MlsCredentialType::X509(openmls::prelude::Certificate { cert_data, .. }) => {
                let leaf = cert_data.get(0).ok_or(CryptoError::InvalidIdentity)?;
                use wire_e2e_identity::prelude::WireIdentityReader as _;
                let identity = leaf
                    .as_slice()
                    .extract_identity()
                    .map_err(|_| CryptoError::InvalidIdentity)?;
                Ok(Some(identity.into()))
            }
            _ => Ok(None),
        }
    }
}
