use crate::acme::{Error, Result};

/// First, call the directory endpoint `GET /acme/{provisioner_name}/directory`.
/// Then pass the response to this method to deserialize it
/// see [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
pub(crate) fn acme_directory_response(response: serde_json::Value) -> Result<AcmeDirectory> {
    let directory = serde_json::from_value::<AcmeDirectory>(response)
        .map_err(|_| Error::SmallstepImplementationError("Invalid directory response"))?;
    Ok(directory)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
pub(crate) struct AcmeDirectory {
    /// URL for fetching the initial nonce used to create an account
    pub new_nonce: url::Url,
    /// URL for creating an account
    pub new_account: url::Url,
    /// URL for creating an order
    pub new_order: url::Url,
    /// URL for revoking a certificate
    pub revoke_cert: url::Url,
}
