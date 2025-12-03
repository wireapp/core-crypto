use crate::acme::prelude::*;

impl RustyAcme {
    /// First, call the directory endpoint `GET /acme/{provisioner_name}/directory`.
    /// Then pass the response to this method to deserialize it
    /// see [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
    pub fn acme_directory_response(response: serde_json::Value) -> RustyAcmeResult<AcmeDirectory> {
        let directory = serde_json::from_value::<AcmeDirectory>(response)
            .map_err(|_| RustyAcmeError::SmallstepImplementationError("Invalid directory response"))?;
        Ok(directory)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
pub struct AcmeDirectory {
    /// URL for fetching the initial nonce used to create an account
    pub new_nonce: url::Url,
    /// URL for creating an account
    pub new_account: url::Url,
    /// URL for creating an order
    pub new_order: url::Url,
    /// URL for revoking a certificate
    pub revoke_cert: url::Url,
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn can_deserialize_rfc_sample() {
        let rfc_sample = serde_json::json!({
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
            "newAuthz": "https://example.com/acme/new-authz",
            "revokeCert": "https://example.com/acme/revoke-cert",
            "keyChange": "https://example.com/acme/key-change",
            "meta": {
                "termsOfService": "https://example.com/acme/terms/2017-5-30",
                "website": "https://www.example.com/",
                "caaIdentities": ["example.com"],
                "externalAccountRequired": false
            }
        });
        assert!(serde_json::from_value::<AcmeDirectory>(rfc_sample).is_ok());
    }
}
