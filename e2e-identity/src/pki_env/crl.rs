use std::collections::HashMap;

use super::{Error, Result};
use crate::pki_env::{PkiEnvironment, hooks::HttpMethod};

impl PkiEnvironment {
    /// Fetch certificate revocation lists from the given URIs, return a map from the URLs to a DER-encoded certificate
    /// list.
    pub async fn fetch_crls(&self, uris: impl Iterator<Item = &str>) -> Result<HashMap<String, Vec<u8>>> {
        let mut crls = HashMap::with_capacity(uris.size_hint().0);

        for uri in uris {
            let uri = uri.to_owned();
            let response = self
                .hooks
                .http_request(HttpMethod::Get, uri.clone(), vec![], vec![])
                .await?;
            if !(200..300).contains(&response.status) {
                return Err(Error::CrlFetchUnsuccessful {
                    uri,
                    status: response.status,
                });
            }

            crls.insert(uri, response.body);
        }

        Ok(crls)
    }
}
