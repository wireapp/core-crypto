use std::collections::HashMap;

use core_crypto_keystore::entities::E2eiCrl;

use super::{Error, Result};
use crate::{
    pki_env::{PkiEnvironment, hooks::HttpMethod},
    x509_check::revocation::PkiEnvironment as RjtPkiEnvironment,
};

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

    /// Validate the CRL (trust anchors must be configured prior to this) and
    /// save it to the database.
    pub async fn save_crl(&mut self, crl_dp: &str, crl_der: &[u8]) -> Result<()> {
        let crl = self.rjt_pki_env.validate_crl_with_raw(crl_der)?;
        let crl_data = E2eiCrl {
            content: RjtPkiEnvironment::encode_crl_to_der(&crl)?,
            distribution_point: crl_dp.to_owned(),
        };
        self.database.save(crl_data).await.map_err(Into::into)
    }
}
