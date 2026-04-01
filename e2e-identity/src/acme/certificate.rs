use rusty_jwt_tools::prelude::{JwsAlgorithm, Pem};
use x509_cert::{Certificate, der::Decode as _};

use crate::acme::{AcmeAccount, AcmeFinalize, AcmeJws, AcmeOrder, RustyAcme, RustyAcmeResult};

impl RustyAcme {
    /// For fetching the generated certificate
    /// see [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
    pub fn certificate_req(
        finalize: &AcmeFinalize,
        account: &AcmeAccount,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        // Extract the account URL from previous response which created a new account
        let acct_url = account.acct_url()?;

        // No payload required for getting a certificate
        let payload = None::<serde_json::Value>;
        let req = AcmeJws::new(alg, previous_nonce, &finalize.certificate, Some(&acct_url), payload, kp)?;
        Ok(req)
    }

    /// see [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
    pub fn certificate_response(response: String, order: AcmeOrder) -> RustyAcmeResult<Vec<Certificate>> {
        order.verify()?;
        let pems: Vec<pem::Pem> = pem::parse_many(response)?;
        let mut certs = Vec::with_capacity(pems.len());
        for pem in pems {
            certs.push(Certificate::from_der(pem.contents())?);
        }
        Ok(certs)
    }
}
