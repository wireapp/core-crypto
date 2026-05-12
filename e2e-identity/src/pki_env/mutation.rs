//! Mutating operations on the PKI Environment

use certval::{CertSource, CertVector as _, CertificationPathSettings, TaSource};
use core_crypto_keystore::entities::{E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert};
use x509_cert::{Certificate, der::Encode as _};

use crate::{
    pki_env::{Error, PkiEnvironment, Result},
    x509_check::{extract_crl_uris, revocation::PkiEnvironment as RjtPkiEnvironment},
};

impl PkiEnvironment {
    /// Validate the CRL (trust anchors must be configured prior to this) and
    /// save it to the database.
    pub(crate) async fn save_crl(&self, crl_dp: &str, crl_der: &[u8]) -> Result<()> {
        let crl = self.rjt_pki_env.lock().await.validate_crl_with_raw(crl_der)?;
        let crl_data = E2eiCrl {
            content: RjtPkiEnvironment::encode_crl_to_der(&crl)?,
            distribution_point: crl_dp.to_owned(),
        };
        self.database.save(crl_data).await.map_err(Into::into)
    }

    /// Adds the certificate as a trust anchor to the PKI environment.
    ///
    /// The certificate is saved to the database, and included in the PKI environment for
    /// future validation.
    pub(crate) async fn add_trust_anchor(&self, name: &str, cert: Certificate) -> Result<()> {
        // Validate it (expiration & signature only)
        self.rjt_pki_env.lock().await.validate_trust_anchor_cert(&cert)?;

        // Save cert's DER representation to the database
        let cert_data = E2eiAcmeCA {
            content: cert.to_der()?,
        };

        self.database.save(cert_data).await?;

        let mut trust_anchors = TaSource::new();
        trust_anchors.push(certval::CertFile {
            filename: name.to_owned(),
            bytes: cert.to_der()?,
        });
        trust_anchors.initialize().map_err(Error::Certval)?;
        self.rjt_pki_env
            .lock()
            .await
            .add_trust_anchor_source(Box::new(trust_anchors));
        Ok(())
    }

    /// Adds the certificate to the PKI environment.
    ///
    /// The certificate is saved to the database, and included in the PKI environment for
    /// future validation.
    ///
    /// CRL (Certificate Revocation List) distribution points are extracted from the certificate and
    /// an attempt is made to fetch a CRL from each one.
    pub(crate) async fn add_intermediate_cert(&self, name: &str, cert: Certificate) -> Result<()> {
        // Save cert's DER representation to the database
        let (ski, aki) = RjtPkiEnvironment::extract_ski_aki_from_cert(&cert)?;
        let ski_aki_pair = format!("{ski}:{}", aki.unwrap_or_default());
        let cert_der = RjtPkiEnvironment::encode_cert_to_der(&cert)?;
        let intermediate_cert = E2eiIntermediateCert {
            content: cert_der,
            ski_aki_pair,
        };

        self.database.save(intermediate_cert).await?;

        // Get CRL distribution points and CRLs
        let dps: Vec<String> = extract_crl_uris(&cert)?.iter().flatten().cloned().collect();
        let crls = self.fetch_crls(dps.iter().map(AsRef::as_ref)).await?;

        // Save all CRLs to the database
        for (distribution_point, crl) in &crls {
            self.save_crl(distribution_point, crl).await?;
        }

        let cps = CertificationPathSettings::new();
        let mut cert_source = CertSource::new();
        cert_source.push(certval::CertFile {
            filename: name.to_owned(),
            bytes: cert.to_der()?,
        });

        cert_source.initialize(&cps).map_err(Error::Certval)?;
        self.rjt_pki_env
            .lock()
            .await
            .add_certificate_source(Box::new(cert_source));

        Ok(())
    }
}
