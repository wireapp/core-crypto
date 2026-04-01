use rusty_jwt_tools::prelude::{ClientId, HashAlgorithm, QualifiedHandle};
use x509_cert::der::Decode as _;

use crate::{
    acme::{RustyAcmeResult, error::CertificateError},
    x509_check::{IdentityStatus, revocation::PkiEnvironment},
};

pub(crate) mod thumbprint;

#[derive(Debug, Clone)]
pub struct WireIdentity {
    pub client_id: String,
    pub handle: QualifiedHandle,
    pub display_name: String,
    pub domain: String,
    pub status: IdentityStatus,
    pub thumbprint: String,
    pub serial_number: String,
    pub not_before: u64,
    pub not_after: u64,
}

pub trait WireIdentityReader {
    /// Verifies a proof of identity, may it be a x509 certificate (or a Verifiable Presentation (later)).
    /// We do not verify anything else e.g. expiry, it is left to MLS implementation
    fn extract_identity(&self, env: Option<&PkiEnvironment>, hash_alg: HashAlgorithm) -> RustyAcmeResult<WireIdentity>;

    /// returns the 'Not Before' claim which usually matches the creation timestamp
    fn extract_created_at(&self) -> RustyAcmeResult<u64>;

    /// returns the 'Subject Public Key Info' claim
    fn extract_public_key(&self) -> RustyAcmeResult<Vec<u8>>;
}

impl WireIdentityReader for x509_cert::Certificate {
    fn extract_identity(&self, env: Option<&PkiEnvironment>, hash_alg: HashAlgorithm) -> RustyAcmeResult<WireIdentity> {
        let serial_number = hex::encode(self.tbs_certificate.serial_number.as_bytes());
        let not_before = self.tbs_certificate.validity.not_before.to_unix_duration().as_secs();
        let not_after = self.tbs_certificate.validity.not_after.to_unix_duration().as_secs();
        let (client_id, handle) = try_extract_san(&self.tbs_certificate)?;
        let (display_name, domain) = try_extract_subject(&self.tbs_certificate)?;
        let status = IdentityStatus::from_cert(self, env);
        let thumbprint = thumbprint::try_compute_jwk_canonicalized_thumbprint(&self.tbs_certificate, hash_alg)?;

        Ok(WireIdentity {
            client_id,
            handle,
            display_name,
            domain,
            status,
            thumbprint,
            serial_number,
            not_before,
            not_after,
        })
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        Ok(self.tbs_certificate.validity.not_before.to_unix_duration().as_secs())
    }

    fn extract_public_key(&self) -> RustyAcmeResult<Vec<u8>> {
        Ok(self
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec())
    }
}

impl WireIdentityReader for &[u8] {
    fn extract_identity(&self, env: Option<&PkiEnvironment>, hash_alg: HashAlgorithm) -> RustyAcmeResult<WireIdentity> {
        x509_cert::Certificate::from_der(self)?.extract_identity(env, hash_alg)
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        x509_cert::Certificate::from_der(self)?.extract_created_at()
    }

    fn extract_public_key(&self) -> RustyAcmeResult<Vec<u8>> {
        x509_cert::Certificate::from_der(self)?.extract_public_key()
    }
}

impl WireIdentityReader for Vec<u8> {
    fn extract_identity(&self, env: Option<&PkiEnvironment>, hash_alg: HashAlgorithm) -> RustyAcmeResult<WireIdentity> {
        self.as_slice().extract_identity(env, hash_alg)
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        self.as_slice().extract_created_at()
    }

    fn extract_public_key(&self) -> RustyAcmeResult<Vec<u8>> {
        self.as_slice().extract_public_key()
    }
}

fn try_extract_subject(cert: &x509_cert::TbsCertificate) -> RustyAcmeResult<(String, String)> {
    let mut display_name = None;
    let mut domain = None;

    let mut subjects = cert.subject.0.iter().flat_map(|n| n.0.iter());
    subjects.try_for_each(|s| -> RustyAcmeResult<()> {
        match s.oid {
            const_oid::db::rfc4519::ORGANIZATION_NAME => {
                domain = Some(std::str::from_utf8(s.value.value())?);
            }
            const_oid::db::rfc4519::COMMON_NAME => {
                display_name = Some(std::str::from_utf8(s.value.value())?);
            }
            _ => {}
        }

        Ok(())
    })?;
    let display_name = display_name.ok_or(CertificateError::MissingDisplayName)?.to_string();
    let domain = domain.ok_or(CertificateError::MissingDomain)?.to_string();
    Ok((display_name, domain))
}

/// extract Subject Alternative Name to pick client-id & display name
fn try_extract_san(cert: &x509_cert::TbsCertificate) -> RustyAcmeResult<(String, QualifiedHandle)> {
    let extensions = cert.extensions.as_ref().ok_or(CertificateError::InvalidFormat)?;

    let san = extensions
        .iter()
        .find_map(|e| {
            (e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
                .then(|| x509_cert::ext::pkix::SubjectAltName::from_der(e.extn_value.as_bytes()))
        })
        .transpose()?
        .ok_or(CertificateError::InvalidFormat)?;

    let mut client_id = None;
    let mut handle = None;
    san.0
        .iter()
        .filter_map(|n| match n {
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(ia5_str) => Some(ia5_str.as_str()),
            _ => None,
        })
        .try_for_each(|name| -> RustyAcmeResult<()> {
            // since both ClientId & handle are in the SAN we first try to parse the element as
            // a ClientId (since it's the most characterizable) and else fallback to a handle
            if let Ok(cid) = ClientId::try_from_uri(name) {
                client_id = Some(cid.to_qualified());
            } else if let Ok(h) = name.parse::<QualifiedHandle>() {
                handle = Some(h);
            }
            Ok(())
        })?;

    let client_id = client_id.ok_or(CertificateError::MissingClientId)?;
    let handle = handle.ok_or(CertificateError::MissingHandle)?;
    Ok((client_id, handle))
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;
    use crate::x509_check::revocation::PkiEnvironmentParams;

    wasm_bindgen_test_configure!(run_in_browser);

    const CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAJaZdl+hZDl9qSSju5kmWNAwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMTA1MTQ1MzAyWhcNMzQwMTAyMTQ1MzAyWjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQChy/GdWnVyNKWvsB+D
BoxYb+qpVN9QIBXeYdmp1hobOqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFOM5yRKA3dHSlYnjEzcuWoiMWm+TMB8G
A1UdIwQYMBaAFBP7HtkE3WdbqzE6Ll4aIB2jFM2LMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vb2Jha2pQT0hR
MkNrTmIwck9yTk0zQSUyMWJhNTRlOGFjZThiNGM5MGRAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIDRaadkt
pPSLrZ+qy07VJOhE/ypOS6oDItpaq/HPxoTUAiEA7EKzmAFv+/zIEA7lAZjNJ+x4
dHnOydGcC6TZ9zo0pIM=
-----END CERTIFICATE-----"#;

    const CERT_EXPIRED: &str = r#"-----BEGIN CERTIFICATE-----
MIICGTCCAb+gAwIBAgIQb84UE+pSF517knYRMfo5ozAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
NDAxMDUxNDUxMjVaFw0yNDAxMDUxNDU0MjVaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAAbao8C3jBq8DxniGYmO
lq6W1tlkNeRMs8aQ3SvIKMR3o4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUwTyA2moMyOKoHgJ8Y+dJezNuO8gwHwYD
VR0jBBgwFoAUC7y0skJjTvA8UA3bHr1JoAzOxqgwaQYDVR0RBGIwYIYgd2lyZWFw
cDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9OQjNjVnJRZFNi
Ni1Dd2tmQWljUnpnJTIxNWNkNGViYjFmNzU0ODA5ZUB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIgfwfd5vXm
EoOKgYLyKNa24aewZZObydD+k0hFs4iKddICIQDf70uv+h0tHw/WNf15mZ8NGkJm
OfqfZA1YMtN5NLz/AA==
-----END CERTIFICATE-----"#;

    #[test]
    #[wasm_bindgen_test]
    fn should_find_claims_in_x509() {
        let cert_der = pem::parse(CERT).unwrap();
        let identity = cert_der
            .contents()
            .extract_identity(None, HashAlgorithm::SHA256)
            .unwrap();

        assert_eq!(&identity.client_id, "obakjPOHQ2CkNb0rOrNM3A:ba54e8ace8b4c90d@wire.com");
        assert_eq!(identity.handle.as_str(), "wireapp://%40alice_wire@wire.com");
        assert_eq!(&identity.display_name, "Alice Smith");
        assert_eq!(&identity.domain, "wire.com");
        assert_eq!(&identity.serial_number, "009699765fa164397da924a3bb992658d0");
        assert_eq!(identity.not_before, 1704466382);
        assert_eq!(identity.not_after, 2019826382);
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_find_created_at_claim() {
        let cert_der = pem::parse(CERT).unwrap();
        let created_at = cert_der.contents().extract_created_at().unwrap();
        assert_eq!(created_at, 1704466382);
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_find_public_key() {
        let cert_der = pem::parse(CERT).unwrap();
        let spki = cert_der.contents().extract_public_key().unwrap();
        assert_eq!(
            hex::encode(spki),
            "a1cbf19d5a757234a5afb01f83068c586feaa954df502015de61d9a9d61a1b3a"
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_have_valid_status() {
        let cert_der = pem::parse(CERT).unwrap();
        let identity = cert_der
            .contents()
            .extract_identity(None, HashAlgorithm::SHA256)
            .unwrap();
        assert_eq!(&identity.status, &IdentityStatus::Valid);

        let cert_der = pem::parse(CERT_EXPIRED).unwrap();
        let mut env = PkiEnvironment::init(PkiEnvironmentParams::default()).unwrap();
        env.refresh_time_of_interest().unwrap();
        let identity = cert_der
            .contents()
            .extract_identity(Some(&env), HashAlgorithm::SHA256)
            .unwrap();
        assert_eq!(&identity.status, &IdentityStatus::Expired);
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_have_thumbprint() {
        let cert_der = pem::parse(CERT).unwrap();
        let identity = cert_der
            .contents()
            .extract_identity(None, HashAlgorithm::SHA256)
            .unwrap();
        assert!(!identity.thumbprint.is_empty());
    }
}
