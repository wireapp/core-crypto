#![cfg(test)]

use crate::prelude::MlsConversationConfiguration;
use crate::test_utils::x509::{new_self_signed_certificate, CertificateParams};
use crate::test_utils::TestCase;
use x509_cert::der::pem::LineEnding;
use x509_cert::der::EncodePem;

pub const ROOT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIIBdicm6yCejUwCgYIKoZIzj0EAwIwLzEaMBgGA1UECgwR
UHJvamVjdCBaZXRhIEdtQmgxETAPBgNVBAMMCHdpcmUuY29tMB4XDTIzMDkyMTA4
MzE1NVoXDTIzMDkyMTA4MzIxNVowLzEaMBgGA1UECgwRUHJvamVjdCBaZXRhIEdt
QmgxETAPBgNVBAMMCHdpcmUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
CE40oN4M9T9ZcXDB+gmEcTXZNr34qcDZ6aCA2rxT2Wv9w16cYH7c1wPd2SyBFMLU
9Tgc1e7BeTp2CJOfcwEx1aNHMEUwEwYDVR0RBAwwCoIId2lyZS5jb20wHQYDVR0O
BBYEFDV6gqybnNgF1NuVnCFhwAeKwsnvMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDSAAwRQIhAJeINR1DUUU57slK/zr+ERDGiBdj2//XhMcUGHMmYNdwAiAV
Nb+z2F1DosAftchaLpBrfAw3qQPnKova7907uUXH7g==
-----END CERTIFICATE-----"#;

#[test]
fn generate_root() {
    let case = TestCase {
        cfg: MlsConversationConfiguration {
            ciphersuite: openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let cert = new_self_signed_certificate(CertificateParams::default(), case.signature_scheme(), true);
    let pem = cert.to_pem(LineEnding::CRLF).unwrap();
    println!("{}", pem);
}
