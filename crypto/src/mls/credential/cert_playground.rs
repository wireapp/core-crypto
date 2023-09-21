#![cfg(test)]

use crate::prelude::MlsConversationConfiguration;
use crate::test_utils::x509::{new_certificate_chain, new_self_signed_certificate, CertificateParams};
use crate::test_utils::TestCase;
use rustls::client::ServerCertVerifier;
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Encode, EncodePem};

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
    let case = TestCase::default_for_trust_anchor();
    let cert = new_self_signed_certificate(CertificateParams::default(), case.signature_scheme(), true);
    let pem = cert.to_pem(LineEnding::CRLF).unwrap();
    println!("{}", pem);
}

#[test]
fn test_root() {
    let case = TestCase::default_for_trust_anchor();
    let mut chain = new_certificate_chain(CertificateParams::default(), case.signature_scheme());

    use x509_cert::der::DecodePem as _;
    let root = std::env::var("TEST_CERT").unwrap();
    let root = x509_cert::Certificate::from_pem(root).unwrap();
    let root = root.to_der().unwrap();
    let verifier = rustls_platform_verifier::Verifier::new_with_fake_root(&root);

    let end_entity = rustls::Certificate(chain.remove(0).to_der().unwrap());
    let server_name = rustls::ServerName::try_from("wire.com").unwrap();

    verifier
        .verify_server_cert(
            &end_entity,
            &[],
            &server_name,
            &mut std::iter::empty(),
            &[],
            std::time::SystemTime::now(),
        )
        .unwrap();
}
