#![cfg(test)]

use crate::test_utils::x509::{new_self_signed_certificate, CertificateParams};
use openmls_traits::types::SignatureScheme;
use rustls::client::ServerCertVerifier as _;
use std::process::Command;
use x509_cert::der::Encode;

#[test]
fn toy() {
    let root1 = include_bytes!("root1.crt");
    let intermediate = include_bytes!("root1-int1-ee_1-good.crt");

    let scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    let cert = new_self_signed_certificate(CertificateParams::default(), scheme, true);

    // println!("{:#?}", &cert.tbs_certificate);
    use x509_cert::der::EncodePem as _;
    let cert_pem = cert.to_pem(x509_cert::der::pem::LineEnding::CRLF).unwrap();

    let path = std::env::temp_dir().join(format!("cert-{}.pem", rand_base64_str(12)));
    std::fs::write(&path, cert_pem).unwrap();
    let path_str = path.to_str().unwrap();

    let pretty = Command::new("openssl")
        .args(["x509", "-text", "-noout", "-in", path_str])
        .output()
        .unwrap();
    println!("> {}", String::from_utf8(pretty.stdout).unwrap());

    let verify = Command::new("openssl")
        .args(["x509", "-verify", "-in", path_str])
        .output()
        .unwrap();
    let verify = if verify.status.success() { "✅" } else { "❌" };
    println!("verify > {verify}");

    let verifier = rustls_platform_verifier::Verifier::new();
    let verifier = rustls_platform_verifier::Verifier::new_with_fake_root(cert.to_der().unwrap().as_slice());

    let end_identity = rustls::Certificate(cert.to_der().unwrap());
    let server_name = rustls::ServerName::try_from("wire.com").unwrap();

    verifier
        .verify_certificate(&end_identity, &vec![], "wire.com", None, std::time::SystemTime::now())
        .unwrap();
    /*verifier
    .verify_server_cert(
        &end_identity,
        &vec![],
        &server_name,
        &mut std::iter::empty(),
        &[],
        std::time::SystemTime::now(),
    )
    .unwrap();*/
}

const ROOT1: &[u8] = include_bytes!("root1.crt");
const ROOT1_INT1: &[u8] = include_bytes!("root1-int1.crt");
const ROOT1_INT1_EXAMPLE_COM_GOOD: &[u8] = include_bytes!("root1-int1-ee_example.com-good.crt");

#[test]
fn toy_2() {
    let verifier = rustls_platform_verifier::Verifier::new_with_fake_root(ROOT1);
    let end_entity = rustls::Certificate(ROOT1_INT1_EXAMPLE_COM_GOOD.to_vec());
    let intermediates = [rustls::Certificate(ROOT1_INT1.to_vec())];
    let server_name = rustls::client::ServerName::try_from("example.com").unwrap();
    verifier
        .verify_server_cert(
            &end_entity,
            &intermediates,
            &server_name,
            &mut std::iter::empty(),
            &[],
            std::time::SystemTime::now(),
        )
        .unwrap();
}

pub fn rand_base64_str(size: usize) -> String {
    use base64::Engine as _;
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(rand_str(size))
}

pub(crate) fn rand_str(size: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), size)
}
