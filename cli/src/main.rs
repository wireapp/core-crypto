use openmls::{
    ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
    credentials::{CredentialBundle, CredentialType},
    key_packages::KeyPackageBundle,
};
use openmls_rust_crypto::{OpenMlsRustCrypto};
use openmls::prelude::{TlsSerializeTrait};
use core_crypto::prelude::ClientId;

use uuid::Uuid;
use std::io::Write;

fn main() {
    let backend = OpenMlsRustCrypto::default();
    let ciphersuite_name = CiphersuiteName::default();
    let ciphersuite = Ciphersuite::new(ciphersuite_name).unwrap();

    let identity = ClientId::new(
        Uuid::parse_str("b455a431-9db6-4404-86e7-6a3ebe73fcaf").unwrap(),
        "mls.example.com".to_string(),
        988119381
    );

    let credentials = CredentialBundle::new(
        identity.as_bytes(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &backend,
    ).unwrap();

    let kps = KeyPackageBundle::new(
        &[ciphersuite_name],
        &credentials,
        &backend,
        vec![]
    ).unwrap();

    let kp = kps.key_package();
    let mut kp_bytes = Vec::new();
    kp.tls_serialize(&mut kp_bytes).unwrap();
    std::io::stdout().write_all(&kp_bytes).unwrap();
}
