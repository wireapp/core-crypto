use openmls::{
    ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
    credentials::{CredentialBundle, CredentialType},
    key_packages::KeyPackageBundle,
};
use openmls_rust_crypto::{OpenMlsRustCrypto};
use openmls::prelude::{TlsSerializeTrait};

use rand::Rng;
use itertools::Itertools;

struct WireIdentity {
    domain: Vec<u8>,
    user_id: [u8; 16],
    device_id: Vec<u8>,
}

impl WireIdentity {
    fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(&self.user_id);
        v.extend(&self.device_id);
        v.extend(&self.domain);
        v
    }
}

fn main() {
    let backend = OpenMlsRustCrypto::default();
    let ciphersuite_name = CiphersuiteName::default();
    let ciphersuite = Ciphersuite::new(ciphersuite_name).unwrap();

    let identity = WireIdentity { 
        domain: b"mls.example.com".to_vec(),
        user_id: rand::thread_rng().gen(),
        device_id: vec![0],
    };
    println!("user_id: {:02x}", identity.user_id.iter().format(" "));

    let credentials = CredentialBundle::new(
        identity.to_vec(),
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
    println!("{:02x}", kp_bytes.iter().format(" "));
}
