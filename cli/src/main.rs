use openmls::{
    ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
    credentials::{CredentialBundle, CredentialType},
    key_packages::KeyPackageBundle,
};
use openmls_rust_crypto::{OpenMlsRustCrypto};
use openmls::prelude::{TlsSerializeTrait};

use uuid::Uuid;
use std::io::Write;

// copied from crypto::client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId {
    user_id: uuid::Uuid,
    domain: String,
    client_id: u64,
}

impl ClientId {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut ret = vec![];
        ret.extend_from_slice(self.user_id.as_hyphenated().to_string().as_bytes());
        ret.push(b':');
        ret.extend_from_slice(self.client_id.to_string().as_bytes());
        ret.push(b'@');
        ret.extend_from_slice(self.domain.as_bytes());

        ret
    }
}

fn main() {
    let backend = OpenMlsRustCrypto::default();
    let ciphersuite_name = CiphersuiteName::default();
    let ciphersuite = Ciphersuite::new(ciphersuite_name).unwrap();

    let identity = ClientId {
        user_id: Uuid::parse_str("b455a431-9db6-4404-86e7-6a3ebe73fcaf").unwrap(),
        domain: "mls.example.com".to_string(),
        client_id: 0,
    };

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
