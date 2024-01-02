use jwt_simple::prelude::*;
use rusty_jwt_tools::prelude::*;
use wire_e2e_identity::RustyE2eIdentity;

#[allow(clippy::type_complexity)]
pub fn enrollments() -> Vec<(RustyE2eIdentity, Pem, Pem, HashAlgorithm)> {
    let ed25519_enrollment = {
        let ed25519_client_kp = Ed25519KeyPair::generate().to_bytes();
        let ed25519_backend_kp = Ed25519KeyPair::generate();
        (
            RustyE2eIdentity::try_new(JwsAlgorithm::Ed25519, ed25519_client_kp).unwrap(),
            ed25519_backend_kp.to_pem().into(),
            ed25519_backend_kp.public_key().to_pem().into(),
            HashAlgorithm::SHA256,
        )
    };
    let p256_enrollment = {
        let p256_client_kp = ES256KeyPair::generate().to_bytes();
        let p256_backend_kp = ES256KeyPair::generate();
        (
            RustyE2eIdentity::try_new(JwsAlgorithm::P256, p256_client_kp).unwrap(),
            p256_backend_kp.to_pem().unwrap().into(),
            p256_backend_kp.public_key().to_pem().unwrap().into(),
            HashAlgorithm::SHA256,
        )
    };
    let p384_enrollment = {
        let p384_client_kp = ES384KeyPair::generate().to_bytes();
        let p384_backend_kp = ES384KeyPair::generate();
        (
            RustyE2eIdentity::try_new(JwsAlgorithm::P384, p384_client_kp).unwrap(),
            p384_backend_kp.to_pem().unwrap().into(),
            p384_backend_kp.public_key().to_pem().unwrap().into(),
            HashAlgorithm::SHA384,
        )
    };
    vec![ed25519_enrollment, p256_enrollment, p384_enrollment]
}
