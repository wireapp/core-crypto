pub use crate::prelude::{
    MlsCiphersuite, MlsConversationConfiguration, MlsCredentialType, MlsCustomConfiguration, MlsWirePolicy,
};
use crate::test_utils::SessionContext;
pub use openmls_traits::types::SignatureScheme;
pub use rstest::*;
pub use rstest_reuse::{self, *};

#[template]
#[rstest(
    case,
    case::basic_cs1(TestCase::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    case::cert_cs1(TestCase::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs2(TestCase::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs2(TestCase::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs3(TestCase::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs3(TestCase::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs5(TestCase::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs5(TestCase::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs7(TestCase::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs7(TestCase::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    case::pure_ciphertext(TestCase {
        credential_type: crate::prelude::MlsCredentialType::Basic,
        cfg: $crate::prelude::MlsConversationConfiguration {
            custom: $crate::prelude::MlsCustomConfiguration {
                wire_policy: $crate::prelude::MlsWirePolicy::Ciphertext,
                ..Default::default()
            },
            ..Default::default()
        },
        contexts: vec![],
    }),
)]
#[allow(non_snake_case)]
pub fn all_cred_cipher(case: TestCase) {}

#[derive(Debug, Clone)]
pub struct TestCase {
    pub credential_type: MlsCredentialType,
    pub cfg: MlsConversationConfiguration,
    pub contexts: Vec<SessionContext>,
}

impl TestCase {
    pub fn new(credential_type: MlsCredentialType, cs: openmls::prelude::Ciphersuite) -> Self {
        Self {
            credential_type,
            cfg: MlsConversationConfiguration {
                ciphersuite: cs.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn ciphersuite(&self) -> MlsCiphersuite {
        self.cfg.ciphersuite
    }

    pub fn signature_scheme(&self) -> SignatureScheme {
        self.cfg.ciphersuite.signature_algorithm()
    }

    pub fn custom_cfg(&self) -> MlsCustomConfiguration {
        self.cfg.custom.clone()
    }

    pub fn default_x509() -> Self {
        Self {
            credential_type: MlsCredentialType::X509,
            cfg: MlsConversationConfiguration::default(),
            contexts: vec![],
        }
    }

    pub fn is_x509(&self) -> bool {
        matches!(self.credential_type, MlsCredentialType::X509)
    }

    pub fn is_basic(&self) -> bool {
        matches!(self.credential_type, MlsCredentialType::Basic)
    }

    pub fn is_pure_ciphertext(&self) -> bool {
        matches!(self.cfg.custom.wire_policy, MlsWirePolicy::Ciphertext)
    }
}

impl Default for TestCase {
    fn default() -> Self {
        Self {
            credential_type: MlsCredentialType::Basic,
            cfg: MlsConversationConfiguration::default(),
            contexts: vec![],
        }
    }
}
