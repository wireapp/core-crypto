use std::sync::Arc;

pub use crate::prelude::{
    MlsCiphersuite, MlsConversationConfiguration, MlsCredentialType, MlsCustomConfiguration, MlsWirePolicy,
};
use crate::test_utils::SessionContext;
pub use openmls_traits::types::SignatureScheme;
pub use rstest::*;
pub use rstest_reuse::{self, *};

use super::{
    CoreCryptoTransportSuccessProvider, MlsTransportTestExt, TestCertificateSource, X509SessionParameters,
    x509::X509TestChain,
};

#[template]
#[rstest(
    case,
    case::basic_cs1(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    case::cert_cs1(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs2(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs2(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs3(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs3(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs5(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs5(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs7(TestContext::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs7(TestContext::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    case::pure_ciphertext(TestContext::default_cipher()),
)]
#[allow(non_snake_case)]
pub fn all_cred_cipher(case: TestContext) {}

/// Needed to specify the context a x509 certificate chain is initialized from.
enum TestChainKind {
    /// A certificate chain that is cross-signed by another
    CrossSigned,
    /// A certificate chain that exists on its own (default case).
    Single,
}

#[derive(Debug, Clone)]
pub struct TestContext {
    pub credential_type: MlsCredentialType,
    pub cfg: MlsConversationConfiguration,
    pub transport: Arc<dyn MlsTransportTestExt>,
}

impl TestContext {
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
            transport: Arc::<CoreCryptoTransportSuccessProvider>::default(),
        }
    }

    pub fn default_cipher() -> Self {
        let mut default = Self::default();
        default.cfg.custom.wire_policy = MlsWirePolicy::Ciphertext;
        default
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

    pub async fn sessions<const N: usize>(&self) -> [SessionContext; N] {
        self.sessions_x509(None).await
    }

    pub async fn sessions_x509<const N: usize>(&self, test_chain: Option<&X509TestChain>) -> [SessionContext; N] {
        self.sessions_x509_cross_signed_inner(test_chain, TestChainKind::Single)
            .await
    }

    /// Use this to create sessions with a test chain that has cross-signed another
    pub async fn sessions_x509_cross_signed<const N: usize>(
        &self,
        test_chain: Option<&X509TestChain>,
    ) -> [SessionContext; N] {
        self.sessions_x509_cross_signed_inner(test_chain, TestChainKind::CrossSigned)
            .await
    }

    async fn sessions_x509_cross_signed_inner<const N: usize>(
        &self,
        test_chain: Option<&X509TestChain>,
        test_chain_kind: TestChainKind,
    ) -> [SessionContext; N] {
        let mut result = Vec::with_capacity(N);
        for i in 0..N {
            let certificate_source = match test_chain_kind {
                TestChainKind::CrossSigned => TestCertificateSource::TestChainActor(i),
                TestChainKind::Single => TestCertificateSource::Generated,
            };
            result.push(
                SessionContext::new(
                    self,
                    test_chain.map(|chain| X509SessionParameters {
                        chain,
                        certificate_source,
                    }),
                )
                .await,
            );
        }
        result.try_into().expect("Vec length should match N")
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            credential_type: MlsCredentialType::Basic,
            cfg: MlsConversationConfiguration::default(),
            transport: Arc::<CoreCryptoTransportSuccessProvider>::default(),
        }
    }
}
