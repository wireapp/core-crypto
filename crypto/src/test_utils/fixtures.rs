// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::prelude::MlsCredentialType;
use crate::prelude::{MlsCiphersuite, MlsConversationConfiguration, MlsCustomConfiguration};
use openmls_traits::types::SignatureScheme;
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
    /*
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs2(TestCase::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    */
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs3(TestCase::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    // #[cfg(feature = "test-all-cipher")]
    // case::cert_cs3(TestCase::new(
    //     crate::prelude::MlsCredentialType::X509,
    //     openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    // )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs7(TestCase::new(
        crate::prelude::MlsCredentialType::Basic,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    /*
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs7(TestCase::new(
        crate::prelude::MlsCredentialType::X509,
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    */
    case::pure_ciphertext(TestCase {
        credential_type: crate::prelude::MlsCredentialType::Basic,
        cfg: $crate::prelude::MlsConversationConfiguration {
            custom: $crate::prelude::MlsCustomConfiguration {
                wire_policy: $crate::prelude::MlsWirePolicy::Ciphertext,
                ..Default::default()
            },
            ..Default::default()
        }
    }),
)]
#[allow(non_snake_case)]
pub fn all_cred_cipher(case: TestCase) {}

#[derive(Debug, Clone)]
pub struct TestCase {
    pub credential_type: MlsCredentialType,
    pub cfg: MlsConversationConfiguration,
}

impl TestCase {
    pub fn new(credential_type: MlsCredentialType, cs: openmls::prelude::Ciphersuite) -> Self {
        if matches!(credential_type, MlsCredentialType::X509) {
            return Self::default_x509(cs);
        }
        Self {
            credential_type,
            cfg: MlsConversationConfiguration {
                ciphersuite: cs.into(),
                ..Default::default()
            },
        }
    }

    pub fn ciphersuite(&self) -> MlsCiphersuite {
        self.cfg.ciphersuite
    }

    pub fn signature_scheme(&self) -> SignatureScheme {
        openmls::prelude::Ciphersuite::from(self.ciphersuite()).signature_algorithm()
    }

    pub fn custom_cfg(&self) -> MlsCustomConfiguration {
        self.cfg.custom.clone()
    }

    pub fn default_x509(cs: openmls::prelude::Ciphersuite) -> Self {
        let certs = crate::mls::credential::x509::CertificateBundle::rand(cs.into(), "alice".into());
        let pem_chain: Vec<_> = certs
            .certificate_chain
            .into_iter()
            .map(|cert| pem::Pem::new("CERTIFICATE", cert))
            .collect();
        let certificate_list = pem::encode_many(&pem_chain);
        Self {
            credential_type: MlsCredentialType::X509,
            cfg: MlsConversationConfiguration {
                ciphersuite: cs.into(),
                certificate_list: Some(vec![certificate_list]),
                ..Default::default()
            },
        }
    }
}

impl Default for TestCase {
    fn default() -> Self {
        Self {
            credential_type: MlsCredentialType::Basic,
            cfg: MlsConversationConfiguration::default(),
        }
    }
}
