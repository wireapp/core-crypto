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

pub use crate::mls::credential::CredentialSupplier;
use crate::prelude::{MlsConversationConfiguration, MlsCustomConfiguration};

use crate::mls::MlsCiphersuite;
pub use rstest::*;
pub use rstest_reuse::{self, *};

// TODO: EC signatures are not supported for certificates because 'rcgen' crate used for generating
// certificates relies on 'ring' which does not support elliptic curves on WASM
#[template]
#[export]
#[rstest(
    case,
    case::basic_cs1(TestCase::new(
        $crate::mls::credential::CertificateBundle::rand_basic(),
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    case::cert_cs1(TestCase::new(
        $crate::mls::credential::CertificateBundle::rand_certificate_bundle(),
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs2(TestCase::new(
        $crate::mls::credential::CertificateBundle::rand_basic(),
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    /*
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs2(TestCase::new(
        $crate::mls::credential::CertificateBundle::rand_certificate_bundle(),
        openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    )),
    */
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs3(TestCase::new(
        $crate::mls::credential::CertificateBundle::rand_basic(),
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs3(TestCase::new(
        $crate::mls::credential::CertificateBundle::rand_certificate_bundle(),
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )),
    #[cfg(feature = "test-all-cipher")]
    case::basic_cs7(TestCase::new(
        $crate::mls::credential::CertificateBundle::rand_basic(),
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    /*
    #[cfg(feature = "test-all-cipher")]
    case::cert_cs7(TestCase::new(
        $crate::mls::credential::CertificateBundle::rand_certificate_bundle(),
        openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    )),
    */
    case::pure_ciphertext(TestCase {
        credential: $crate::mls::credential::CertificateBundle::rand_basic(),
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
    pub credential: CredentialSupplier,
    pub cfg: MlsConversationConfiguration,
}

impl TestCase {
    pub fn new(credential: CredentialSupplier, cs: openmls::prelude::Ciphersuite) -> Self {
        Self {
            credential,
            cfg: MlsConversationConfiguration {
                ciphersuite: cs.into(),
                ..Default::default()
            },
        }
    }

    pub fn ciphersuite(&self) -> MlsCiphersuite {
        self.cfg.ciphersuite
    }

    pub fn custom_cfg(&self) -> MlsCustomConfiguration {
        self.cfg.custom.clone()
    }

    pub fn credential(&self) -> Option<crate::mls::credential::CertificateBundle> {
        (self.credential)(self.cfg.ciphersuite)
    }
}

impl Default for TestCase {
    fn default() -> Self {
        Self {
            credential: |_| None,
            cfg: MlsConversationConfiguration::default(),
        }
    }
}
