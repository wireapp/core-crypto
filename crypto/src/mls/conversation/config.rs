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

//! Conversation configuration.
//!
//! Either use [MlsConversationConfiguration] when creating a conversation or [MlsCustomConfiguration]
//! when joining one by Welcome or external commit

use openmls::prelude::{
    Credential, CredentialType, ExternalSender, PerDomainTrustAnchor, PerDomainTrustAnchorsExtension,
    SenderRatchetConfiguration, SignaturePublicKey, WireFormatPolicy, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use openmls_x509_credential::X509Ext;
use serde::{Deserialize, Serialize};
use wire_e2e_identity::prelude::WireIdentityReader;
use x509_cert::der::Decode;

use crate::{mls::MlsCiphersuite, CryptoError, CryptoResult, MlsError};

/// Sets the config in OpenMls for the oldest possible epoch(past current) that a message can be decrypted
pub(crate) const MAX_PAST_EPOCHS: usize = 2;

/// The configuration parameters for a group/conversation
#[derive(Debug, Clone, Default)]
pub struct MlsConversationConfiguration {
    /// The `OpenMls` Ciphersuite used in the group
    pub ciphersuite: MlsCiphersuite,
    /// Delivery service public signature key and credential
    pub external_senders: Vec<ExternalSender>,
    /// Implementation specific configuration
    pub custom: MlsCustomConfiguration,
    /// List of tuples of domain name and trusted root certificates to be set as an extension to the group
    pub certificate_list: Option<Vec<String>>,
}

impl MlsConversationConfiguration {
    // TODO: pending a long term solution with a real certificate
    const WIRE_SERVER_IDENTITY: &'static str = "wire-server";
    const PADDING_SIZE: usize = 128;

    /// Generates an `MlsGroupConfig` from this configuration
    #[inline(always)]
    pub fn as_openmls_default_configuration(&self) -> CryptoResult<openmls::group::MlsGroupConfig> {
        let certificate_roots = if let Some(ref certificate_list) = self.certificate_list {
            certificate_list.iter().try_fold(
                PerDomainTrustAnchorsExtension::new(),
                |mut acc, cert_chain| -> Result<Vec<PerDomainTrustAnchor>, CryptoError> {
                    let cert_data: Vec<Vec<u8>> = pem::parse_many(cert_chain)
                        .map_err(|_| CryptoError::InvalidPem)?
                        .into_iter()
                        .map(|p| p.contents().into())
                        .collect();
                    // at the moment we need only the root certificate
                    let root_cert = cert_data
                        .get(0)
                        .map(|cert_data| -> Result<x509_cert::Certificate, CryptoError> {
                            let cert = x509_cert::Certificate::from_der(&cert_data)
                                .map_err(|_| CryptoError::CertificateDecodingError)?;
                            cert.is_valid().map_err(MlsError::from)?;
                            Ok(cert)
                        })
                        .ok_or(CryptoError::IncompleteCertificateChain)??;
                    let identity = root_cert.extract_identity()?;
                    let anchor = PerDomainTrustAnchor::new(identity.domain.into(), CredentialType::X509, cert_data)
                        .map_err(MlsError::from)?;
                    acc.push(anchor);
                    Ok(acc)
                },
            )?
        } else {
            PerDomainTrustAnchorsExtension::default()
        };
        Ok(openmls::group::MlsGroupConfig::builder()
            .wire_format_policy(self.custom.wire_policy.into())
            .max_past_epochs(MAX_PAST_EPOCHS)
            .padding_size(Self::PADDING_SIZE)
            .number_of_resumption_psks(1)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                self.custom.out_of_order_tolerance,
                self.custom.maximum_forward_distance,
            ))
            .use_ratchet_tree_extension(true)
            .trust_certificates(certificate_roots)
            .external_senders(self.external_senders.clone())
            .build())
    }

    /// Parses supplied key from Delivery Service in order to build back an [ExternalSender]
    /// Note that this only works currently with Ed25519 keys and will have to be changed to accept
    /// other key schemes
    pub fn set_raw_external_senders(&mut self, external_senders: Vec<Vec<u8>>) {
        self.external_senders = external_senders
            .into_iter()
            .map(|key| {
                ExternalSender::new(
                    SignaturePublicKey::from(key),
                    Credential::new_basic(Self::WIRE_SERVER_IDENTITY.into()),
                )
            })
            .collect();
    }
}

/// The configuration parameters for a group/conversation which are not handled natively by openmls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsCustomConfiguration {
    // TODO: Not implemented yet
    /// Duration in seconds after which we will automatically force a self_update commit
    pub key_rotation_span: Option<std::time::Duration>,
    /// Defines if handshake messages are encrypted or not
    pub wire_policy: MlsWirePolicy,
    /// Window for which decryption secrets are kept within an epoch. Use this with caution since
    /// this affects forward secrecy within an epoch. Use this when the Delivery Service cannot
    /// guarantee application messages order.
    pub out_of_order_tolerance: u32,
    /// How many application messages can be skipped. Use this when the Delivery Service can drop
    /// application messages
    pub maximum_forward_distance: u32,
}

impl Default for MlsCustomConfiguration {
    fn default() -> Self {
        Self {
            wire_policy: MlsWirePolicy::Plaintext,
            key_rotation_span: Default::default(),
            out_of_order_tolerance: 2,
            maximum_forward_distance: 1000,
        }
    }
}

/// Wrapper over [WireFormatPolicy](openmls::prelude::WireFormatPolicy)
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MlsWirePolicy {
    /// Handshake messages are never encrypted
    #[default]
    Plaintext = 1,
    /// Handshake messages are always encrypted
    Ciphertext = 2,
}

impl From<MlsWirePolicy> for WireFormatPolicy {
    fn from(policy: MlsWirePolicy) -> Self {
        match policy {
            MlsWirePolicy::Ciphertext => PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
            MlsWirePolicy::Plaintext => PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        }
    }
}
