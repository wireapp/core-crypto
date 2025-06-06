//! Conversation configuration.
//!
//! Either use [MlsConversationConfiguration] when creating a conversation or [MlsCustomConfiguration]
//! when joining one by Welcome or external commit

use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{
    Capabilities, Credential, CredentialType, ExternalSender, OpenMlsSignaturePublicKey,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ProtocolVersion,
    RequiredCapabilitiesExtension, SenderRatchetConfiguration, WireFormatPolicy,
};
use openmls_traits::{
    OpenMlsCryptoProvider,
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, SignatureScheme},
};
use serde::{Deserialize, Serialize};
use wire_e2e_identity::prelude::parse_json_jwk;

use super::Result;
use crate::{MlsError, RecursiveError, prelude::MlsCiphersuite};

/// Sets the config in OpenMls for the oldest possible epoch(past current) that a message can be decrypted
pub(crate) const MAX_PAST_EPOCHS: usize = 3;

/// Window for which decryption secrets are kept within an epoch. Use this with caution since this affects forward secrecy within an epoch.
/// Use this when the Delivery Service cannot guarantee application messages order
pub(crate) const OUT_OF_ORDER_TOLERANCE: u32 = 2;

/// How many application messages can be skipped. Use this when the Delivery Service can drop application messages
pub(crate) const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;

/// The configuration parameters for a group/conversation
#[derive(Debug, Clone, Default)]
pub struct MlsConversationConfiguration {
    /// The `OpenMls` Ciphersuite used in the group
    pub ciphersuite: MlsCiphersuite,
    /// Delivery service public signature key and credential
    pub external_senders: Vec<ExternalSender>,
    /// Implementation specific configuration
    pub custom: MlsCustomConfiguration,
}

impl MlsConversationConfiguration {
    const WIRE_SERVER_IDENTITY: &'static str = "wire-server";

    const PADDING_SIZE: usize = 128;

    /// Default protocol
    pub(crate) const DEFAULT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;

    /// List all until further notice
    pub(crate) const DEFAULT_SUPPORTED_CREDENTIALS: &'static [CredentialType] =
        &[CredentialType::Basic, CredentialType::X509];

    /// Conservative sensible defaults
    pub(crate) const DEFAULT_SUPPORTED_CIPHERSUITES: &'static [Ciphersuite] = &[
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    ];

    /// Not used at the moment
    const NUMBER_RESUMPTION_PSK: usize = 1;

    /// Generates an `MlsGroupConfig` from this configuration
    #[inline(always)]
    pub fn as_openmls_default_configuration(&self) -> Result<openmls::group::MlsGroupConfig> {
        let crypto_config = openmls::prelude::CryptoConfig {
            version: Self::DEFAULT_PROTOCOL_VERSION,
            ciphersuite: self.ciphersuite.into(),
        };
        Ok(openmls::group::MlsGroupConfig::builder()
            .wire_format_policy(self.custom.wire_policy.into())
            .max_past_epochs(MAX_PAST_EPOCHS)
            .padding_size(Self::PADDING_SIZE)
            .number_of_resumption_psks(Self::NUMBER_RESUMPTION_PSK)
            .leaf_capabilities(Self::default_leaf_capabilities())
            .required_capabilities(self.default_required_capabilities())
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                self.custom.out_of_order_tolerance,
                self.custom.maximum_forward_distance,
            ))
            .use_ratchet_tree_extension(true)
            .external_senders(self.external_senders.clone())
            .crypto_config(crypto_config)
            .build())
    }

    /// Default capabilities for every generated [openmls::prelude::KeyPackage]
    pub fn default_leaf_capabilities() -> Capabilities {
        Capabilities::new(
            Some(&[Self::DEFAULT_PROTOCOL_VERSION]),
            Some(Self::DEFAULT_SUPPORTED_CIPHERSUITES),
            Some(&[]),
            Some(&[]),
            Some(Self::DEFAULT_SUPPORTED_CREDENTIALS),
        )
    }

    fn default_required_capabilities(&self) -> RequiredCapabilitiesExtension {
        RequiredCapabilitiesExtension::new(&[], &[], Self::DEFAULT_SUPPORTED_CREDENTIALS)
    }

    /// This expects a raw json serialized JWK. It works with any Signature scheme
    pub(crate) fn parse_external_sender(jwk: &[u8]) -> Result<ExternalSender> {
        let pk = parse_json_jwk(jwk)
            .map_err(wire_e2e_identity::prelude::E2eIdentityError::from)
            .map_err(crate::e2e_identity::Error::from)
            .map_err(RecursiveError::e2e_identity("parsing jwk"))?;
        Ok(ExternalSender::new(
            pk.into(),
            Credential::new_basic(Self::WIRE_SERVER_IDENTITY.into()),
        ))
    }

    /// This supports the legacy behaviour where the server was providing the external sender public key
    /// raw.
    // TODO: remove at some point when the backend API is not used anymore. Tracking issue: WPB-9614
    pub(crate) fn legacy_external_sender(
        key: Vec<u8>,
        signature_scheme: SignatureScheme,
        backend: &MlsCryptoProvider,
    ) -> Result<ExternalSender> {
        backend
            .crypto()
            .validate_signature_key(signature_scheme, &key[..])
            .map_err(MlsError::wrap("validating signature key"))?;
        let key = OpenMlsSignaturePublicKey::new(key.into(), signature_scheme)
            .map_err(MlsError::wrap("creating new signature public key"))?;
        Ok(ExternalSender::new(
            key.into(),
            Credential::new_basic(Self::WIRE_SERVER_IDENTITY.into()),
        ))
    }
}

/// The configuration parameters for a group/conversation which are not handled natively by openmls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsCustomConfiguration {
    // TODO: Not implemented yet. Tracking issue: WPB-9609
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
            out_of_order_tolerance: OUT_OF_ORDER_TOLERANCE,
            maximum_forward_distance: MAXIMUM_FORWARD_DISTANCE,
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

#[cfg(test)]
mod tests {
    use openmls::prelude::ProtocolVersion;
    use openmls_traits::{
        OpenMlsCryptoProvider,
        crypto::OpenMlsCrypto,
        types::{SignatureScheme, VerifiableCiphersuite},
    };
    use wire_e2e_identity::prelude::JwsAlgorithm;

    use crate::mls::conversation::ConversationWithMls as _;
    use crate::{prelude::MlsConversationConfiguration, test_utils::*};

    #[async_std::test]
    pub async fn group_should_have_required_capabilities() {
        let case = TestContext::default();

        let [session] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&session]).await;
            let guard = conversation.guard().await;
            let group = guard.conversation().await;

            let capabilities = group.group.group_context_extensions().required_capabilities().unwrap();

            // see https://www.rfc-editor.org/rfc/rfc9420.html#section-11.1
            assert!(capabilities.extension_types().is_empty());
            assert!(capabilities.proposal_types().is_empty());
            assert_eq!(
                capabilities.credential_types(),
                MlsConversationConfiguration::DEFAULT_SUPPORTED_CREDENTIALS
            );
        })
        .await
    }

    #[apply(all_cred_cipher)]
    pub async fn creator_leaf_node_should_have_default_capabilities(case: TestContext) {
        let [session] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&session]).await;
            let guard = conversation.guard().await;
            let group = guard.conversation().await;

            // verifying https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2
            let creator_capabilities = group.group.own_leaf().unwrap().capabilities();

            // https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2-5.1.1
            // ProtocolVersion must be the default one
            assert_eq!(creator_capabilities.versions(), &[ProtocolVersion::Mls10]);

            // To prevent downgrade attacks, Ciphersuite MUST ONLY contain the current one
            assert_eq!(
                creator_capabilities.ciphersuites().to_vec(),
                MlsConversationConfiguration::DEFAULT_SUPPORTED_CIPHERSUITES
                    .iter()
                    .map(|c| VerifiableCiphersuite::from(*c))
                    .collect::<Vec<_>>()
            );

            // Proposals MUST be empty since we support all the default ones
            assert!(creator_capabilities.proposals().is_empty());

            // Extensions MUST only contain non-default extension (i.e. empty for now)
            assert!(creator_capabilities.extensions().is_empty(),);

            // To prevent downgrade attacks, Credentials should just contain the current
            assert_eq!(
                creator_capabilities.credentials(),
                MlsConversationConfiguration::DEFAULT_SUPPORTED_CREDENTIALS
            );
        })
        .await
    }

    #[apply(all_cred_cipher)]
    pub async fn should_support_raw_external_sender(case: TestContext) {
        let [cc] = case.sessions().await;
        Box::pin(async move {
            let (_sk, pk) = cc
                .transaction
                .mls_provider()
                .await
                .unwrap()
                .crypto()
                .signature_key_gen(case.signature_scheme())
                .unwrap();

            assert!(
                cc.transaction
                    .set_raw_external_senders(&mut case.cfg.clone(), vec![pk])
                    .await
                    .is_ok()
            );
        })
        .await
    }

    #[apply(all_cred_cipher)]
    pub async fn should_support_jwk_external_sender(case: TestContext) {
        let [cc] = case.sessions().await;
        Box::pin(async move {
            let sc = case.signature_scheme();

            let alg = match sc {
                SignatureScheme::ED25519 => JwsAlgorithm::Ed25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256 => JwsAlgorithm::P256,
                SignatureScheme::ECDSA_SECP384R1_SHA384 => JwsAlgorithm::P384,
                SignatureScheme::ECDSA_SECP521R1_SHA512 => JwsAlgorithm::P521,
                SignatureScheme::ED448 => unreachable!(),
            };

            let jwk = wire_e2e_identity::prelude::generate_jwk(alg);
            cc.transaction
                .set_raw_external_senders(&mut case.cfg.clone(), vec![jwk])
                .await
                .unwrap();
        })
        .await;
    }
}
