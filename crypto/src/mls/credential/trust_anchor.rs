use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::group_context::GroupContext;
use openmls_traits::OpenMlsCryptoProvider;
use openmls_x509_credential::X509Ext;
use x509_cert::{der::Decode, Certificate, PkiPath};

use crate::{
    mls::{
        client::Client,
        conversation::{group_info::MlsGroupInfoBundle, handshake::MlsCommitBundle, ConversationId},
        MlsCentral,
    },
    prelude::MlsConversation,
    MlsError,
};
use crate::{CryptoError, CryptoResult};

/// A wrapper containing the configuration for trust anchors to be added in the group's context
/// extensions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerDomainTrustAnchor {
    /// Domain name in which the trust anchor belongs to
    pub domain_name: String,
    /// PEM encoded certificate chain
    pub intermediate_certificate_chain: String,
}

impl TryFrom<&openmls::extensions::PerDomainTrustAnchor> for PerDomainTrustAnchor {
    type Error = CryptoError;

    fn try_from(value: &openmls::extensions::PerDomainTrustAnchor) -> Result<Self, Self::Error> {
        let pems: Vec<_> = value
            .certificate_chain()
            .iter()
            .map(|cert| pem::Pem::new("CERTIFICATE", &cert[..]))
            .collect();
        Ok(Self {
            domain_name: std::str::from_utf8(value.domain_name())?.to_string(),
            intermediate_certificate_chain: pem::encode_many(&pems),
        })
    }
}

impl PerDomainTrustAnchor {
    /// Converts to the OpenMls's counterpart of this struct
    /// It performs validation first
    pub fn try_as_checked_openmls_trust_anchor(
        self,
        backend: &MlsCryptoProvider,
        group_context: Option<&GroupContext>,
    ) -> CryptoResult<openmls::extensions::PerDomainTrustAnchor> {
        let certificate_chain = self.validate(backend, group_context)?;
        Ok(openmls::extensions::PerDomainTrustAnchor::new(
            self.domain_name.into(),
            openmls::prelude::CredentialType::X509,
            certificate_chain,
        )
        .map_err(MlsError::from)?)
    }

    /// Validates the trust anchor and return its encoded chain encoded to der.
    fn validate(
        &self,
        backend: &MlsCryptoProvider,
        group_context: Option<&GroupContext>,
    ) -> CryptoResult<Vec<Vec<u8>>> {
        // parse PEM
        let certificate_chain = pem::parse_many(&self.intermediate_certificate_chain)?
            .iter()
            .map(|p| Certificate::from_der(p.contents()))
            .collect::<Result<PkiPath, x509_cert::der::Error>>()?;

        // verify domain_name is unique
        if let Some(group_context) = group_context {
            if group_context
                .extensions()
                .per_domain_trust_anchors()
                .is_some_and(|anchors| {
                    anchors
                        .iter()
                        .any(|anchor| String::from_utf8_lossy(anchor.domain_name()) == self.domain_name)
                })
            {
                return Err(CryptoError::DuplicateDomainName);
            }
        }

        // empty chains are not allowed
        let leaf_cert = certificate_chain.first().ok_or(CryptoError::InvalidCertificateChain)?;

        // validate domain in the leaf matches with the one supplied
        let domain_names = extract_domain_names(leaf_cert)?;
        if !domain_names.contains(&self.domain_name) {
            return Err(CryptoError::DomainNamesDontMatch);
        }

        // verify the whole chain
        let root_cert = certificate_chain
            .iter()
            .map(Ok)
            .reduce(
                |child, parent| -> Result<&Certificate, openmls_traits::types::CryptoError> {
                    let child = child?;
                    let parent = parent?;
                    child.is_valid()?;
                    child.is_signed_by(backend.crypto(), parent)?;
                    Ok(parent)
                },
            )
            .unwrap()
            .map_err(MlsError::from)?;
        // ensure that the root is also valid
        root_cert.is_valid().map_err(MlsError::from)?;

        check_root_in_trust_store(root_cert)?;

        let encoded_chain = pem::parse_many(&self.intermediate_certificate_chain)?
            .into_iter()
            .map(|p| p.into_contents())
            .collect::<Vec<_>>();
        Ok(encoded_chain)
    }
}

/// Checks the root cert against the trust store. In wasm maybe use webpki-roots (https://github.com/rustls/webpki-roots) crate
fn check_root_in_trust_store(_root: &Certificate) -> CryptoResult<()> {
    // TODO: verify root certificate is valid in the device's trust store
    Ok(())
}

fn is_trust_anchor_new(new_anchor: &openmls::prelude::PerDomainTrustAnchor, old_group_context: &GroupContext) -> bool {
    let old_trust_anchor = old_group_context.extensions().per_domain_trust_anchors();

    let no_old_trust_anchor = old_trust_anchor.is_none();
    let empty_old_trust_anchor = old_trust_anchor.map(|a| a.is_empty()).unwrap_or_default();

    let anchor_is_new = old_trust_anchor.is_some_and(|old_anchor| {
        !old_anchor
            .iter()
            .any(|old_anchor| old_anchor.certificate_chain() == new_anchor.certificate_chain())
    });

    no_old_trust_anchor || empty_old_trust_anchor || anchor_is_new
}

impl MlsConversation {
    /// Validates the certificate chain
    pub(crate) fn validate_received_trust_anchors(
        old_group_context: &GroupContext,
        commit_group_context: &GroupContext,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<()> {
        if let Some(new_anchors) = commit_group_context.extensions().per_domain_trust_anchors() {
            // find new anchors
            new_anchors
                .iter()
                .filter(|new_anchor| is_trust_anchor_new(new_anchor, old_group_context))
                .try_for_each(|anchor| -> CryptoResult<()> {
                    let anchor = PerDomainTrustAnchor::try_from(anchor)?;
                    // the domain will obviously be in the context and will be already applied by
                    // other client, so the domain uniqueness should not be validated here
                    anchor.validate(backend, None)?;
                    Ok(())
                })?;
        }
        Ok(())
    }

    /// Validates the trust anchors update against the current state of the group context and
    /// returns a new list of anchors that should be set for the group's extension
    fn compute_anchors_for_next_epoch(
        &self,
        remove_domain_names: Vec<String>,
        add_trust_anchors: Vec<PerDomainTrustAnchor>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<openmls::prelude::PerDomainTrustAnchor>> {
        if remove_domain_names.is_empty() && add_trust_anchors.is_empty() {
            return Err(CryptoError::EmptyTrustAnchorUpdate);
        }

        let context = self.group.export_group_context();
        let extensions = context.extensions();
        let mut anchors = extensions
            .per_domain_trust_anchors()
            .map(|anchors| {
                anchors
                    .iter()
                    .map(PerDomainTrustAnchor::try_from)
                    .collect::<CryptoResult<Vec<_>>>()
            })
            .unwrap_or_else(|| Ok(Vec::new()))?;

        let chain_count = anchors.len();

        // remove anchors
        anchors.retain(|anchor| !remove_domain_names.contains(&anchor.domain_name));

        // check if all to remove exists
        if chain_count != anchors.len() + remove_domain_names.len() {
            return Err(CryptoError::DomainNameNotFound);
        }

        anchors.iter().try_for_each(|a| {
            // check for duplicate anchors to be added
            if add_trust_anchors.iter().any(|n| a.domain_name == n.domain_name) {
                return Err(CryptoError::DuplicateDomainName);
            }
            // check if any new chain is already in the group's context
            if add_trust_anchors
                .iter()
                .any(|n| n.intermediate_certificate_chain == a.intermediate_certificate_chain)
            {
                return Err(CryptoError::DuplicateCertificateChain);
            }
            Ok(())
        })?;
        let new_anchors = anchors
            .into_iter()
            .chain(add_trust_anchors.into_iter())
            .map(|anchor| anchor.try_as_checked_openmls_trust_anchor(backend, None))
            .collect::<CryptoResult<Vec<_>>>()?;
        Ok(new_anchors)
    }

    /// see [MlsCentral::update_trust_anchors_from_conversation]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn update_trust_anchors(
        &mut self,
        client: &Client,
        remove_domain_names: Vec<String>,
        add_trust_anchors: Vec<PerDomainTrustAnchor>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsCommitBundle> {
        // parse back to mls and validate the anchors
        let context = self.group.export_group_context();
        let mut extensions = context.extensions().clone();
        let new_anchors = self.compute_anchors_for_next_epoch(remove_domain_names, add_trust_anchors, backend)?;
        extensions.add_or_replace(openmls::prelude::Extension::PerDomainTrustAnchor(new_anchors));

        // update the group extension through a GCE commit
        let cs = self.ciphersuite();
        let ct = self.own_credential_type()?;
        let signer = &client
            .find_most_recent_credential_bundle(cs.signature_algorithm(), ct)
            .ok_or(CryptoError::MlsNotInitialized)?
            .signature_key;
        let (commit, welcome, gi) = self
            .group
            .update_extensions(backend, signer, extensions)
            .await
            .map_err(MlsError::from)?;

        // SAFETY: This should be safe as updating extensions always generates a new commit
        let gi = gi.ok_or(CryptoError::ImplementationError)?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(gi)?;

        self.persist_group_when_changed(backend, false).await?;

        Ok(MlsCommitBundle {
            commit,
            welcome,
            group_info,
        })
    }
}

impl MlsCentral {
    /// Updates the trust anchors for a conversation
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `remove_domain_names` - domains to be removed from the group
    /// * `add_trust_anchors` - new trust anchors to be added to the group
    ///
    /// # Return type
    /// An struct containing a welcome(optional, will be present only if there's pending add
    /// proposals in the store), a message with the commit to fan out to other clients and
    /// the group info will be returned on successful call.
    ///
    /// # Errors
    /// If the authorisation callback is set, an error can be caused when the authorization fails.
    /// Other errors are KeyStore and OpenMls errors:
    pub async fn update_trust_anchors_from_conversation(
        &mut self,
        id: &ConversationId,
        remove_domain_names: Vec<String>,
        add_trust_anchors: Vec<PerDomainTrustAnchor>,
    ) -> CryptoResult<MlsCommitBundle> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            let client_id = self.mls_client()?.id().clone();
            if !callbacks.authorize(id.clone(), client_id).await {
                return Err(CryptoError::Unauthorized);
            }
        }

        self.get_conversation(id)
            .await?
            .write()
            .await
            .update_trust_anchors(
                self.mls_client()?,
                remove_domain_names,
                add_trust_anchors,
                &self.mls_backend,
            )
            .await
    }
}

pub(crate) fn extract_domain_names(certificate: &Certificate) -> CryptoResult<Vec<String>> {
    let common_name = certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|n| n.0.iter())
        .find_map(|attr| {
            if attr.oid.as_bytes() == oid_registry::OID_X509_COMMON_NAME.as_bytes() {
                Some(attr.value.value())
            } else {
                None
            }
        })
        .map(|bytes| String::from_utf8(bytes.to_owned()))
        .transpose()?;

    let san = if let Some(extensions) = certificate.tbs_certificate.extensions.as_ref() {
        extensions
            .iter()
            .find(|e| e.extn_id.as_bytes() == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME.as_bytes())
            .map(|e| x509_cert::ext::pkix::SubjectAltName::from_der(e.extn_value.as_bytes()))
            .transpose()?
    } else {
        None
    };

    let dns_names: Vec<_> = san
        .into_iter()
        .flat_map(|san| {
            san.0
                .iter()
                .filter_map(|n| match n {
                    x509_cert::ext::pkix::name::GeneralName::DnsName(ia5_str) => Some(ia5_str.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .chain(common_name)
        .collect();

    if dns_names.is_empty() {
        Err(CryptoError::DomainNameNotFound)
    } else {
        Ok(dns_names)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        mls::{
            conversation::{
                config::MlsConversationConfiguration, handshake::MlsConversationCreationMessage, ConversationId,
            },
            credential::typ::MlsCredentialType,
            MlsCentral,
        },
        test_utils::{conversation_id, TestCase},
        CryptoResult,
    };

    mod domain_name_extraction {
        use crate::{mls::credential::trust_anchor::extract_domain_names, test_utils::TestCase};

        use super::*;
        use crate::{
            test_utils::{x509::*, *},
            CryptoError,
        };
        use openmls_traits::types::Ciphersuite;
        use wasm_bindgen_test::*;

        wasm_bindgen_test_configure!(run_in_browser);

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        fn should_extract_domain_name(case: TestCase) {
            let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
            let cert = create_single_certificate(
                CertificateParams {
                    org: "Project Zeta GmBh".to_string(),
                    common_name: None,
                    domain: Some("wire.com".to_string()),
                    expiration: Duration::from_secs(10),
                },
                ciphersuite.into(),
                false,
            );

            let domain_names = extract_domain_names(&cert).unwrap();
            assert_eq!(domain_names[0], "wire.com");
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        fn should_extract_domain_name_common_name(case: TestCase) {
            let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
            let cert = create_single_certificate(
                CertificateParams {
                    org: "Project Zeta GmBh".to_string(),
                    common_name: Some("wire.com".to_string()),
                    domain: None,
                    expiration: Duration::from_secs(10),
                },
                ciphersuite.into(),
                false,
            );

            let domain_names = extract_domain_names(&cert).unwrap();
            assert_eq!(domain_names[0], "wire.com");
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        fn should_fail_extract_domain_name(case: TestCase) {
            let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
            let cert = create_single_certificate(
                CertificateParams {
                    org: "Project Zeta GmBh".to_string(),
                    common_name: None,
                    domain: None,
                    expiration: Duration::from_secs(10),
                },
                ciphersuite.into(),
                false,
            );

            let err = extract_domain_names(&cert).unwrap_err();
            assert!(matches!(err, CryptoError::DomainNameNotFound));
        }
    }

    mod on_group_creation {

        use super::*;
        use crate::{
            mls::credential::trust_anchor::PerDomainTrustAnchor,
            test_utils::{x509::*, *},
            CryptoError, MlsError,
        };
        use openmls::prelude::CryptoError as MlsCryptoError;
        use openmls_traits::types::Ciphersuite;
        use wasm_bindgen_test::*;

        wasm_bindgen_test_configure!(run_in_browser);

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_create_group_with_trust_anchors(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(&alice_central.mls_backend, None).unwrap();
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_create_group_with_expired_certs(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::ZERO,
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let error = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap_err();

                        assert!(matches!(
                            error,
                            CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::ExpiredCertificate))
                        ));
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_create_group_single_cert(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let cert = create_single_certificate(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                            true,
                        );
                        case.cfg.per_domain_trust_anchors = vec![cert.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();
                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(&alice_central.mls_backend, None).unwrap();
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_create_group_invalid_chain(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let cert = create_single_certificate(
                            CertificateParams {
                                org: "World Domination Inc".to_string(),
                                common_name: Some("World Domination".to_string()),
                                domain: None,
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                            false,
                        );
                        let ca = create_single_certificate(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                            true,
                        );
                        case.cfg.per_domain_trust_anchors = vec![vec![cert, ca].into()];
                        let error = dbg!(create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case
                        )
                        .await
                        .unwrap_err());

                        assert!(matches!(
                            error,
                            CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::InvalidSignature))
                        ));
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_create_group_unmatched_domains(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let mut anchor: PerDomainTrustAnchor = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::ZERO,
                            },
                            ciphersuite.into(),
                        )
                        .into();
                        anchor.domain_name = "wrong.domain.cc".to_string();
                        case.cfg.per_domain_trust_anchors = vec![anchor];
                        let error = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap_err();

                        assert!(matches!(error, CryptoError::DomainNamesDontMatch));
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_create_group_domain_not_found(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        // No domain at all
                        let anchor: PerDomainTrustAnchor = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: None,
                                domain: None,
                                expiration: Duration::ZERO,
                            },
                            ciphersuite.into(),
                        )
                        .into();
                        case.cfg.per_domain_trust_anchors = vec![anchor];
                        let error = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap_err();

                        assert!(matches!(error, CryptoError::DomainNameNotFound));
                    })
                },
            )
            .await;
        }
    }

    mod update_anchors {

        use super::*;
        use crate::{
            test_utils::{x509::*, *},
            CryptoError, MlsError,
        };
        use openmls::prelude::CryptoError as MlsCryptoError;
        use openmls_traits::types::Ciphersuite;
        use wasm_bindgen_test::*;

        wasm_bindgen_test_configure!(run_in_browser);

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_add_anchors_to_group(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();
                        // anchors should not be present
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .extensions()
                            .per_domain_trust_anchors()
                            .is_none());

                        // adding anchors to group
                        let commit_bundle = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![anchors.into()])
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        // bob parses the commit
                        bob_central
                            .decrypt_message(&id, &commit_bundle.commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(&alice_central.mls_backend, None).unwrap();
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_add_anchors_to_group_with_anchors(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();
                        let new_anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta 2 GmBh".to_string(),
                                common_name: Some("wire2.com".to_string()),
                                domain: Some("wire2.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );

                        // adding anchors to group
                        let commit_bundle = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![new_anchors.into()])
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        // bob parses the commit
                        bob_central
                            .decrypt_message(&id, &commit_bundle.commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 2);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(&alice_central.mls_backend, None).unwrap();
                        alice_anchors[1].validate(&alice_central.mls_backend, None).unwrap();
                        assert_eq!(alice_anchors[0].domain_name, "wire.com");
                        assert_eq!(alice_anchors[1].domain_name, "wire2.com");
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_add_duplicate_anchors_to_group(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();

                        let new_anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        // try adding anchors to group
                        let error = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![new_anchors.into()])
                            .await
                            .unwrap_err();

                        assert!(matches!(error, CryptoError::DuplicateDomainName));
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_add_invalid_anchors_to_group(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();
                        let cert = create_single_certificate(
                            CertificateParams {
                                org: "World Domination Inc".to_string(),
                                common_name: Some("World Domination".to_string()),
                                domain: None,
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                            false,
                        );
                        let ca = create_single_certificate(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                            true,
                        );

                        // try adding anchors to group
                        let error = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![vec![cert, ca].into()])
                            .await
                            .unwrap_err();

                        assert!(matches!(
                            error,
                            CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::InvalidSignature))
                        ));
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_add_expired_anchors_to_group(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();
                        let new_anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire2.com".to_string()),
                                domain: Some("wire2.com".to_string()),
                                expiration: Duration::ZERO,
                            },
                            ciphersuite.into(),
                        );

                        // try adding anchors to group
                        let error = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![new_anchors.into()])
                            .await
                            .unwrap_err();

                        assert!(matches!(
                            error,
                            CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::ExpiredCertificate))
                        ));
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_add_single_cert_anchors_to_group(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();
                        let cert = create_single_certificate(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire2.com".to_string()),
                                domain: Some("wire2.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                            false,
                        );

                        // try adding anchors to group
                        let commit_bundle = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![cert.into()])
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        bob_central
                            .decrypt_message(&id, commit_bundle.commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 2);
                        assert_eq!(alice_anchors, bob_anchors);
                    })
                },
            )
            .await;
        }
    }

    mod remove_anchors {
        use super::*;
        use crate::{
            mls::credential::trust_anchor::PerDomainTrustAnchor,
            test_utils::{x509::*, *},
            CryptoError,
        };

        use openmls_traits::types::Ciphersuite;
        use wasm_bindgen_test::*;

        wasm_bindgen_test_configure!(run_in_browser);

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_remove_anchors_from_group(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();

                        // remove anchor to group
                        let commit_bundle = alice_central
                            .update_trust_anchors_from_conversation(&id, vec!["wire.com".to_string()], vec![])
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        // bob parses the commit
                        bob_central
                            .decrypt_message(&id, &commit_bundle.commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 0);
                        assert_eq!(alice_anchors, bob_anchors);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_remove_anchors_add_new(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();
                        let new_anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta 2 GmBh".to_string(),
                                common_name: Some("wire2.com".to_string()),
                                domain: Some("wire2.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );

                        // adding anchors to group
                        let commit_bundle = alice_central
                            .update_trust_anchors_from_conversation(
                                &id,
                                vec!["wire.com".to_string()],
                                vec![new_anchors.into()],
                            )
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        // bob parses the commit
                        bob_central
                            .decrypt_message(&id, &commit_bundle.commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(&alice_central.mls_backend, None).unwrap();
                        assert_eq!(alice_anchors[0].domain_name, "wire2.com");
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_remove_anchors_not_found(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();

                        // remove anchor to group
                        let error = alice_central
                            .update_trust_anchors_from_conversation(&id, vec!["wire2.com".to_string()], vec![])
                            .await
                            .unwrap_err();
                        assert!(matches!(error, CryptoError::DomainNameNotFound));

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_empty_request(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();

                        // remove anchor to group
                        let error = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![])
                            .await
                            .unwrap_err();
                        assert!(matches!(error, CryptoError::EmptyTrustAnchorUpdate));

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_replace_anchors(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors: PerDomainTrustAnchor = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        )
                        .into();
                        let old_chain = anchors.intermediate_certificate_chain.clone();
                        case.cfg.per_domain_trust_anchors = vec![anchors];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();
                        let new_anchors: PerDomainTrustAnchor = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        )
                        .into();
                        let new_chain = new_anchors.intermediate_certificate_chain.clone();

                        // adding anchors to group
                        let commit_bundle = alice_central
                            .update_trust_anchors_from_conversation(
                                &id,
                                vec!["wire.com".to_string()],
                                vec![new_anchors],
                            )
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        // bob parses the commit
                        bob_central
                            .decrypt_message(&id, &commit_bundle.commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(&alice_central.mls_backend, None).unwrap();
                        assert_eq!(alice_anchors[0].domain_name, "wire.com");
                        assert_ne!(new_chain, old_chain);
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_re_add_same_anchors(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        use x509_cert::der::Encode;
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                        );
                        case.cfg.per_domain_trust_anchors = vec![anchors.clone().into()];
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();

                        // try adding anchors to group
                        let pems = anchors
                            .iter()
                            .map(|c| pem::Pem::new("CERTIFICATE", c.to_der().unwrap()))
                            .collect::<Vec<_>>();
                        let per_domain_trust_anchor = PerDomainTrustAnchor {
                            domain_name: "new_domain.com".to_string(),
                            intermediate_certificate_chain: pem::encode_many(&pems),
                        };
                        let error = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![per_domain_trust_anchor])
                            .await
                            .unwrap_err();

                        assert!(matches!(error, CryptoError::DuplicateCertificateChain));
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        let bob_anchors = bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                    })
                },
            )
            .await;
        }
    }

    mod receiver_validation {
        use super::*;
        use crate::{
            test_utils::{x509::*, *},
            CryptoError, MlsError,
        };

        use openmls::prelude::CryptoError as MlsCryptoError;
        use openmls_traits::types::Ciphersuite;
        use wasm_bindgen_test::*;

        wasm_bindgen_test_configure!(run_in_browser);

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_decrypting_expired(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();

                        // adding anchors to group
                        let anchors = create_intermediate_certificates(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::ZERO,
                            },
                            ciphersuite.into(),
                        );

                        // replace with manual openmls gce
                        let commit = alice_central
                            .add_per_domain_trust_anchor_unchecked(&id, anchors.into())
                            .await;
                        alice_central.commit_accepted(&id).await.unwrap();
                        // bob parses the commit
                        let error = bob_central
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await
                            .unwrap_err();

                        assert!(matches!(
                            error,
                            CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::ExpiredCertificate))
                        ));

                        // alice should have the invalid anchor but not bob
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert!(bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .extensions()
                            .per_domain_trust_anchors()
                            .is_none());
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_decrypting_invalid_chain(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let ciphersuite: Ciphersuite = case.cfg.ciphersuite.into();
                        let id = create_group(
                            case.cfg.clone(),
                            case.credential_type,
                            &mut alice_central,
                            &mut bob_central,
                            &case,
                        )
                        .await
                        .unwrap();

                        // adding anchors to group
                        let cert = create_single_certificate(
                            CertificateParams {
                                org: "World Domination Inc".to_string(),
                                common_name: Some("World Domination".to_string()),
                                domain: None,
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                            false,
                        );

                        let ca = create_single_certificate(
                            CertificateParams {
                                org: "Project Zeta GmBh".to_string(),
                                common_name: Some("wire.com".to_string()),
                                domain: Some("wire.com".to_string()),
                                expiration: Duration::from_secs(10),
                            },
                            ciphersuite.into(),
                            true,
                        );

                        // replace with manual openmls gce
                        let commit = alice_central
                            .add_per_domain_trust_anchor_unchecked(&id, vec![cert, ca].into())
                            .await;
                        alice_central.commit_accepted(&id).await.unwrap();
                        // bob parses the commit
                        let message = &commit.to_bytes().unwrap();
                        let error = bob_central.decrypt_message(&id, message).await.unwrap_err();

                        assert!(matches!(
                            error,
                            CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::InvalidSignature))
                        ));

                        // alice should have the invalid anchor but not bob
                        let alice_anchors = alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .per_domain_trust_anchors();
                        assert_eq!(alice_anchors.len(), 1);
                        assert!(bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .extensions()
                            .per_domain_trust_anchors()
                            .is_none());
                    })
                },
            )
            .await;
        }
    }

    async fn create_group(
        cfg: MlsConversationConfiguration,
        credential_type: MlsCredentialType,
        alice_central: &mut MlsCentral,
        bob_central: &mut MlsCentral,
        test_case: &TestCase,
    ) -> CryptoResult<ConversationId> {
        let id = conversation_id();
        let custom_cfg = cfg.custom.clone();
        alice_central.new_conversation(id.clone(), credential_type, cfg).await?;
        assert_eq!(alice_central.get_conversation_unchecked(&id).await.id, id);

        let MlsConversationCreationMessage { welcome, .. } = alice_central
            .add_members_to_conversation(&id, &mut [bob_central.rand_member(test_case).await])
            .await?;
        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
        alice_central.commit_accepted(&id).await?;
        bob_central
            .try_join_from_welcome(&id, welcome.into(), custom_cfg, vec![alice_central])
            .await?;
        Ok(id)
    }
}
