use openmls::prelude::group_context::GroupContext;
use x509_cert::der::Encode;
use x509_cert::{der::Decode, Certificate, PkiPath};

use crate::prelude::{
    Client, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsCommitBundle, MlsConversation, MlsError,
    MlsGroupInfoBundle,
};
use mls_crypto_provider::MlsCryptoProvider;

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
        group_context: Option<&GroupContext>,
    ) -> CryptoResult<openmls::extensions::PerDomainTrustAnchor> {
        let certificate_chain = self.validate(group_context)?;
        Ok(openmls::extensions::PerDomainTrustAnchor::new(
            self.domain_name.into(),
            openmls::prelude::CredentialType::X509,
            certificate_chain,
        )
        .map_err(MlsError::from)?)
    }

    /// Validates the trust anchor and return its encoded chain encoded to der.
    fn validate(&self, group_context: Option<&GroupContext>) -> CryptoResult<Vec<Vec<u8>>> {
        // parse PEM
        let mut certificate_chain: PkiPath = pem::parse_many(&self.intermediate_certificate_chain)?
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
                        .any(|anchor| anchor.domain_name() == self.domain_name.as_bytes())
                })
            {
                return Err(CryptoError::DuplicateDomainName);
            }
        }

        // empty chains are not allowed
        if certificate_chain.is_empty() {
            return Err(CryptoError::InvalidCertificateChain);
        }
        let end_identity = certificate_chain.remove(0);

        // validate domain in the leaf matches with the one supplied
        let domain_names = extract_domain_names(&end_identity)?;
        if !domain_names.contains(&self.domain_name) {
            return Err(CryptoError::DomainNamesDontMatch);
        }

        // verify the whole chain
        use rustls::client::ServerCertVerifier as _;

        #[cfg(not(test))]
        let verifier = rustls_platform_verifier::Verifier::new();
        #[cfg(test)]
        let verifier = {
            use x509_cert::der::DecodePem as _;
            let root = std::env::var("TEST_CERT").unwrap();
            // let root = super::cert_playground::ROOT;
            let root = x509_cert::Certificate::from_pem(root).unwrap();
            let root = root.to_der().unwrap();
            rustls_platform_verifier::Verifier::new_with_fake_root(&root)
        };

        let end_identity = rustls::Certificate(end_identity.to_der()?);
        let intermediates = certificate_chain
            .into_iter()
            .map(|c| c.to_der().map(rustls::Certificate).map_err(CryptoError::from))
            .collect::<CryptoResult<Vec<rustls::Certificate>>>()?;

        let server_name = rustls::ServerName::try_from(self.domain_name.as_str())?;

        verifier
            .verify_server_cert(
                &end_identity,
                &intermediates,
                &server_name,
                &mut std::iter::empty(),
                &[],
                std::time::SystemTime::now(),
            )
            .unwrap();

        let encoded_chain = pem::parse_many(&self.intermediate_certificate_chain)?
            .into_iter()
            .map(pem::Pem::into_contents)
            .collect::<Vec<_>>();
        Ok(encoded_chain)
    }
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
                    anchor.validate(None)?;
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
            .map(|anchor| anchor.try_as_checked_openmls_trust_anchor(None))
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
        let new_anchors = self.compute_anchors_for_next_epoch(remove_domain_names, add_trust_anchors)?;
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
pub mod tests {
    use super::*;
    use std::time::Duration;

    use wasm_bindgen_test::*;

    use openmls::prelude::CryptoError as MlsCryptoError;

    use crate::{
        mls::credential::{trust_anchor::extract_domain_names, trust_anchor::PerDomainTrustAnchor},
        test_utils::{x509::*, *},
    };

    wasm_bindgen_test_configure!(run_in_browser);

    mod domain_name_extraction {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        fn should_extract_domain_name(case: TestCase) {
            let cert = new_self_signed_certificate(
                CertificateParams {
                    common_name: None,
                    ..Default::default()
                },
                case.signature_scheme(),
                false,
            );

            let domain_names = extract_domain_names(&cert).unwrap();
            assert_eq!(domain_names[0], "wire.com");
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        fn should_extract_domain_name_common_name(case: TestCase) {
            let cert = new_self_signed_certificate(
                CertificateParams {
                    domain: None,
                    ..Default::default()
                },
                case.signature_scheme(),
                false,
            );

            let domain_names = extract_domain_names(&cert).unwrap();
            assert_eq!(domain_names[0], "wire.com");
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        fn should_fail_extract_domain_name(case: TestCase) {
            let cert = new_self_signed_certificate(
                CertificateParams {
                    common_name: None,
                    domain: None,
                    ..Default::default()
                },
                case.signature_scheme(),
                false,
            );

            let err = extract_domain_names(&cert).unwrap_err();
            assert!(matches!(err, CryptoError::DomainNameNotFound));
        }
    }

    mod on_group_creation {
        use super::*;

        // #[apply(all_cred_cipher)]
        // #[wasm_bindgen_test]
        #[async_std::test]
        pub async fn should_create_group_with_trust_anchors(/*mut case: TestCase*/) {
            let mut case = TestCase::default_for_trust_anchor();
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(None).unwrap();
                    })
                },
            )
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_create_group_with_expired_certs(mut case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let anchors = new_certificate_chain(
                        CertificateParams {
                            expiration: Duration::ZERO,
                            ..Default::default()
                        },
                        case.signature_scheme(),
                    );
                    case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                    let id = conversation_id();
                    let error = alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap_err();

                    assert!(matches!(
                        error,
                        CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::ExpiredCertificate))
                    ));
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_create_group_single_cert(mut case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let cert = new_self_signed_certificate(CertificateParams::default(), case.signature_scheme(), true);

                    case.cfg.per_domain_trust_anchors = vec![cert.into()];
                    let id = conversation_id();
                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    // both must have the anchors in the extensions
                    let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                    assert_eq!(alice_anchors.len(), 1);
                    alice_anchors[0].validate(None).unwrap();
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_create_group_invalid_chain(mut case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let cert = new_self_signed_certificate(
                        CertificateParams {
                            org: "World Domination Inc".to_string(),
                            common_name: Some("World Domination".to_string()),
                            domain: None,
                            ..Default::default()
                        },
                        case.signature_scheme(),
                        false,
                    );
                    let ca = new_self_signed_certificate(CertificateParams::default(), case.signature_scheme(), true);
                    case.cfg.per_domain_trust_anchors = vec![vec![cert, ca].into()];
                    let id = conversation_id();
                    let error = alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap_err();

                    assert!(matches!(
                        error,
                        CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::InvalidSignature))
                    ));
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_create_group_unmatched_domains(mut case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let mut anchor: PerDomainTrustAnchor = new_certificate_chain(
                        CertificateParams {
                            expiration: Duration::ZERO,
                            ..Default::default()
                        },
                        case.signature_scheme(),
                    )
                    .into();
                    anchor.domain_name = "wrong.domain.cc".to_string();
                    case.cfg.per_domain_trust_anchors = vec![anchor];
                    let id = conversation_id();
                    let error = alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap_err();

                    assert!(matches!(error, CryptoError::DomainNamesDontMatch));
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_create_group_domain_not_found(mut case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    // No domain at all
                    let anchor: PerDomainTrustAnchor = new_certificate_chain(
                        CertificateParams {
                            common_name: None,
                            domain: None,
                            expiration: Duration::ZERO,
                            ..Default::default()
                        },
                        case.signature_scheme(),
                    )
                    .into();
                    case.cfg.per_domain_trust_anchors = vec![anchor];
                    let id = conversation_id();
                    let error = alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap_err();

                    assert!(matches!(error, CryptoError::DomainNameNotFound));
                })
            })
            .await;
        }
    }

    mod update_anchors {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_add_anchors_to_group(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                        // anchors should not be present
                        assert!(alice_central.per_domain_trust_anchors(&id).await.is_empty());

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
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(None).unwrap();
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
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                        let new_anchors = new_certificate_chain(
                            CertificateParams {
                                org: "Project Zeta 2 GmBh".to_string(),
                                common_name: Some("wire2.com".to_string()),
                                domain: Some("wire2.com".to_string()),
                                ..Default::default()
                            },
                            case.signature_scheme(),
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
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
                        assert_eq!(alice_anchors.len(), 2);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(None).unwrap();
                        alice_anchors[1].validate(None).unwrap();
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
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                    case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                    let id = conversation_id();
                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let new_anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                    // try adding anchors to group
                    let error = alice_central
                        .update_trust_anchors_from_conversation(&id, vec![], vec![new_anchors.into()])
                        .await
                        .unwrap_err();

                    assert!(matches!(error, CryptoError::DuplicateDomainName));
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_add_invalid_anchors_to_group(mut case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                    case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                    let id = conversation_id();
                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let cert = new_self_signed_certificate(
                        CertificateParams {
                            org: "World Domination Inc".to_string(),
                            common_name: Some("World Domination".to_string()),
                            domain: None,
                            ..Default::default()
                        },
                        case.signature_scheme(),
                        false,
                    );
                    let ca = new_self_signed_certificate(CertificateParams::default(), case.signature_scheme(), true);

                    // try adding anchors to group
                    let error = alice_central
                        .update_trust_anchors_from_conversation(&id, vec![], vec![vec![cert, ca].into()])
                        .await
                        .unwrap_err();

                    assert!(matches!(
                        error,
                        CryptoError::MlsError(MlsError::MlsCryptoError(MlsCryptoError::InvalidSignature))
                    ));
                })
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_add_expired_anchors_to_group(mut case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                    case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                    let id = conversation_id();
                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    let new_anchors = new_certificate_chain(
                        CertificateParams {
                            common_name: Some("wire2.com".to_string()),
                            domain: Some("wire2.com".to_string()),
                            expiration: Duration::ZERO,
                            ..Default::default()
                        },
                        case.signature_scheme(),
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
                })
            })
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
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                        let cert = new_self_signed_certificate(
                            CertificateParams {
                                common_name: Some("wire2.com".to_string()),
                                domain: Some("wire2.com".to_string()),
                                ..Default::default()
                            },
                            case.signature_scheme(),
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

                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
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

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_remove_anchors_from_group(mut case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

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
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
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
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                        let new_anchors = new_certificate_chain(
                            CertificateParams {
                                org: "Project Zeta 2 GmBh".to_string(),
                                common_name: Some("wire2.com".to_string()),
                                domain: Some("wire2.com".to_string()),
                                ..Default::default()
                            },
                            case.signature_scheme(),
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
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(None).unwrap();
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
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                        // remove anchor to group
                        let error = alice_central
                            .update_trust_anchors_from_conversation(&id, vec!["wire2.com".to_string()], vec![])
                            .await
                            .unwrap_err();
                        assert!(matches!(error, CryptoError::DomainNameNotFound));

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
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
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        case.cfg.per_domain_trust_anchors = vec![anchors.into()];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                        // remove anchor to group
                        let error = alice_central
                            .update_trust_anchors_from_conversation(&id, vec![], vec![])
                            .await
                            .unwrap_err();
                        assert!(matches!(error, CryptoError::EmptyTrustAnchorUpdate));

                        // both must have the anchors in the extensions
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
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
                        let anchors: PerDomainTrustAnchor =
                            new_certificate_chain(CertificateParams::default(), case.signature_scheme()).into();
                        let old_chain = anchors.intermediate_certificate_chain.clone();
                        case.cfg.per_domain_trust_anchors = vec![anchors];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                        let new_anchors: PerDomainTrustAnchor =
                            new_certificate_chain(CertificateParams::default(), case.signature_scheme()).into();
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
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
                        assert_eq!(alice_anchors.len(), 1);
                        assert_eq!(alice_anchors, bob_anchors);
                        alice_anchors[0].validate(None).unwrap();
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
                        let anchors = new_certificate_chain(CertificateParams::default(), case.signature_scheme());
                        case.cfg.per_domain_trust_anchors = vec![anchors.clone().into()];
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

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
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        let bob_anchors = bob_central.per_domain_trust_anchors(&id).await;
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

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_decrypting_expired(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                        // adding anchors to group
                        let anchors = new_certificate_chain(
                            CertificateParams {
                                expiration: Duration::ZERO,
                                ..Default::default()
                            },
                            case.signature_scheme(),
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
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        assert_eq!(alice_anchors.len(), 1);
                        assert!(bob_central.per_domain_trust_anchors(&id).await.is_empty());
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
                        let id = conversation_id();
                        alice_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                        // adding anchors to group
                        let cert = new_self_signed_certificate(
                            CertificateParams {
                                org: "World Domination Inc".to_string(),
                                common_name: Some("World Domination".to_string()),
                                domain: None,
                                ..Default::default()
                            },
                            case.signature_scheme(),
                            false,
                        );

                        let ca =
                            new_self_signed_certificate(CertificateParams::default(), case.signature_scheme(), true);

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
                        let alice_anchors = alice_central.per_domain_trust_anchors(&id).await;
                        assert_eq!(alice_anchors.len(), 1);
                        assert!(bob_central.per_domain_trust_anchors(&id).await.is_empty());
                    })
                },
            )
            .await;
        }
    }
}
