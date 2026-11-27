//! Checking the credentials that enter a group.
//!
//! The old openmls fork asked our authentication service about every credential it met while processing: in key
//! packages, proposals, commits and the ratchet trees of welcomes and group infos. It rejected the message unless the
//! credential was valid or expired. Upstream openmls doesn't check credentials at all, and leaves it to us, so we do
//! the same checks after openmls has processed a message and before we merge it.

use std::borrow::Borrow;

use openmls::prelude::{
    Credential as MlsCredential, CredentialType as MlsCredentialType, KeyPackage, KeyPackageIn, ProtocolVersion,
    X509Credential,
};
use wire_e2e_identity::pki_env::{CredentialAuthenticationStatus, CredentialRef};

use super::{Error, Result, identity::credential_identity};
use crate::{
    OpenMlsError,
    mls_provider::{AuthenticationService, MlsProvider},
};

/// Check credentials with the authentication service, rejecting any it doesn't consider valid or expired, and any
/// we can't read an identity from.
///
/// This takes a slice, not an iterator: an iterator adapter held across the `await` makes callers' futures fail to be
/// `Send` in the FFI.
pub(crate) async fn validate_credentials(
    authentication_service: &AuthenticationService,
    credentials: &[impl Borrow<MlsCredential> + Sync],
) -> Result<()> {
    for credential in credentials.iter().map(Borrow::borrow) {
        // The authentication service only checks an X509 credential's chain. Without an identity, the member would
        // break everything that lists the group's members.
        credential_identity(credential)?;

        let status = match credential.credential_type() {
            MlsCredentialType::Basic => {
                authentication_service
                    .validate_credential(CredentialRef::Basic {
                        identity: credential.serialized_content(),
                    })
                    .await
            }
            MlsCredentialType::X509 => {
                let credential = X509Credential::try_from(credential.clone()).map_err(Error::DecodeX509Chain)?;
                let chain = credential
                    .certificates()
                    .iter()
                    .map(|certificate| certificate.as_slice())
                    .collect::<Vec<_>>();
                authentication_service
                    .validate_credential(CredentialRef::X509 { certificates: &chain })
                    .await
            }
            other => return Err(Error::UnsupportedCredentialType(other.into())),
        };

        if !matches!(
            status,
            CredentialAuthenticationStatus::Valid | CredentialAuthenticationStatus::Expired
        ) {
            return Err(Error::CredentialRejected(status));
        }
    }
    Ok(())
}

/// Validate key packages of members to add, and check their credentials.
///
/// openmls only takes key packages which have been validated.
pub(crate) async fn validate_key_packages(
    provider: &MlsProvider,
    key_packages: impl IntoIterator<Item = KeyPackageIn>,
) -> Result<Vec<KeyPackage>> {
    let key_packages = key_packages
        .into_iter()
        .map(|key_package| key_package.validate(provider.crypto(), ProtocolVersion::Mls10))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(OpenMlsError::wrap("validating key package"))?;
    validate_credentials(
        provider.authentication_service(),
        &key_packages
            .iter()
            .map(|key_package| key_package.leaf_node().credential())
            .collect::<Vec<_>>(),
    )
    .await?;
    Ok(key_packages)
}

#[cfg(test)]
mod tests {
    use openmls::prelude::{Certificate, KeyPackage, MlsMessageOut, X509Credential};
    use x509_cert::der::Encode as _;

    use crate::{
        CertificateBundle, ConversationConfiguration, Credential, CredentialRef,
        test_utils::{
            x509::{CertificateParams, X509TestChain},
            *,
        },
    };

    /// A key package of `session`'s, with a certificate from a CA no one else trusts.
    async fn untrusted_key_package(case: &TestContext, session: &SessionContext) -> KeyPackage {
        let mut untrusted_chain = X509TestChain::init_empty(case.signature_scheme());
        let certificate_bundle = untrusted_chain.issue_simple_certificate_bundle("mallory", None);
        let credential = Credential::x509(case.cipher_suite(), certificate_bundle).unwrap();
        let credential = session
            .transaction
            .add_credential_without_clientid_check(credential)
            .unwrap();
        session
            .new_keypackage_from_ref(CredentialRef::from_credential(&credential), None)
            .await
    }

    /// A key package of `session`'s, with a certificate from the trusted CA that has no client id in it.
    ///
    /// core-crypto doesn't make credentials like this, so this one is made from a valid credential by swapping in a
    /// certificate for the same key without the client id, as a client without our checks could.
    async fn key_package_without_client_id(case: &TestContext, session: &SessionContext) -> KeyPackage {
        let intermediate = session.x509_chain_unchecked().find_local_intermediate_ca();
        let [client_id] = case.client_ids();
        let certificate = intermediate.create_and_sign_end_identity(CertificateParams {
            client_id: Some(client_id),
            ..Default::default()
        });
        let mut credential = Credential::x509(
            case.cipher_suite(),
            CertificateBundle::from_certificate_and_issuer(&certificate, intermediate),
        )
        .unwrap();

        let without_client_id = intermediate.create_and_sign_end_identity(CertificateParams {
            client_id: None,
            cert_keypair: Some(certificate.pki_keypair.clone()),
            ..Default::default()
        });
        credential.mls_credential = X509Credential::new(
            [&without_client_id, intermediate]
                .map(|certificate| Certificate::new(certificate.certificate.to_der().unwrap()))
                .into(),
        )
        .try_into()
        .unwrap();

        // core-crypto can't load this credential to make a key package with it, so make one with openmls.
        let provider = session.transaction.mls_provider().await.unwrap();
        let inner = session.transaction.inner().unwrap();
        KeyPackage::builder()
            .leaf_node_capabilities(ConversationConfiguration::default_leaf_capabilities())
            .build(
                credential.cipher_suite.into(),
                &provider.with_transaction(inner.transaction()),
                &credential.signature_key_pair,
                credential.to_mls_credential_with_key(),
            )
            .unwrap()
            .into_key_package()
    }

    /// Add a member with openmls directly, skipping core-crypto's checks, as a client without them would.
    async fn add_unchecked(conversation: &TestConversation<'_>, key_package: KeyPackage) -> MlsMessageOut {
        let credential = conversation.credential().await;
        let provider = conversation.actor().transaction.crypto_provider().await.unwrap();
        conversation
            .guard()
            .await
            .mutate_group_test(async |tx, group, _| {
                let provider = provider.with_transaction(tx);
                let (commit, ..) = group
                    .add_members(&provider, &credential.signature_key_pair, &[key_package])
                    .unwrap();
                group.merge_pending_commit(&provider).unwrap();
                Ok(commit)
            })
            .await
            .unwrap()
    }

    macro_rules! assert_rejected {
        ($result:expr) => {
            assert!(innermost_source_matches!(
                $result.unwrap_err(),
                crate::mls::credential::Error::CredentialRejected(_)
            ))
        };
    }

    #[apply(all_cred_cipher)]
    async fn adding_a_member_with_an_untrusted_certificate_fails(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let [alice, mallory] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let key_package = untrusted_key_package(&case, &mallory).await;

        let result = conversation.guard().await.add_members(vec![key_package.into()]).await;

        assert_rejected!(result);
    }

    #[apply(all_cred_cipher)]
    async fn a_commit_adding_a_member_with_an_untrusted_certificate_is_rejected(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let [alice, bob, mallory] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let key_package = untrusted_key_package(&case, &mallory).await;
        let commit = add_unchecked(&conversation, key_package).await;

        let result = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(commit.to_bytes().unwrap())
            .await;

        assert_rejected!(result);
    }

    #[apply(all_cred_cipher)]
    async fn adding_a_member_without_a_client_id_fails(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let [alice, mallory] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let key_package = key_package_without_client_id(&case, &mallory).await;

        let result = conversation.guard().await.add_members(vec![key_package.into()]).await;

        assert!(innermost_source_matches!(
            result.unwrap_err(),
            crate::mls::credential::Error::InvalidIdentity
        ));
    }

    #[apply(all_cred_cipher)]
    async fn a_commit_adding_a_member_without_a_client_id_is_rejected(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let [alice, bob, mallory] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let key_package = key_package_without_client_id(&case, &mallory).await;
        let commit = add_unchecked(&conversation, key_package).await;

        let result = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(commit.to_bytes().unwrap())
            .await;

        assert!(innermost_source_matches!(
            result.unwrap_err(),
            crate::mls::credential::Error::InvalidIdentity
        ));
        assert!(
            conversation.guard_of(&bob).await.get_client_ids().await.is_ok(),
            "the rejected commit must leave the group's members readable"
        );
    }

    #[apply(all_cred_cipher)]
    async fn a_proposal_adding_a_member_with_an_untrusted_certificate_is_rejected(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let [alice, bob, mallory] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let key_package = untrusted_key_package(&case, &mallory).await;
        let credential = conversation.credential().await;
        let provider = alice.transaction.crypto_provider().await.unwrap();
        let proposal = conversation
            .guard()
            .await
            .mutate_group_test(async |tx, group, _| {
                let (proposal, _) = group
                    .propose_add_member(
                        &provider.with_transaction(tx),
                        &credential.signature_key_pair,
                        &key_package,
                    )
                    .unwrap();
                Ok(proposal)
            })
            .await
            .unwrap();

        let result = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(proposal.to_bytes().unwrap())
            .await;

        assert_rejected!(result);
    }

    #[apply(all_cred_cipher)]
    async fn a_welcome_to_a_group_with_an_untrusted_member_is_rejected(case: TestContext) {
        if !case.is_x509() {
            return;
        }
        let [alice, mallory, dave] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let key_package = untrusted_key_package(&case, &mallory).await;
        add_unchecked(&conversation, key_package).await;

        let dave_key_package = dave.new_keypackage(&case).await;
        conversation
            .guard()
            .await
            .add_members(vec![dave_key_package.into()])
            .await
            .unwrap();
        let welcome = conversation.transport().await.latest_welcome_message().await;

        let result = dave.transaction.process_welcome_message(welcome).await;

        assert_rejected!(result);
    }

    #[apply(all_cred_cipher)]
    async fn joining_a_group_with_an_untrusted_member_by_external_commit_fails_and_leaves_nothing_behind(
        case: TestContext,
    ) {
        if !case.is_x509() {
            return;
        }
        let [alice, mallory, guest] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let key_package = untrusted_key_package(&case, &mallory).await;
        add_unchecked(&conversation, key_package).await;
        let group_info = conversation.export_group_info().await;

        let result = guest
            .transaction
            .join_by_external_commit(group_info, &guest.initial_credential)
            .await;

        assert_rejected!(result);
        assert!(
            !guest
                .transaction
                .conversation_exists(conversation.id(), None)
                .await
                .unwrap(),
            "the rejected join must not leave a group behind"
        );
    }
}
