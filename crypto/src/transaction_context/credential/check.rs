use core_crypto_keystore::{
    entities::E2eiCrl,
    traits::{CryptoTransaction as _, FetchFromDatabase},
};
use wire_e2e_identity::x509_check::extract_crl_uris;
use x509_cert::Certificate;

use super::{Error, Result};
use crate::{
    Credential, CredentialRef, CredentialType, KeystoreError, MlsConversation, RecursiveError,
    mls::credential::{
        crl::{CrlUris, extract_crl_uris_from_credentials, extract_crl_uris_from_group},
        ext::CredentialExt as _,
    },
    transaction_context::TransactionContext,
};

impl TransactionContext {
    /// This function must be called at least once every 24 hours. It is recommended to do this during an idle period,
    /// because in case x509 credentials are used, HTTP requests are done to fetch new certificate revocation lists.
    pub async fn check_credentials(&self) -> Result<()> {
        let database = self.database().await?;
        let pki_env = self.pki_environment().await?;

        let credentials = Credential::get_all(&database)
            .await
            .map_err(RecursiveError::mls_credential("getting all credentials"))?;
        let trust_anchor = pki_env
            .trust_anchor()
            .await
            .map_err(RecursiveError::e2e_identity("reading trust anchor cert"))?;
        let conversations_with_id =
            MlsConversation::load_all(&database)
                .await
                .map_err(RecursiveError::mls_conversation(
                    "loading all conversations to check if the credential to be removed is present",
                ))?;
        let conversations = conversations_with_id
            .iter()
            .map(|conversation_with_id| conversation_with_id.1);
        let relevant_crl_uris = Self::get_crl_uris(trust_anchor, credentials.iter(), conversations).await?;

        self.clean_up_irrelevant_crls(&relevant_crl_uris).await?;

        let crls = pki_env
            .fetch_crls(relevant_crl_uris.iter().map(AsRef::as_ref))
            .await
            .map_err(RecursiveError::e2e_identity("fetching crls"))?;

        // store fresh CRLs
        for (crl_uri, crl) in crls {
            self.e2ei_register_crl(crl_uri, crl).await?;
        }

        let mut invalid_credential_refs = Vec::new();

        // check our own credentials for expiration or revocation
        for credential in credentials {
            if self.check_credential(&credential).await.is_err() {
                invalid_credential_refs.push(CredentialRef::from_credential(&credential));
            }
        }

        if !invalid_credential_refs.is_empty() {
            return Err(Error::InvalidCredentials(invalid_credential_refs));
        }

        Ok(())
    }

    /// To get CRL URLs, we want to consider all sources of relevant certificates:
    /// - the stored credentials
    /// - the trust anchor
    /// - MLS groups
    async fn get_crl_uris(
        trust_anchor: Certificate,
        credentials: impl Iterator<Item = &Credential>,
        conversations: impl Iterator<Item = &MlsConversation>,
    ) -> Result<CrlUris> {
        let mls_credentials = credentials
            .filter(|credential| credential.credential_type == CredentialType::X509)
            .map(|credential| credential.mls_credential().mls_credential());

        let mut crl_uris = extract_crl_uris_from_credentials(mls_credentials).map_err(
            RecursiveError::mls_credential("extracting CRL URLs from stored credentials"),
        )?;

        crl_uris.extend(
            extract_crl_uris(&trust_anchor)
                .map_err(RecursiveError::e2e_identity("extracting CRL URL from trust anchor"))?
                .unwrap_or_default(),
        );

        for conversation in conversations {
            let uris_from_group = extract_crl_uris_from_group(conversation.group())
                .map_err(RecursiveError::mls_credential("extracting CRL URLs from MLS groups"))?;
            crl_uris.extend(uris_from_group);
        }

        Ok(crl_uris)
    }

    async fn check_credential(&self, credential: &Credential) -> Result<()> {
        let pki_env = self.pki_environment().await?;
        let provider = pki_env.mls_pki_env_provider();
        let auth_service_arc = provider.borrow().await;
        let Some(pki_env) = auth_service_arc.as_ref() else {
            return Err(crate::transaction_context::e2e_identity::Error::PkiEnvironmentUnset.into());
        };
        let Some(cert) = credential
            .mls_credential()
            .parse_leaf_cert()
            .map_err(RecursiveError::mls_credential("parsing leaf certificate"))?
        else {
            return Err(Error::InvalidCredential);
        };
        pki_env
            .validate_cert_and_revocation(&cert)
            .map_err(RecursiveError::e2e_identity("validating credential certificate"))?;
        Ok(())
    }

    async fn clean_up_irrelevant_crls(&self, relevant_crl_uris: &CrlUris) -> Result<()> {
        let database = self.database().await?;
        for db_crl in database
            .load_all::<E2eiCrl>()
            .await
            .map_err(KeystoreError::wrap("getting all database CRLs"))?
        {
            if !relevant_crl_uris.contains(&db_crl.distribution_point) {
                database
                    .remove::<E2eiCrl>(&db_crl.distribution_point)
                    .await
                    .map_err(KeystoreError::wrap("removing irrelevant CRL"))?;
            }
        }
        Ok(())
    }
}
