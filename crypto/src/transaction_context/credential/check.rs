use core_crypto_keystore::{entities::E2eiCrl, traits::FetchFromDatabase};
use wire_e2e_identity::x509_check::extract_crl_uris;
use x509_cert::Certificate;

use super::{Error, Result};
use crate::{
    Credential, CredentialRef, CredentialType, KeystoreError, RecursiveError,
    mls::{
        conversation::Conversation,
        credential::crl::{CrlUris, extract_crl_uris_from_credentials, extract_crl_uris_from_group},
    },
    transaction_context::TransactionContext,
};

impl TransactionContext {
    /// Check all X509 credentials for expiration and revocation
    /// This function must be called at least once every 24 hours. It is recommended to do this during an idle period,
    /// because in case x509 credentials are used, HTTP requests are done to fetch new certificate revocation lists.
    pub async fn check_credentials(&self) -> Result<()> {
        let database = self.database().await?;
        let env = self.pki_environment().await?;

        let credentials = Credential::get_all(&database)
            .await
            .map_err(RecursiveError::mls_credential("getting all credentials"))?;
        let trust_anchors = env.get_trust_anchors().await;

        let session = self.session().await?;
        let conversations = Conversation::load_all(session)
            .await
            .map_err(RecursiveError::mls_conversation(
                "loading all conversations to check if the credential to be removed is present",
            ))?;
        let relevant_crl_uris =
            Self::get_crl_uris(trust_anchors.iter(), credentials.iter(), conversations.values()).await?;

        self.clean_up_irrelevant_crls(&relevant_crl_uris).await?;

        let crls = env
            .fetch_crls(relevant_crl_uris.iter().map(AsRef::as_ref))
            .await
            .map_err(RecursiveError::e2e_identity("fetching crls"))?;

        // store fresh CRLs
        for (crl_uri, crl) in crls {
            env.save_crl(&crl_uri, &crl)
                .await
                .map_err(RecursiveError::e2e_identity("saving CRL"))?;
        }

        let mut invalid_credential_refs = Vec::new();

        // Check our own x509 credentials for expiration or revocation
        // Ideally, we can load credentials by type from db as we actually only care about X509 checks.
        // Unfortunately, this is not supported yet.
        for credential in credentials {
            if credential.check(&env).await.is_err() {
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
        trust_anchors: impl Iterator<Item = &Certificate>,
        credentials: impl Iterator<Item = &Credential>,
        conversations: impl Iterator<Item = &Conversation>,
    ) -> Result<CrlUris> {
        let mls_credentials = credentials
            .filter(|credential| credential.credential_type == CredentialType::X509)
            .map(|credential| credential.mls_credential().mls_credential());

        let mut crl_uris = extract_crl_uris_from_credentials(mls_credentials).map_err(
            RecursiveError::mls_credential("extracting CRL URLs from stored credentials"),
        )?;

        for trust_anchor in trust_anchors {
            crl_uris.extend(
                extract_crl_uris(trust_anchor)
                    .map_err(RecursiveError::e2e_identity("extracting CRL URL from trust anchor"))?
                    .unwrap_or_default(),
            );
        }

        for conversation in conversations {
            let uris_from_group = extract_crl_uris_from_group(&*conversation.group().await)
                .map_err(RecursiveError::mls_credential("extracting CRL URLs from MLS groups"))?;
            crl_uris.extend(uris_from_group);
        }

        Ok(crl_uris)
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
