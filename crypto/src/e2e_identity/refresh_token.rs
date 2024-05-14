use super::E2eiEnrollment;
use crate::{
    prelude::{E2eIdentityError, E2eIdentityResult, MlsCentral},
    CryptoError, CryptoResult,
};
use core_crypto_keystore::{
    entities::{E2eiRefreshToken, UniqueEntity},
    CryptoKeystoreResult,
};
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::OpenMlsCryptoProvider;
use zeroize::Zeroize;

/// An OIDC refresh token managed by CoreCrypto to benefit from encryption-at-rest
#[derive(Debug, serde::Serialize, serde::Deserialize, Zeroize, derive_more::From, derive_more::Deref)]
#[zeroize(drop)]
pub struct RefreshToken(String);

impl E2eiEnrollment {
    /// Lets clients retrieve the OIDC refresh token to try to renew the user's authorization.
    /// If it's expired, the user needs to reauthenticate and they will update the refresh token
    /// in [E2eiEnrollment::new_oidc_challenge_request]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub fn get_refresh_token(&self) -> E2eIdentityResult<&str> {
        self.refresh_token
            .as_ref()
            .map(|rt| rt.as_str())
            .ok_or(E2eIdentityError::OutOfOrderEnrollment(
                "No OIDC refresh token registered yet or it has been persisted",
            ))
    }

    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub(crate) async fn replace_refresh_token(
        &self,
        backend: &MlsCryptoProvider,
        rt: RefreshToken,
    ) -> CryptoKeystoreResult<()> {
        let mut conn = backend.key_store().borrow_conn().await?;
        let rt = E2eiRefreshToken::from(rt);
        rt.replace(&mut conn).await
    }
}

impl MlsCentral {
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub(crate) async fn find_refresh_token(&self) -> CryptoResult<RefreshToken> {
        let mut conn = self.mls_backend.key_store().borrow_conn().await?;
        E2eiRefreshToken::find_unique(&mut conn).await?.try_into()
    }
}

impl TryFrom<E2eiRefreshToken> for RefreshToken {
    type Error = CryptoError;

    fn try_from(mut entity: E2eiRefreshToken) -> CryptoResult<Self> {
        let content = std::mem::take(&mut entity.content);
        Ok(Self(String::from_utf8(content)?))
    }
}

impl From<RefreshToken> for E2eiRefreshToken {
    fn from(mut rt: RefreshToken) -> Self {
        let content = std::mem::take(&mut rt.0);
        Self {
            content: content.into_bytes(),
        }
    }
}
