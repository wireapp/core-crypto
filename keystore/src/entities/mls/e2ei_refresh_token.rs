use zeroize::Zeroize;

use crate::traits::UnifiedUniqueEntityImplementationHelper;

/// OIDC refresh token used in E2EI
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct E2eiRefreshToken {
    pub content: Vec<u8>,
}

impl UnifiedUniqueEntityImplementationHelper for E2eiRefreshToken {
    const COLLECTION_NAME: &str = "e2ei_refresh_token";

    fn new(content: Vec<u8>) -> Self {
        Self { content }
    }

    fn content(&self) -> &[u8] {
        &self.content
    }
}
