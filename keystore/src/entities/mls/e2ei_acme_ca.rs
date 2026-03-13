use zeroize::Zeroize;

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct E2eiAcmeCA {
    pub content: Vec<u8>,
}

impl crate::traits::UnifiedUniqueEntityImplementationHelper for E2eiAcmeCA {
    const COLLECTION_NAME: &str = "e2ei_acme_ca";

    fn new(content: Vec<u8>) -> Self {
        Self { content }
    }

    fn content(&self) -> &[u8] {
        &self.content
    }
}
