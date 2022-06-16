use crate::credential::CredentialSupplier;
use crate::{ConversationId, ConversationMember, CryptoResult};
use mls_crypto_provider::MlsCryptoProvider;
pub use rstest::*;
pub use rstest_reuse::{self, *};

#[template]
#[export]
#[rstest(
    credential,
    case::credential_basic(CertificateBundle::rnd_basic()),
    case::credential_x509(CertificateBundle::rnd_certificate_bundle())
)]
#[allow(non_snake_case)]
pub fn all_credential_types(credential: crate::credential::CredentialSupplier) {}

pub fn conversation_id() -> ConversationId {
    let uuid = uuid::Uuid::new_v4();
    ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()))
}

/// Typically client creating a conversation
pub async fn alice(credential: CredentialSupplier) -> CryptoResult<(MlsCryptoProvider, ConversationMember)> {
    new_client("alice", credential).await
}

/// Typically client joining the conversation initiated by [alice]
pub async fn bob(credential: CredentialSupplier) -> CryptoResult<(MlsCryptoProvider, ConversationMember)> {
    new_client("bob", credential).await
}

/// A third client
pub async fn charlie(credential: CredentialSupplier) -> CryptoResult<(MlsCryptoProvider, ConversationMember)> {
    new_client("charlie", credential).await
}

async fn new_client(
    name: &str,
    credential: CredentialSupplier,
) -> CryptoResult<(MlsCryptoProvider, ConversationMember)> {
    let backend = init_keystore(name).await;
    let member = ConversationMember::random_generate(&backend, credential).await?;
    Ok((backend, member))
}

#[inline(always)]
pub async fn init_keystore(identifier: &str) -> MlsCryptoProvider {
    MlsCryptoProvider::try_new_in_memory(identifier).await.unwrap()
}
