use crate::{
    MissingKeyErrorKind,
    connection::KeystoreDatabaseConnection,
    entities::{E2eiRefreshToken, EntityBase, UniqueEntity},
};

#[async_trait::async_trait(?Send)]
impl EntityBase for E2eiRefreshToken {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "e2ei_refresh_token";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::E2eiRefreshToken
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::E2eiRefreshToken(self)
    }
}

#[async_trait::async_trait(?Send)]
impl UniqueEntity for E2eiRefreshToken {
    fn content(&self) -> &[u8] {
        &self.content
    }

    fn set_content(&mut self, content: Vec<u8>) {
        self.content = content;
    }
}
