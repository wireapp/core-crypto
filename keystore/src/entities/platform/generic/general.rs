use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{ConsumerData, EntityBase, UniqueEntity},
    MissingKeyErrorKind,
};

#[async_trait::async_trait]
impl UniqueEntity for ConsumerData {
    fn new(content: Vec<u8>) -> Self {
        Self { content }
    }

    fn content(&self) -> &[u8] {
        &self.content
    }
}

#[async_trait::async_trait]
impl EntityBase for ConsumerData {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "consumer_data";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ConsumerData
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::ConsumerData(self)
    }
}
