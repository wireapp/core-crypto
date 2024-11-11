/// Consumers of this library can use this to specify data to be persisted at the end of
/// a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ConsumerData {
    pub content: Vec<u8>,
}

impl From<Vec<u8>> for ConsumerData {
    fn from(content: Vec<u8>) -> Self {
        Self { content }
    }
}

impl From<ConsumerData> for Vec<u8> {
    fn from(consumer_data: ConsumerData) -> Self {
        consumer_data.content
    }
}
