//! Types and functions which support the entities (i.e. as primary or search keys) without themselves being entities.

mod conversation_epochs_older_than;
mod conversation_id;
pub(crate) mod helpers;
mod message_rx_counter_key;

pub use conversation_epochs_older_than::ConversationEpochsOlderThan;
pub use conversation_id::{ConversationId, ConversationIdRef};
pub use message_rx_counter_key::{MessageRxCounterPk, MessageRxCounterPkRef};
