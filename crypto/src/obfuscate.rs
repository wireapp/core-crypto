use crate::prelude::{ConversationId, HistorySecret};
use hex;

impl Obfuscate for &ConversationId {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(hex::encode(compute_hash(self)).as_str())
    }
}
