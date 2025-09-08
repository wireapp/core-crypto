use crate::prelude::{ClientId, ConversationId, HistorySecret};
use hex;

impl Obfuscate for &ConversationId {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(hex::encode(compute_hash(self)).as_str())
    }
}

impl Obfuscate for &ClientId {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(hex::encode(compute_hash(self)).as_str())
    }
}

impl Obfuscate for &HistorySecret {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HistorySecret")
            .field("client_id", &Obfuscated::from(&self.client_id))
            .field("key_package", &"<secret>")
            .finish()
    }
}
