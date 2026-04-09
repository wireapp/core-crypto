/// Encapsulates a prekey id and a CBOR-serialized prekey.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProteusAutoPrekeyBundle {
    /// Prekey id (automatically incremented)
    pub id: u16,
    /// CBOR serialization of prekey
    pub pkb: Vec<u8>,
}
