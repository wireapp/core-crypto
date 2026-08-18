/// A TLS codec operation failed, but we captured some context about which item it was coding
#[derive(Debug, thiserror::Error)]
#[error("TLS {direction} {item}")]
pub struct TlsCodecError {
    direction: &'static str,
    item: &'static str,
    #[source]
    source: tls_codec::Error,
}

impl TlsCodecError {
    /// Wrap a failure to TLS-serialize `item`
    pub fn serialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self {
            direction: "serializing",
            item,
            source,
        }
    }

    /// Wrap a failure to TLS-deserialize `item`
    pub fn deserialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self {
            direction: "deserializing",
            item,
            source,
        }
    }
}
