use crate::error::CryptoResult;

#[repr(C)]
pub enum Message<'a> {
    Proteus(proteus::message::Message<'a>),
    Mls(openmls::framing::ApplicationMessage),
}

impl std::fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proteus(arg0) => f.debug_tuple("Proteus").field(&"[REDACTED]").finish(),
            Self::Mls(arg0) => f.debug_tuple("Mls").field(arg0).finish(),
        }
    }
}

impl Message<'_> {
    pub fn to_vec(&self) -> CryptoResult<Vec<u8>> {
        match self {
            Message::Proteus(proteus::message::Message::Plain(p_msg)) => {
                Ok(p_msg.cipher_text.clone())
            },
            Message::Proteus(_) => Err(eyre::eyre!("Message is still ciphered!").into()),
            Message::Mls(mls_msg) => Ok(mls_msg.message().into()),
        }
    }

    pub fn as_slice(&self) -> CryptoResult<&[u8]> {
        match self {
            Message::Proteus(proteus::message::Message::Plain(p_msg)) => Ok(p_msg.cipher_text.as_slice()),
            Message::Proteus(_) => Err(eyre::eyre!("Message is still ciphered!").into()),
            Message::Mls(mls_msg) => Ok(mls_msg.message()),
        }
    }
}
