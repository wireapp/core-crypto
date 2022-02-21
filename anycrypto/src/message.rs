// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::error::CryptoResult;

#[repr(C)]
pub enum Message<'a> {
    Proteus(Box<proteus::message::Message<'a>>),
    Mls(Box<openmls::framing::ApplicationMessage>),
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
            Message::Proteus(boxed_p_msg) => match boxed_p_msg.as_ref() {
                proteus::message::Message::Plain(p_msg) => Ok(p_msg.cipher_text.clone()),
                _ => Err(eyre::eyre!("Message is still ciphered!").into()),
            },
            Message::Mls(mls_msg) => Ok(mls_msg.message().into()),
        }
    }

    pub fn as_slice(&self) -> CryptoResult<&[u8]> {
        match self {
            Message::Proteus(boxed_p_msg) => match boxed_p_msg.as_ref() {
                proteus::message::Message::Plain(p_msg) => Ok(p_msg.cipher_text.as_slice()),
                _ => Err(eyre::eyre!("Message is still ciphered!").into()),
            },
            Message::Mls(mls_msg) => Ok(mls_msg.message()),
        }
    }
}
