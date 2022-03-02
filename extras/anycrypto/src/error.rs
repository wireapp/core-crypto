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

#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error(transparent)]
    MlsGroupError(#[from] openmls::group::MlsGroupError),
    #[error(transparent)]
    MlsErrorString(#[from] openmls::error::ErrorString),
}

#[derive(Debug, thiserror::Error)]
pub enum ProteusError {
    #[error(transparent)]
    ProteusSessionError(#[from] proteus::session::Error<Box<ProteusError>>),
    #[error(transparent)]
    ProteusDecodeError(#[from] proteus::DecodeError),
    #[error(transparent)]
    ProteusEncodeError(#[from] proteus::EncodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Couldn't find {protocol} conversation with id {conversation}")]
    ConversationNotFound {
        protocol: crate::Protocol,
        conversation: crate::central::ConversationId,
    },
    #[error(transparent)]
    KeyStoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    #[error(transparent)]
    MlsError(#[from] MlsError),
    #[error(transparent)]
    ProteusError(#[from] ProteusError),
    #[error("The requested ({0}) configuration is not contained in this package")]
    ConfigurationMismatch(crate::Protocol),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
