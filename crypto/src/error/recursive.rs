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

/// These errors wrap each of the module-specific errors in CoreCrypto.
///
/// The goal here is to reduce the need to redeclare each of these error
/// types as an individual variant of a module-specific error type.
#[derive(Debug, thiserror::Error)]
pub enum RecursiveError {
    /// Wrap a [crate::Error] for recursion.
    #[error("{context}")]
    Root {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::Error>,
    },
    /// Wrap a [crate::e2e_identity::Error] for recursion.
    #[error("{context}")]
    E2e {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::e2e_identity::Error>,
    },
    /// Wrap a [crate::mls::Error] for recursion.
    #[error("{context}")]
    Mls {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::mls::Error>,
    },
    /// Wrap a [crate::mls::client::Error] for recursion.
    #[error("{context}")]
    MlsClient {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::mls::client::Error>,
    },
    /// Wrap a [crate::mls::conversation::Error] for recursion.
    #[error("{context}")]
    MlsConversation {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::mls::conversation::Error>,
    },
    /// Wrap a [crate::mls::credential::Error] for recursion.
    #[error("{context}")]
    MlsCredential {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::mls::credential::Error>,
    },
}

impl RecursiveError {
    pub(crate) fn root<E: Into<crate::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::Root {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub(crate) fn e2e_identity<E: Into<crate::e2e_identity::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::E2e {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub(crate) fn mls<E: Into<crate::mls::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::Mls {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub(crate) fn mls_client<E: Into<crate::mls::client::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsClient {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub(crate) fn mls_conversation<E: Into<crate::mls::conversation::Error>>(
        context: &'static str,
    ) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsConversation {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub(crate) fn mls_credential<E: Into<crate::mls::credential::Error>>(
        context: &'static str,
    ) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsCredential {
            context,
            source: Box::new(into_source.into()),
        }
    }
}
