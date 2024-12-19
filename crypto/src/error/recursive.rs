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
    /// Wrap a [crate::test_utils::TestError] for recursion.
    #[cfg(test)]
    #[error(transparent)]
    Test(#[from] Box<crate::test_utils::TestError>),
}

impl RecursiveError {
    /// Convert a [crate::Error] into a [RecursiveError], with context
    pub fn root<E: Into<crate::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::Root {
            context,
            source: Box::new(into_source.into()),
        }
    }

    /// Convert a [crate::e2e_identity::Error] into a [RecursiveError], with context
    pub fn e2e_identity<E: Into<crate::e2e_identity::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::E2e {
            context,
            source: Box::new(into_source.into()),
        }
    }

    /// Convert a [crate::mls::Error] into a [RecursiveError], with context
    pub fn mls<E: Into<crate::mls::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::Mls {
            context,
            source: Box::new(into_source.into()),
        }
    }

    /// Convert a [crate::mls::client::Error] into a [RecursiveError], with context
    pub fn mls_client<E: Into<crate::mls::client::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsClient {
            context,
            source: Box::new(into_source.into()),
        }
    }

    /// Convert a [crate::mls::conversation::Error] into a [RecursiveError], with context
    pub fn mls_conversation<E: Into<crate::mls::conversation::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsConversation {
            context,
            source: Box::new(into_source.into()),
        }
    }

    /// Convert a [crate::mls::credential::Error] into a [RecursiveError], with context
    pub fn mls_credential<E: Into<crate::mls::credential::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsCredential {
            context,
            source: Box::new(into_source.into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn test<E: Into<crate::test_utils::TestError>>() -> impl FnOnce(E) -> Self {
        move |into_source| Self::Test(Box::new(into_source.into()))
    }
}

/// Like [`Into`], but different, because we don't actually want to implement `Into` for our subordinate error types.
///
/// By forcing ourselves to map errors everywhere in order for question mark operators to work, we ensure that
pub trait ToRecursiveError {
    /// Construct a recursive error given the current context
    fn construct_recursive(self, context: &'static str) -> RecursiveError;
}

macro_rules! impl_to_recursive_error_for {
    ($($for:path => $variant:ident),+ $(,)?) => {
        $(
            impl ToRecursiveError for $for {
                fn construct_recursive(self, context: &'static str) -> RecursiveError {
                    RecursiveError::$variant {
                        context,
                        source: Box::new(self),
                    }
                }
            }
        )+
    };
}

impl_to_recursive_error_for!(
    crate::Error => Root,
    crate::e2e_identity::Error => E2e,
    crate::mls::Error => Mls,
    crate::mls::client::Error => MlsClient,
    crate::mls::conversation::Error => MlsConversation,
    crate::mls::credential::Error => MlsCredential,
);
