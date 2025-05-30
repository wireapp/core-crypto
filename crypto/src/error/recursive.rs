#![allow(missing_docs)]

/// These errors wrap each of the module-specific errors in CoreCrypto.
///
/// The goal here is to reduce the need to redeclare each of these error
/// types as an individual variant of a module-specific error type.
#[derive(Debug)]
pub enum RecursiveError {
    Root {
        context: &'static str,
        source: Box<crate::Error>,
    },
    TransactionContext {
        context: &'static str,
        source: Box<crate::transaction_context::Error>,
    },
    E2e {
        context: &'static str,
        source: Box<crate::e2e_identity::Error>,
    },
    Mls {
        context: &'static str,
        source: Box<crate::mls::Error>,
    },
    MlsClient {
        context: &'static str,
        source: Box<crate::mls::session::Error>,
    },
    MlsConversation {
        context: &'static str,
        source: Box<crate::mls::conversation::Error>,
    },
    MlsCredential {
        context: &'static str,
        source: Box<crate::mls::credential::Error>,
    },
    #[cfg(test)]
    Test(Box<crate::test_utils::TestError>),
}

impl RecursiveError {
    pub fn root<E: Into<crate::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::Root {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub fn transaction<E: Into<crate::transaction_context::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::TransactionContext {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub fn e2e_identity<E: Into<crate::e2e_identity::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::E2e {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub fn mls<E: Into<crate::mls::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::Mls {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub fn mls_client<E: Into<crate::mls::session::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsClient {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub fn mls_conversation<E: Into<crate::mls::conversation::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsConversation {
            context,
            source: Box::new(into_source.into()),
        }
    }

    pub fn mls_credential<E: Into<crate::mls::credential::Error>>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |into_source| Self::MlsCredential {
            context,
            source: Box::new(into_source.into()),
        }
    }
}

impl std::fmt::Display for RecursiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(test)]
        use std::ops::Deref;

        let context = match self {
            RecursiveError::Root { context, .. } => context,
            RecursiveError::E2e { context, .. } => context,
            RecursiveError::Mls { context, .. } => context,
            RecursiveError::MlsClient { context, .. } => context,
            RecursiveError::MlsConversation { context, .. } => context,
            RecursiveError::MlsCredential { context, .. } => context,
            RecursiveError::TransactionContext { context, .. } => context,
            #[cfg(test)]
            RecursiveError::Test(e) => return e.deref().fmt(f),
        };
        write!(f, "{}", context)
    }
}

impl std::error::Error for RecursiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RecursiveError::Root { source, .. } => Some(source.as_ref()),
            RecursiveError::E2e { source, .. } => Some(source.as_ref()),
            RecursiveError::Mls { source, .. } => Some(source.as_ref()),
            RecursiveError::MlsClient { source, .. } => Some(source.as_ref()),
            RecursiveError::MlsConversation { source, .. } => Some(source.as_ref()),
            RecursiveError::MlsCredential { source, .. } => Some(source.as_ref()),
            RecursiveError::TransactionContext { source, .. } => Some(source.as_ref()),
            #[cfg(test)]
            RecursiveError::Test(source) => Some(source.as_ref()),
        }
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
    crate::mls::session::Error => MlsClient,
    crate::mls::conversation::Error => MlsConversation,
    crate::mls::credential::Error => MlsCredential,
    crate::transaction_context::Error => TransactionContext,
);
