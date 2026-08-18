#![allow(missing_docs)]

/// Attach context to an error which [`RecursiveError`] knows how to wrap.
///
/// By forcing ourselves to map errors everywhere in order for question mark operators to work, we ensure that we can
/// take the opportunity to include a little bit of manual context. Pervasively done, this means that our errors have
/// quite a lot of contextual information about the call stack and what precisely has gone wrong.
///
/// Implementing this trait is what lets [`RecursiveError::context`] select the right variant from the error's type
/// alone, so most call sites never need to name a variant. It also lets generic code wrap an arbitrary
/// module error without knowing which one it has; `core-crypto-ffi` relies on that.
pub trait ToRecursiveError {
    /// Construct a recursive error given the current context
    fn construct_recursive(self, context: &'static str) -> RecursiveError;
}

/// Build [`RecursiveError`] from a list of `Variant: SourceType => constructor` entries.
///
/// Each entry generates the enum variant, a `RecursiveError::<constructor>` helper, the
/// [`ToRecursiveError`] impl for the source type, and the `Display` and `Error::source` arms, so
/// wrapping a new error type is a one-line change here instead of four coordinated edits.
///
/// We hand-roll `Error` rather than deriving `thiserror::Error`, and that is deliberate:
/// given `#[source] source: Box<E>`, thiserror hands `&Box<E>` to the error chain, and
/// `downcast_ref::<E>()` does not match that. Both the ffi error mapping in `core-crypto-ffi` and
/// the `innermost_source_matches!` test helper downcast to the concrete error type, so the chain
/// has to expose `&E` via `Box::as_ref`.
macro_rules! recursive_error {
    ($(
        $( #[cfg($meta:meta)] )*
        $variant:ident : $source:path => $constructor:ident ;
    )+) => {
        /// These errors wrap each of the module-specific errors in CoreCrypto.
        ///
        /// The goal here is to reduce the need to redeclare each of these error
        /// types as an individual variant of a module-specific error type.
        #[derive(Debug, derive_more::Display)]
        pub enum RecursiveError {
            $(
                $( #[cfg($meta)] )*
                #[display("{context}")]
                $variant {
                    context: &'static str,
                    source: Box<$source>,
                },
            )+
        }

        impl RecursiveError {
            $(
                /// Wrap an error convertible into
                // deliberately not an intra-doc link: some of these targets are `pub(crate)`, and a
                // public doc comment may not link to a private item.
                #[doc = concat!("`", stringify!($source), "`,")]
                /// given the current context.
                ///
                /// Prefer [`Self::context`] unless you are relying on the `Into` conversion.
                $( #[cfg($meta)] )*
                pub fn $constructor<E: Into<$source>>(context: &'static str) -> impl FnOnce(E) -> Self {
                    move |into_source| Self::$variant {
                        context,
                        source: Box::new(into_source.into()),
                    }
                }
            )+
        }

        impl std::error::Error for RecursiveError {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(
                        $( #[cfg($meta)] )*
                        Self::$variant { source, .. } => Some(source.as_ref()),
                    )+
                }
            }
        }

        $(
            $( #[cfg($meta)] )*
            impl ToRecursiveError for $source {
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

recursive_error! {
    Root: crate::Error => root;
    TransactionContext: crate::transaction_context::Error => transaction;
    E2e: wire_e2e_identity::E2eIdentityError => e2e_identity;
    MlsClient: crate::mls::session::Error => mls_client;
    MlsConversation: crate::mls::conversation::Error => mls_conversation;
    MlsCredential: crate::mls::credential::Error => mls_credential;
    #[cfg(test)]
    Test: crate::test_utils::TestError => test;
}

impl RecursiveError {
    /// Wrap any error which [`RecursiveError`] knows how to wrap, given the current context.
    ///
    /// The variant is selected from the error's type, so this is usually what you want:
    ///
    /// ```ignore
    /// self.session().await.map_err(RecursiveError::context("getting mls client"))?
    /// ```
    ///
    /// This only accepts the module error types themselves. When you need to convert first, for
    /// instance because you are holding a [`crate::TlsCodecError`] which several module errors
    /// can absorb, reach for the variant-specific constructor such as
    /// [`Self::mls_conversation`] instead.
    pub fn context<E: ToRecursiveError>(context: &'static str) -> impl FnOnce(E) -> Self {
        move |source| source.construct_recursive(context)
    }
}
