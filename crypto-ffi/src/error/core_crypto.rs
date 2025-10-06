use core_crypto::{InnermostErrorMessage as _, RecursiveError};
#[cfg(target_family = "wasm")]
use wasm_bindgen::JsValue;

#[cfg(feature = "proteus")]
use crate::ProteusError;
use crate::{MlsError, error::log_error};

#[derive(Debug, thiserror::Error)]
#[cfg_attr(target_family = "wasm", derive(strum::AsRefStr))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Error))]
pub enum CoreCryptoError {
    #[error(transparent)]
    Mls {
        #[from]
        mls_error: MlsError,
    },
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    Proteus {
        #[from]
        exception: ProteusError,
    },
    #[error("End to end identity error: {e2ei_error}")]
    E2ei { e2ei_error: String },
    #[cfg(target_family = "wasm")]
    #[error(transparent)]
    SerializationError(#[from] serde_wasm_bindgen::Error),
    #[cfg(target_family = "wasm")]
    #[error("Unknown ciphersuite identifier")]
    UnknownCiphersuite,
    #[cfg(target_family = "wasm")]
    #[error("Transaction rolled back due to unexpected JS error: {error:?}")]
    TransactionFailed { error: JsValue },
    #[cfg(not(target_family = "wasm"))]
    #[error("Transaction rolled back due to unexpected uniffi error: {error:?}")]
    TransactionFailed { error: String },
    #[error("{msg}")]
    Other { msg: String },
}

#[cfg(not(target_family = "wasm"))]
impl From<uniffi::UnexpectedUniFFICallbackError> for CoreCryptoError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::TransactionFailed {
            error: value.to_string(),
        }
    }
}

impl From<RecursiveError> for CoreCryptoError {
    fn from(error: RecursiveError) -> Self {
        log_error(&error);

        let innermost = {
            let mut err: &dyn std::error::Error = &error;
            while let Some(inner) = err.source() {
                #[cfg(feature = "proteus")]
                // We cannot determine in all cases whether a recursive error is a proteus
                // error by just looking at the innermost type. That's because if a session
                // is not found, we're using `ConversationNotFoundError`, wrapped in a
                // `LeafError`, which is not proteus-specific. To avoid having to do
                // this check inside the loop, we'd have to introduce a proteus-specific
                // variant of `ConversationNotFound`.
                if let Some(inner) = inner.downcast_ref::<core_crypto::ProteusErrorKind>() {
                    return ProteusError::from(inner).into();
                }
                err = inner;
            }
            err
        };

        // check if the innermost error is any kind of e2e error
        if let Some(err) = innermost.downcast_ref::<core_crypto::e2e_identity::Error>() {
            return CoreCryptoError::E2ei {
                e2ei_error: err.to_string(),
            };
        }

        // What now? We only really care about the innermost variants, not the error stack, but that produces
        // an arbitrary set of types. We can't match against that!
        //
        // Or at least, not without the power of macros. We can use them to match against heterogenous types.

        /// Like [`matches!`], but with an out expression which can reference items captured by the pattern.
        ///
        /// Hopefully only ever use this in conjunction with `interior_matches!`, because for most sane
        /// circumstances, `if let` is the better design pattern.
        macro_rules! matches_option {
            // Without cfg attribute
            (
                $val:expr,
                $pattern:pat $(if $guard:expr)? => $out:expr
            ) => {
                match ($val) {
                    $pattern $(if $guard)? => Some($out),
                    _ => None,
                }
            };
            // With cfg attribute
            (
                $val:expr,
                #[cfg($meta:meta)]
                $pattern:pat $(if $guard:expr)? => $out:expr
            ) => {
                {
                    #[cfg($meta)]
                    let result = match ($val) {
                        $pattern $(if $guard)? => Some($out),
                        _ => None,
                    };
                    #[cfg(not($meta))]
                    let result = None;
                    result
                }
            };
        }

        /// This is moderately horrific and we hopefully will not require it anywhere else, but
        /// it solves a real problem here: how do we match against the innermost error variants,
        /// when we have a heterogenous set of types to match against?
        macro_rules! match_heterogenous {
            (
                $err:expr => {
                    $(
                        $( #[cfg($meta:meta)] )?
                        $pattern:pat $(if $guard:expr)? => $var:expr,
                    )*
                    ||=> $default:expr,
                }
            ) => {{
                if false { unreachable!() }
                $(
                    else if let Some(v) = matches_option!(
                        $err.downcast_ref(),
                        $( #[cfg($meta)] )?
                        Some($pattern) $(if $guard)? => $var
                    ) {
                        v
                    }
                )*
                else {
                    $default
                }
            }};
        }

        match_heterogenous!(innermost => {
            core_crypto::LeafError::ConversationAlreadyExists(id) => MlsError::ConversationAlreadyExists { conversation_id: id.clone().into() }.into(),
            core_crypto::mls::conversation::Error::BufferedFutureMessage{..} => MlsError::BufferedFutureMessage.into(),
            core_crypto::mls::conversation::Error::DuplicateMessage => MlsError::DuplicateMessage.into(),
            core_crypto::mls::conversation::Error::MessageEpochTooOld => MlsError::MessageEpochTooOld.into(),
            core_crypto::mls::conversation::Error::SelfCommitIgnored => MlsError::SelfCommitIgnored.into(),
            core_crypto::mls::conversation::Error::StaleCommit => MlsError::StaleCommit.into(),
            core_crypto::mls::conversation::Error::StaleProposal => MlsError::StaleProposal.into(),
            core_crypto::mls::conversation::Error::UnbufferedFarFutureMessage => MlsError::WrongEpoch.into(),
            core_crypto::mls::conversation::Error::BufferedCommit => MlsError::BufferedCommit.into(),
            core_crypto::mls::conversation::Error::MessageRejected { reason } => MlsError::MessageRejected { reason: reason.clone() }.into(),
            core_crypto::mls::conversation::Error::OrphanWelcome => MlsError::OrphanWelcome.into(),
            // The internal name is what we want, but renaming the external variant is a breaking change.
            // Since we're re-designing the `BufferedMessage` errors soon, it's not worth producing
            // an additional breaking change until then, so the names are inconsistent.
            core_crypto::mls::conversation::Error::BufferedForPendingConversation => MlsError::UnmergedPendingGroup.into(),
            ||=> MlsError::Other { msg: error.innermost_error_message() }.into(),
        })
    }
}

// This implementation is intended to be temporary; we're going to be completely restructuring the way we handle
// errors in `core-crypto` soon. We can replace this with better error patterns when we do.
//
// Certain error mappings could apply to both MLS and Proteus. In all such cases, we map them to the MLS variant.
// When we redesign the errors in `core-crypto`, these ambiguities should disappear anyway.
impl From<core_crypto::Error> for CoreCryptoError {
    fn from(error: core_crypto::Error) -> Self {
        log_error(&error);

        match error {
            #[cfg(feature = "proteus")]
            core_crypto::Error::ProteusNotInitialized => Self::Other { msg: error.to_string() },
            #[cfg(not(feature = "proteus"))]
            core_crypto::Error::ProteusNotInitialized => Self::Other {
                msg: "proteus not initialized".into(),
            },
            #[cfg(feature = "proteus")]
            core_crypto::Error::Proteus(proteus) => {
                let error_code = proteus.source.error_code();
                if let Some(proteus_error) = ProteusError::from_error_code(error_code) {
                    Self::Proteus {
                        exception: proteus_error,
                    }
                } else {
                    Self::Other {
                        msg: format!("unknown proteus error code: {error_code:?}"),
                    }
                }
            }
            #[cfg(not(feature = "proteus"))]
            core_crypto::Error::Proteus(_proteus) => {
                unreachable!("we don't raise proteus errors when building without proteus")
            }
            core_crypto::Error::Mls(mls) => Self::Mls {
                mls_error: MlsError::from(mls),
            },
            core_crypto::Error::InvalidTransactionContext => Self::Other { msg: error.to_string() },
            core_crypto::Error::MlsTransportNotProvided => Self::Other { msg: error.to_string() },
            core_crypto::Error::ErrorDuringMlsTransport(error_message) => Self::Other { msg: error_message },
            core_crypto::Error::Keystore(keystore_error) => Self::Other {
                msg: keystore_error.innermost_error_message(),
            },
            core_crypto::Error::Recursive(recursive_error) => recursive_error.into(),
            core_crypto::Error::FeatureDisabled(_) | core_crypto::Error::InvalidHistorySecret(_) => {
                Self::Other { msg: error.to_string() }
            }
        }
    }
}

/// We can't do a generic `impl<E: ToRecursiveError> From<E> for CoreCryptoError`
/// because that has the potential to cause breaking conflicts later on: what if
/// core-crypto later did `impl ToRecursiveError for core_crypto::Error`? That would
/// cause a duplicate `From` impl.
///
/// Instead, we explicitly specify every variant which can be converted to a
/// `CoreCryptoError`, and implement its `From` block directly.
macro_rules! impl_from_via_recursive_error {
    ($($t:ty),+ $(,)?) => {
        $(
            impl From<$t> for CoreCryptoError {
                fn from(error: $t) -> Self {
                    use core_crypto::ToRecursiveError;
                    error
                        .construct_recursive("this context string does not matter and gets immediately stripped")
                        .into()
                }
            }
        )*
    };
}

impl_from_via_recursive_error!(
    core_crypto::mls::Error,
    core_crypto::mls::conversation::Error,
    core_crypto::mls::credential::Error,
    core_crypto::e2e_identity::Error,
    core_crypto::transaction_context::Error,
);

impl CoreCryptoError {
    pub(crate) fn generic<E>() -> impl FnOnce(E) -> Self
    where
        E: ToString,
    {
        |err| Self::Other { msg: err.to_string() }
    }

    pub(crate) fn ad_hoc(err: impl ToString) -> Self {
        Self::Other { msg: err.to_string() }
    }

    #[cfg(target_family = "wasm")]
    pub(crate) fn variant_name(&self) -> String {
        let mut out = self.as_ref().to_string() + "Error";
        match self {
            Self::Mls { mls_error } => out += mls_error.as_ref(),
            Self::Proteus { exception } => out += exception.as_ref(),
            _ => {}
        }
        out
    }

    #[cfg(target_family = "wasm")]
    pub(crate) fn stack(&self) -> Vec<String> {
        let mut stack = Vec::new();
        let mut err: &dyn std::error::Error = self;
        stack.push(err.to_string());

        while let Some(source) = err.source() {
            stack.push(source.to_string());
            err = source;
        }

        stack
    }
}
