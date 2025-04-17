use core_crypto::{InnermostErrorMessage as _, RecursiveError};

#[cfg(feature = "proteus")]
use crate::ProteusError;
use crate::{MlsError, error::log_error};
#[cfg(target_family = "wasm")]
use wasm_bindgen::JsValue;

#[derive(Debug, thiserror::Error)]
#[cfg_attr(target_family = "wasm", derive(strum::AsRefStr))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Error))]
pub enum CoreCryptoError {
    #[error(transparent)]
    Mls(#[from] MlsError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    Proteus(#[from] ProteusError),
    #[error("End to end identity error: {0}")]
    E2ei(String),
    #[cfg(target_family = "wasm")]
    #[error(transparent)]
    SerializationError(#[from] serde_wasm_bindgen::Error),
    #[cfg(target_family = "wasm")]
    #[error("Unknown ciphersuite identifier")]
    UnknownCiphersuite,
    #[cfg(target_family = "wasm")]
    #[error("Transaction rolled back due to unexpected JS error: {0:?}")]
    TransactionFailed(JsValue),
    #[cfg(not(target_family = "wasm"))]
    #[error("Transaction rolled back due to unexpected uniffi error: {0:?}")]
    TransactionFailed(String),
    #[error("{0}")]
    Other(String),
}

#[cfg(not(target_family = "wasm"))]
impl From<uniffi::UnexpectedUniFFICallbackError> for CoreCryptoError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::TransactionFailed(value.to_string())
    }
}

impl From<RecursiveError> for CoreCryptoError {
    fn from(error: RecursiveError) -> Self {
        log_error(&error);

        let innermost = {
            let mut err: &dyn std::error::Error = &error;
            while let Some(inner) = err.source() {
                err = inner;
            }
            err
        };

        // check if the innermost error is any kind of e2e error
        if let Some(err) = innermost.downcast_ref::<core_crypto::e2e_identity::Error>() {
            return CoreCryptoError::E2ei(err.to_string());
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
            core_crypto::LeafError::ConversationAlreadyExists(id) => MlsError::ConversationAlreadyExists(id.clone()).into(),
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
            #[cfg(feature="proteus")]
            e @ (
                core_crypto::ProteusErrorKind::ProteusDecodeError(_)
                | core_crypto::ProteusErrorKind::ProteusEncodeError(_)
                | core_crypto::ProteusErrorKind::ProteusInternalError(_)
                | core_crypto::ProteusErrorKind::ProteusSessionError(_)
                | core_crypto::ProteusErrorKind::Leaf(_)
            ) => ProteusError::from(e).into(),
            // The internal name is what we want, but renaming the external variant is a breaking change.
            // Since we're re-designing the `BufferedMessage` errors soon, it's not worth producing
            // an additional breaking change until then, so the names are inconsistent.
            core_crypto::mls::conversation::Error::BufferedForPendingConversation => MlsError::UnmergedPendingGroup.into(),
            ||=> MlsError::Other(error.innermost_error_message()).into(),
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
            core_crypto::Error::ProteusNotInitialized => Self::Other(error.to_string()),
            #[cfg(not(feature = "proteus"))]
            core_crypto::Error::ProteusNotInitialized => Self::Other("proteus not initialized".into()),
            #[cfg(feature = "proteus")]
            core_crypto::Error::Proteus(proteus) => {
                let error_code = proteus.source.error_code();
                if let Some(proteus_error) = ProteusError::from_error_code(error_code) {
                    Self::Proteus(proteus_error)
                } else {
                    Self::Other(format!("unknown proteus error code: {error_code:?}"))
                }
            }
            #[cfg(not(feature = "proteus"))]
            core_crypto::Error::Proteus(_proteus) => {
                unreachable!("we don't raise proteus errors when building without proteus")
            }
            core_crypto::Error::Mls(mls) => Self::Mls(MlsError::from(mls)),
            core_crypto::Error::InvalidTransactionContext => Self::Other(error.to_string()),
            core_crypto::Error::MlsTransportNotProvided => Self::Other(error.to_string()),
            core_crypto::Error::ErrorDuringMlsTransport(error_message) => Self::Other(error_message),
            core_crypto::Error::Keystore(keystore_error) => Self::Other(keystore_error.innermost_error_message()),
            core_crypto::Error::CryptoboxMigration(cryptobox) => Self::Other(cryptobox.innermost_error_message()),
            core_crypto::Error::Recursive(recursive_error) => recursive_error.into(),
            core_crypto::Error::FeatureDisabled(_) => Self::Other(error.to_string()),
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
    core_crypto::e2e_identity::Error,
    core_crypto::transaction_context::Error,
);

impl CoreCryptoError {
    pub(crate) fn generic<E>() -> impl FnOnce(E) -> Self
    where
        E: ToString,
    {
        |err| Self::Other(err.to_string())
    }

    pub(crate) fn ad_hoc(err: impl ToString) -> Self {
        Self::Other(err.to_string())
    }

    #[cfg(target_family = "wasm")]
    pub(crate) fn variant_name(&self) -> String {
        let mut out = self.as_ref().to_string() + "Error";
        match self {
            Self::Mls(mls) => out += mls.as_ref(),
            Self::Proteus(proteus) => out += proteus.as_ref(),
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
