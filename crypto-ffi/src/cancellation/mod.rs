//! # CoreCryptoCancellationToken
//!
//! The [CoreCryptoCancellationToken] is supposed, but in theory not limited, to be used in
//! [crate::CoreCryptoFfi::transaction_ffi_cancellable]. This describes the implementation and intended usage which
//! matches the current usage in that function.
//!
//! ## How Cancellation Works
//! To make a future cancellable, we race the future against [CoreCryptoCancellationToken::cancelled] using
//! [futures_util::select_biased], with a bias for [CoreCryptoCancellationToken::cancelled] - in case both futures
//! complete at the same time, cancellation is preferred. If cancellation wins, we return an appropriate error.
//!
//! ## Sharing the Cancellation Token With Foreign Callbacks
//! Cancellation needs to cause rust futures currently waiting for foreign callbacks to stop waiting, i.e., be dropped.
//! This is because when they are dropped, the uniffi-generated swift code will cancel the task that is running the
//! foreign callback. To share an existing token with callbacks, [crate::CoreCryptoFfi] has a clonable
//! [CancellationSlot], with space for a single token.
//! To fill a slot, call [CancellationSlot::enter]. This will return a [slot::CancellationGuard] which empties the slot
//! when dropped. [CancellationSlot::enter] will panic if called while the slot is still filled.
//! [crate::CoreCryptoFfi::transaction_ffi_cancellable] ensures that this constraint isn't violated by only filling the
//! slot after the transaction semaphore was acquired. *This constraint makes the [CancellationSlot] currently only
//! usable in transactions*.
//! The slot is cloned to this crate's structs implementing foreign traits, currently [crate::MlsTransport] and
//! [crate::PkiEnvironmentHooks]. Trait method implementations can then use the token from the slot to race against its
//! cancellation as described [above](#how-cancellation-works).
//! The [crate::MlsTransport] struct receives its [CancellationSlot] clone directly from [crate::CoreCryptoContext]
//! during [crate::CoreCryptoContext::mls_init].
//! In case of [crate::PkiEnvironmentHooks] it is simpler to provide it with its own cancellation slot that is
//! explicitly filled with the same token during the transaction. That is because of the undetermined initialization
//! order (it may be initialized before or after [crate::CoreCryptoFfi]).

mod slot;
mod token;

pub(crate) use slot::CancellationSlot;
pub use token::CoreCryptoCancellationToken;
