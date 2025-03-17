pub(crate) mod core_crypto;
pub(crate) mod internal;
pub(crate) mod mls;
#[cfg(feature = "proteus")]
pub(crate) mod proteus;

pub type CoreCryptoResult<T, E = core_crypto::CoreCryptoError> = Result<T, E>;
#[cfg(target_family = "wasm")]
pub type WasmCryptoResult<T> = CoreCryptoResult<T, core_crypto::CoreCryptoError>;

/// Prepare and dispatch a log message reporting this error.
///
/// We want to ensure consistent logging every time we pass a log message across the FFI boundary,
/// as we cannot guarantee the method, format, or existence of error logging once the result crosses.
/// Unfortunately, as there is no single point at which we convert internal errors to trans-ffi
/// errors, we need to extract the logging procedure and ensure it's called at each relevant point.
///
/// This has the further disadvantage that we have very little context information at the point of
/// logging. We'll try this out for now anyway; if it turns out that we need to add more tracing
/// in the future, we can figure out our techniques then.
fn log_error(error: &dyn std::error::Error) {
    // we exclude the original error message from the chain
    let chain = {
        let mut error = error;
        let mut chain = Vec::new();
        while let Some(inner) = error.source() {
            chain.push(inner.to_string());
            error = inner;
        }
        chain
    };
    let msg = error.to_string();
    let err = serde_json::json!({"msg": msg, "chain": chain});
    // even though there exists a `:err` formatter, it only captures the top-level
    // message from the error, so it's still worth building our own inner error formatter
    // and using serde here
    log::warn!(target: "core-crypto", err:serde; "core-crypto returning this error across ffi; see recent log messages for context");
}
