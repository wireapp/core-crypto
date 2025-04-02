//! Uniffi uses `CoreCryptoError` directly. Wasm needs to wrap it in order to get proper error handling.
//! This module contains that Wasm special handling.

type InternalError = super::core_crypto::CoreCryptoError;

#[derive(Debug, thiserror::Error)]
pub struct CoreCryptoError(#[source] InternalError);

impl std::fmt::Display for CoreCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let proteus_error_code = match &self.0 {
            InternalError::Proteus(crate::ProteusError::Other(code)) => Some(*code),
            _ => None,
        };

        let json = serde_json::to_string(&serde_json::json!({
            "message": self.0.to_string(),
            "error_name": self.0.variant_name(),
            "error_stack": self.0.stack(),
            "proteus_error_code": proteus_error_code,
        }))
        .map_err(|_| std::fmt::Error)?;

        write!(f, "{json}")
    }
}

impl<T> From<T> for CoreCryptoError
where
    T: Into<InternalError>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl From<CoreCryptoError> for wasm_bindgen::JsValue {
    fn from(val: CoreCryptoError) -> Self {
        fn construct_error_stack(err: &dyn std::error::Error) -> js_sys::Error {
            let out = js_sys::Error::new(&err.to_string());
            if let Some(source) = err.source() {
                let source_value = construct_error_stack(source);
                out.set_cause(&source_value);
            }
            out
        }

        let stacked_error = construct_error_stack(&val);
        stacked_error.set_name(&val.0.variant_name());

        stacked_error.into()
    }
}

impl CoreCryptoError {
    pub(crate) fn generic<E>() -> impl FnOnce(E) -> Self
    where
        E: ToString,
    {
        |err| Self(InternalError::generic()(err))
    }

    pub(crate) fn ad_hoc(err: impl ToString) -> Self {
        Self(InternalError::ad_hoc(err))
    }
}
