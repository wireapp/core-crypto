//! Uniffi uses `CoreCryptoError` directly. Wasm needs to wrap it in order to get proper error handling.
//! This module contains that Wasm special handling.

use js_sys::{Object, Reflect};
use wasm_bindgen::JsValue;

type InternalError = super::core_crypto::CoreCryptoError;

#[derive(Debug, thiserror::Error)]
pub struct CoreCryptoError(#[source] InternalError);

impl std::fmt::Display for CoreCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let (error_type, error_context) = self.get_type_and_context();
        // The context can hold arbitrary JS values, which are not guaranteed to be JSON-serializable.
        let context = js_sys::JSON::stringify(&error_context)
            .ok()
            .and_then(|context| context.as_string())
            .and_then(|context| serde_json::from_str(&context).ok())
            .unwrap_or_else(|| serde_json::json!({ "msg": "error context is not JSON-serializable" }));

        let json = serde_json::to_string(&serde_json::json!({
            "message": self.0.to_string(),
            "error_name": self.0.variant_name(),
            "error_stack": self.0.stack(),
            "type": error_type.to_string(),
            "context": context
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
        let (error_type, error_context) = val.get_type_and_context();
        stacked_error.set_field("type", error_type);
        stacked_error.set_field("context", &error_context);

        stacked_error.into()
    }
}

/// Describe a JS value we don't control without running JS code that can throw uncaught.
///
/// Context: The `Debug` impl of [`JsValue`] throws on e.g. circular arrays or errors with throwing getters,
/// which unwinds through wasm without running any destructors, just like a panic.
pub(super) fn describe_js_value(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| Reflect::get(value, &"message".into()).ok()?.as_string())
        .or_else(|| js_sys::JSON::stringify(value).ok()?.as_string())
        .unwrap_or_else(|| "<JS value without description>".into())
}

pub(super) trait JsErrorContext {
    fn get_context(&self) -> wasm_bindgen::JsValue;
}

pub(super) trait JsValueMutationExt: AsRef<JsValue> + From<JsValue> + wasm_bindgen::JsCast {
    fn new_with_property(property_key: &str, value: impl Into<JsValue>) -> Self {
        let target = Object::new().into();
        Reflect::set(&target, &property_key.into(), &value.into()).expect("mutating newly created js value");
        target.into()
    }

    fn set_field(&self, property: &str, value: impl Into<JsValue>) {
        Reflect::set(self.as_ref(), &property.into(), &value.into()).expect("mutating js value");
    }
}

impl<T> JsValueMutationExt for T where T: AsRef<JsValue> + From<JsValue> + wasm_bindgen::JsCast {}

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

    fn get_type_and_context(&self) -> (&str, wasm_bindgen::JsValue) {
        match &self.0 {
            e @ InternalError::Mls { mls_error } => (e.as_ref(), mls_error.get_context()),
            e @ InternalError::Proteus {
                exception: proteus_error,
            } => (e.as_ref(), proteus_error.get_context()),
            e @ InternalError::E2ei { e2ei_error } => {
                (e.as_ref(), JsValue::new_with_property("e2ei_error", e2ei_error))
            }

            e @ InternalError::SerializationError(_) => (e.as_ref(), JsValue::new_with_property("msg", e.to_string())),

            e @ InternalError::UnknownCiphersuite => (e.as_ref(), JsValue::new_with_property("msg", e.to_string())),
            e @ InternalError::TransactionFailed { error } => (e.as_ref(), JsValue::new_with_property("error", error)),
            e @ InternalError::Other { msg } => (e.as_ref(), JsValue::new_with_property("msg", msg)),
        }
    }
}
