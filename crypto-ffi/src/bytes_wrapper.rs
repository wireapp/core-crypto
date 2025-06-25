/// Construct a FFI newtype wrapping a byte slice.
///
/// This macro just handles the boilerplate of constructing the wrapper.
macro_rules! bytes_wrapper {
    ($( #[ $attrs:meta ] )* $id:ident) => {
        $( #[ $attrs ] )*
        #[cfg_attr(target_family = "wasm", wasm_bindgen)]
        #[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
        pub struct $id(pub(crate) Vec<u8>);

        #[cfg_attr(target_family = "wasm", wasm_bindgen)]
        #[cfg_attr(not(target_family = "wasm"), uniffi::export)]
        impl $id {
            /// Construct a new instance, transferring data from the client layer to Rust.
            #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
            #[cfg_attr(not(target_family = "wasm"), uniffi::constructor)]
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            /// Get the raw bytes from this type, transferring data from Rust to the client layer.
            ///
            /// This does not consume the newtype, instead copying the internal data across the FFI boundary.
            pub fn copy_bytes(&self) -> Vec<u8> {
                self.0.clone()
            }
        }

        impl<T> From<T> for $id
        where
            T: Into<Vec<u8>>,
        {
            #[inline]
            fn from(value: T) -> Self {
                Self(value.into())
            }
        }

        impl std::ops::Deref for $id {
            type Target = Vec<u8>;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        paste::paste! {
            #[cfg(target_family = "wasm")]
            #[allow(dead_code)]
            pub(crate) type [<$id MaybeArc>] = $id;

            #[cfg(not(target_family = "wasm"))]
            #[allow(dead_code)]
            pub(crate) type [<$id MaybeArc>] = std::sync::Arc<$id>;
        }
    };
}

// This import is an idiom which makes it possible for other modules to
// import the macro from this module instead of from the root.
pub(crate) use bytes_wrapper;
