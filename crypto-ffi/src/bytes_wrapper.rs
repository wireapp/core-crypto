/// Construct a FFI newtype wrapping a byte slice.
///
/// This macro just handles the boilerplate of constructing the wrapper.
macro_rules! bytes_wrapper {
    ($( #[ $attrs:meta ] )* $id:ident) => {
        $( #[ $attrs ] )*
        #[derive(uniffi::Object)]
        #[uniffi::export(Eq, Hash, Display)]
        #[derive(PartialEq, Eq, Hash)]
        pub struct $id(pub(crate) Vec<u8>);

        #[uniffi::export]
        impl $id {
            /// Construct a new instance, transferring data from the client layer to Rust.
            #[uniffi::constructor]
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

        impl std::fmt::Display for $id {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&hex::encode(&self))
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

        impl AsRef<[u8]> for $id {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        paste::paste! {
            #[allow(dead_code)]
            pub(crate) type [<$id MaybeArc>] = std::sync::Arc<$id>;

            #[allow(dead_code)]
            #[inline]
            pub(crate) fn [<$id:snake _coerce_maybe_arc>]<'a>(value: impl Into<std::borrow::Cow<'a, [u8]>>) -> [<$id MaybeArc>] {
                std::sync::Arc::new($id(value.into().into_owned()))
            }
        }
    };
}

// This import is an idiom which makes it possible for other modules to
// import the macro from this module instead of from the root.
pub(crate) use bytes_wrapper;
