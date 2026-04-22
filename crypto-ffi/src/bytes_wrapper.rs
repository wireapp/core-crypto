/// Construct a FFI newtype wrapping a byte slice.
///
/// This macro just handles the boilerplate of constructing the wrapper.
macro_rules! bytes_wrapper_old {
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
    };
}

// This import is an idiom which makes it possible for other modules to
// import the macro from this module instead of from the root.
pub(crate) use bytes_wrapper_old;

/// Construct a FFI newtype wrapping a CC type wrapping a byte slice.
///
/// This macro handles the boilerplate of constructing the wrapper and defining some convenience
/// methods and trait implementations on it.
///
/// There are separate branches for fallible and infallible wrapping.
///
/// ## Infallible wrappers
///
/// Certain byte newtypes are infallible: any sequence of bytes is valid.
/// For these types, use this wrapper form:
///
/// ```rust,ignore
/// bytes_wrapper!(Foo infallibly wraps core_crypto::Foo);
/// ```
///
/// This invocation requires that `core_crypto::Foo` implements `From<Vec<u8>>`.
///
/// ## Fallible wrappers
///
/// Certain byte newtypes are fallible: some sequences of bytes are invalid.
/// For these types, use this wrapper form:
///
/// ```rust,ignore
/// bytes_wrapper!(Foo fallibly wraps core_crypto::Foo);
/// ```
///
/// This invocation requires that `core_crypto::Foo` implements `TryFrom<Vec<u8>>`
/// with an error type which implements `Into<CoreCryptoError>`.
///
/// ### Mapping Errors
///
/// In case an error mapping is required for the constructor of a fallible wrapper, use this syntax:
///
/// ```rust,ignore
/// bytes_wrapper!(Foo fallibly wraps core_crypto::Foo; constructor_map_error(|_| CoreCryptoError::Foo));
/// ```
///
/// ## Copying bytes back out
///
/// Append `; copy_bytes` to any invocation to generate a `copy_bytes` method visible through FFI.
/// The wrapped type must impl `Clone + Into<Vec<u8>>` for this to compile.
///
/// ```rust,ignore
/// bytes_wrapper!(Foo infallibly wraps core_crypto::Foo; copy_bytes);
/// bytes_wrapper!(Foo fallibly wraps core_crypto::Foo; copy_bytes);
/// bytes_wrapper!(Foo fallibly wraps core_crypto::Foo; constructor_map_err(|_| ...); copy_bytes);
/// ```
///
/// ## Derives
///
/// This macro automatically implements `#[derive(derive_more::From, derive_more::Into, derive_more::Deref,
/// derive_more::DerefMut, uniffi::Object)]` for the produced type.
///
/// Other annotations, including documentation, are passed through.
/// This is the recommended method for adding derives to the produced item.
macro_rules! bytes_wrapper {
    // === Infallible, without copy_bytes ===
    ($( #[ $attrs:meta ] )* $id:ident infallibly wraps $wrapped:path) => {
        bytes_wrapper!(@DEFINITION $( #[ $attrs ] )* $id; $wrapped);

        #[uniffi::export]
        impl $id {
            /// Infallibly instantiate an instance from a byte array.
            #[uniffi::constructor]
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes.into())
            }
        }
    };

    // === Infallible, with copy_bytes ===
    ($( #[ $attrs:meta ] )* $id:ident infallibly wraps $wrapped:path; copy_bytes) => {
        bytes_wrapper!($( #[ $attrs ] )* $id infallibly wraps $wrapped);
        bytes_wrapper!(@COPY_BYTES $id; $wrapped);
    };

    // === Fallible, without copy_bytes ===
    ($( #[ $attrs:meta ] )* $id:ident fallibly wraps $wrapped:path $(; constructor_map_err($constructor_map_err:expr))?) => {
        bytes_wrapper!(@DEFINITION $( #[ $attrs ] )* $id; $wrapped);

        #[uniffi::export]
        impl $id {
            /// Fallibly instantiate an instance from a byte array.
            #[uniffi::constructor]
            pub fn new(bytes: Vec<u8>) -> crate::CoreCryptoResult<Self> {
                let wrapped = bytes.try_into()$(.map_err($constructor_map_err))? ?;
                Ok(Self(wrapped))
            }
        }
    };

    // === Fallible, with copy_bytes, no constructor_map_err ===
    ($( #[ $attrs:meta ] )* $id:ident fallibly wraps $wrapped:path; copy_bytes) => {
        bytes_wrapper!($( #[ $attrs ] )* $id fallibly wraps $wrapped);
        bytes_wrapper!(@COPY_BYTES $id; $wrapped);
    };

    // === Fallible, with constructor_map_err and copy_bytes ===
    ($( #[ $attrs:meta ] )* $id:ident fallibly wraps $wrapped:path; constructor_map_err($constructor_map_err:expr); copy_bytes) => {
        bytes_wrapper!($( #[ $attrs ] )* $id fallibly wraps $wrapped; constructor_map_err($constructor_map_err));
        bytes_wrapper!(@COPY_BYTES $id; $wrapped);
    };

    // === Internal: struct definition (no copy_bytes) ===
    (@DEFINITION $( #[ $attrs:meta ] )* $id:ident; $wrapped:path) => {
        $( #[ $attrs ] )*
        #[derive(derive_more::From, derive_more::Into, derive_more::Deref, derive_more::DerefMut, uniffi::Object)]
        pub struct $id(pub(crate) $wrapped);
    };

    // === Internal: copy_bytes impl ===
    (@COPY_BYTES $id:ident; $wrapped:path) => {
        #[uniffi::export]
        impl $id {
            /// Copy the wrapped data into a new byte array.
            pub fn copy_bytes(&self) -> Vec<u8> {
                <$wrapped as Into<Vec<u8>>>::into(self.0.clone())
            }
        }
    };
}

// This import is an idiom which makes it possible for other modules to
// import the macro from this module instead of from the root.
pub(crate) use bytes_wrapper;

/// Implement `Display` based on the hex-encoding of the bytes in the inner type.
macro_rules! impl_display_via_hex {
    ($id:ident) => {
        impl std::fmt::Display for $id {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&hex::encode(<_ as AsRef<[u8]>>::as_ref(&self.0)))
            }
        }
    };
}

pub(crate) use impl_display_via_hex;
