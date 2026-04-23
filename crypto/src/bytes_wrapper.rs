/// Construct a newtype wrapping a byte slice.
///
/// This macro just handles the boilerplate of constructing the wrapper.
macro_rules! bytes_wrapper {
    ($( #[ $attrs:meta ] )* $id:ident) => {
        $( #[ $attrs ] )*
        #[derive(Debug,  PartialEq, Eq, Hash, derive_more::From, derive_more::Into, derive_more::Deref, derive_more::AsRef)]
        pub struct $id(pub(crate) Vec<u8>);

        impl std::fmt::Display for $id {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&hex::encode(&self))
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
pub(crate) use bytes_wrapper;
