/// Implement a proteus function, or return an error if the feature is not enabled.
///
/// The `macro_export` macro ensures this shows up at the crate root in all cases.
#[macro_export]
macro_rules! proteus_impl {
    ($body:block) => {{
        if cfg!(feature = "proteus") {
            $body
        } else {
            Err(core_crypto::Error::FeatureDisabled("proteus").into())
        }
    }};
}
