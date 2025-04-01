/// Implement a proteus function, or return an error if the feature is not enabled.
///
/// The `macro_export` macro ensures this shows up at the crate root in all cases.
#[macro_export]
macro_rules! proteus_impl {
    ($body:block or throw $result:ty) => {{
        if cfg!(feature = "proteus") {
            $body
        } else {
            <$result>::Err(core_crypto::Error::FeatureDisabled("proteus").into())
        }
    }};
    ($body:block) => {
        proteus_impl!($body or throw std::result::Result::<_, _>)
    }
}
