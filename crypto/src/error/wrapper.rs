/// A wrapped operation failed, but we captured some context about what was happening
#[derive(Debug, thiserror::Error)]
#[error("{context}")]
pub struct WrappedContextualError<T> {
    /// What was happening in the caller
    pub context: &'static str,
    /// What happened
    #[source]
    pub source: T,
}

impl<T> WrappedContextualError<T> {
    pub fn wrap<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: Into<T>,
    {
        move |source| Self {
            source: source.into(),
            context,
        }
    }
}
