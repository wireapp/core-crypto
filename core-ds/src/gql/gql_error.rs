#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum GraphQLError {
    #[error("Could not find resource")]
    NotFound,

    #[error(transparent)]
    ServerError(#[from] color_eyre::Report),

    #[error("No extensions")]
    ErrorWithoutExtensions,
}

impl async_graphql::ErrorExtensions for GraphQLError {
    fn extend(&self) -> async_graphql::FieldError {
        self.extend_with(|err, e| match err {
            GraphQLError::NotFound => e.set("code", "NOT_FOUND"),
            GraphQLError::ServerError(reason) => e.set("reason", reason.to_string()),
            GraphQLError::ErrorWithoutExtensions => {}
        })
    }
}
