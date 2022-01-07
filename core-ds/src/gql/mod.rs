use async_graphql::{ErrorExtensions, FieldResult};

mod gql_error;

pub struct QueryRoot;

#[async_graphql::Object]
impl QueryRoot {
    async fn extend(&self) -> FieldResult<i32> {
        Err(gql_error::GraphQLError::NotFound.extend())
    }
}

pub use async_graphql::EmptyMutation as MutationRoot;
pub use async_graphql::EmptySubscription as SubscriptionRoot;

pub type LocalSchema = async_graphql::Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

#[actix_web::post("/gql")]
pub async fn gql_endpoint(
    schema: actix_web::web::Data<LocalSchema>,
    req: async_graphql_actix_web::GraphQLRequest,
) -> impl actix_web::Responder {
    let response: async_graphql_actix_web::GraphQLResponse = schema.execute(req.into_inner()).await.into();
    response
}

#[cfg(feature = "gql_playground")]
#[actix_web::get("/gql/playground")]
pub async fn gql_playgound() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(async_graphql::http::playground_source(
            async_graphql::http::GraphQLPlaygroundConfig::new("/gql"),
        ))
}
