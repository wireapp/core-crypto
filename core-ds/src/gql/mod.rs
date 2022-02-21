// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

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
