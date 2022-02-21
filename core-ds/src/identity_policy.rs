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

use actix_identity::IdentityPolicy;
use actix_utils::future::{ready, Ready};
use actix_web::dev::{ServiceRequest, ServiceResponse};

#[derive(Debug, Clone, Copy)]
pub struct IdentitySignaturePolicy;

impl actix_identity::IdentityPolicy for IdentitySignaturePolicy {
    type Future = Ready<Result<Option<String>, actix_web::Error>>;
    type ResponseFuture = Ready<Result<(), actix_web::Error>>;

    fn from_request(&self, req: &mut ServiceRequest) -> <Self as IdentityPolicy>::Future {
        ready({
            let token = req
                .headers()
                .get(actix_web::http::header::AUTHORIZATION)
                .map(|auth_header| hex::encode(auth_header.as_bytes()));

            // if let Some(token) = token.as_ref() {}

            Ok(token)
        })
    }

    fn to_response<B>(
        &self,
        _: Option<std::string::String>,
        _: bool,
        _: &mut ServiceResponse<B>,
    ) -> <Self as IdentityPolicy>::ResponseFuture {
        ready(Ok(()))
    }
}
