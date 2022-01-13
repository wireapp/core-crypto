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
