#[cfg(feature = "gql")]
mod gql;

#[cfg(feature = "ws")]
mod ws;

mod identity_policy;
mod models;
mod rest;

mod error;

pub use self::error::*;

const REDIS_DEFAULT_URL: &str = "redis://127.0.0.1:6379/core-crypto";

#[allow(dead_code)]
#[derive(Clone)]
pub struct AppState {
    redis: redis::Client,
    db: sea_orm::DatabaseConnection,
    #[cfg(feature = "gql")]
    schema: gql::LocalSchema,
}

#[actix_web::get("/healthz")]
fn healthz(_: actix_web::HttpRequest) -> actix_web::HttpResponse {
    actix_web::HttpResponseBuilder::new(actix_web::http::StatusCode::OK).into()
}

// #[actix_web::get("/ws")]
// async fn ws_start(
//     uuid: actix_identity::Identity,
//     req: actix_web::HttpRequest,
//     stream: actix_web::web::Payload,
// ) -> impl actix_web::Responder {
//     if uuid.identity().is_none() {
//         return Ok(actix_web::Either::Left(
//             actix_web::HttpResponse::Unauthorized().finish(),
//         ));
//     }

//     let uuid = uuid::Uuid::from_slice(&hex::decode(uuid.identity().unwrap())?)?;
//     let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| REDIS_DEFAULT_URL.into());

//     Ok(actix_web::Either::Right(actix_web_actors::ws::start(
//         ws::client::DsClientSession {
//             id: ws::client::DsClientSessionId(uuid::Uuid::new_v4()),
//             identity: uuid,
//             hb: std::time::Instant::now(),
//             redis: redis::Client::open(redis_url)?,
//         },
//         &req,
//         stream,
//     )))
// }

fn configure(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.service(healthz);

    #[cfg(feature = "gql")]
    cfg.service(gql::gql_endpoint);

    #[cfg(feature = "gql_playground")]
    cfg.service(gql::gql_playgound);

    cfg.service(rest::rest_services());
}

#[actix_web::main]
async fn main() -> DsResult<()> {
    dotenv::dotenv().ok();
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let host = std::env::var("HOST").expect("HOST is not set in .env file");
    let port = std::env::var("PORT").expect("PORT is not set in .env file");
    let server_url = format!("{}:{}", host, port);

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| REDIS_DEFAULT_URL.into());

    let db = {
        let mut opts = sea_orm::ConnectOptions::new(db_url);
        opts.max_connections(100).min_connections(5).sqlx_logging(true);

        sea_orm::Database::connect(opts).await?
    };

    #[cfg(feature = "gql")]
    let schema = gql::LocalSchema::new(gql::QueryRoot, gql::MutationRoot, gql::SubscriptionRoot);

    let state = AppState {
        redis: redis::Client::open(redis_url)?,
        db: db.clone(),
        #[cfg(feature = "gql")]
        schema: schema.clone(),
    };

    let mut listenfd = listenfd::ListenFd::from_env();

    let mut server = actix_web::HttpServer::new(move || {
        let cors = actix_cors::Cors::default()
            .allowed_origin_fn(|origin, _| {
                origin.as_bytes().ends_with(b".wire.com") || origin.as_bytes().ends_with(b"localhost")
            })
            .allowed_methods(vec!["GET", "POST", "UPDATE", "PATCH", "DELETE"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::CONTENT_TYPE,
            ])
            .max_age(3600);

        actix_web::App::new()
            .app_data(state.clone())
            .wrap(cors)
            // .wrap(tracing_actix_web::TracingLogger::default())
            .wrap(actix_identity::IdentityService::new(
                identity_policy::IdentitySignaturePolicy,
            ))
            .configure(configure)
    });

    server = match listenfd.take_tcp_listener(0)? {
        Some(listener) => server.listen(listener)?,
        None => server.bind(&server_url)?,
    };

    server.run().await?;

    Ok(())
}
