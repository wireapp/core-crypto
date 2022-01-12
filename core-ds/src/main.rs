#[cfg(feature = "gql")]
mod gql;

#[cfg(feature = "ws")]
mod ws;

mod identity_policy;
mod models;
mod rest;

mod error;
use identity_policy::IdentitySignaturePolicy;

pub use self::error::*;

#[allow(dead_code)]
#[derive(Clone)]
pub struct AppState {
    redis: actix::Addr<actix_redis::RedisActor>,
    db: sea_orm::DatabaseConnection,
    #[cfg(feature = "gql")]
    schema: gql::LocalSchema,
}

#[actix_web::get("/healthz")]
fn healthz(_: actix_web::HttpRequest) -> actix_web::HttpResponse {
    actix_web::HttpResponseBuilder::new(actix_web::http::StatusCode::OK).into()
}

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

    let db = {
        let mut opts = sea_orm::ConnectOptions::new(db_url);
        opts.max_connections(100).min_connections(5).sqlx_logging(true);

        sea_orm::Database::connect(opts).await?
    };

    #[cfg(feature = "gql")]
    let schema = gql::LocalSchema::new(gql::QueryRoot, gql::MutationRoot, gql::SubscriptionRoot);

    let mut listenfd = listenfd::ListenFd::from_env();

    let mut server = actix_web::HttpServer::new(move || {
        let state = AppState {
            redis: actix_redis::RedisActor::start("127.0.0.1:6379"),
            db: db.clone(),
            #[cfg(feature = "gql")]
            schema: schema.clone(),
        };

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
            .app_data(state)
            .wrap(cors)
            .wrap(tracing_actix_web::TracingLogger::default())
            .wrap(actix_identity::IdentityService::new(IdentitySignaturePolicy))
            .configure(configure)
    });

    server = match listenfd.take_tcp_listener(0)? {
        Some(listener) => server.listen(listener)?,
        None => server.bind(&server_url)?,
    };

    server.run().await?;

    Ok(())
}
