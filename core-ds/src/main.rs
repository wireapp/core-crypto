#[cfg(feature = "gql")]
mod gql;

#[cfg(feature = "ws")]
mod ws;

mod error;
pub use self::error::*;

#[allow(dead_code)]
#[derive(Clone)]
pub struct AppState {
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

    let state = AppState {
        db,
        #[cfg(feature = "gql")]
        schema,
    };

    let mut listenfd = listenfd::ListenFd::from_env();

    let mut server = actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(state.clone())
            .wrap(tracing_actix_web::TracingLogger::default())
            .configure(configure)
    });

    server = match listenfd.take_tcp_listener(0)? {
        Some(listener) => server.listen(listener)?,
        None => server.bind(&server_url)?,
    };

    server.run().await?;

    Ok(())
}
