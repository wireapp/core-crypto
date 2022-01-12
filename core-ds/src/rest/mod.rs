mod clients;

pub fn rest_services() -> impl actix_web::dev::HttpServiceFactory {
    vec![clients::register_client]
}
