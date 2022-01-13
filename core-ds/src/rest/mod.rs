mod clients;
mod conversations;

pub fn rest_services() -> impl actix_web::dev::HttpServiceFactory {
    actix_web::services![clients::register_client, clients::list_client_keypackages]
}
