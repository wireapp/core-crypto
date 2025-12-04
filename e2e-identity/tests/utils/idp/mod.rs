use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};

use serde::{Deserialize, Serialize};

mod authelia;
mod keycloak;

const OAUTH_CLIENT_ID: &str = "wireapp";
const OAUTH_CLIENT_NAME: &str = "Wire";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum OidcProvider {
    Authelia,
    Keycloak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpServer {
    pub provider: OidcProvider,
    pub hostname: String,
    pub addr: SocketAddr,
    pub issuer: String,
    pub discovery_base_url: String,
    pub user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdpServerConfig {
    pub hostname: String,
    pub user: User,
    pub redirect_uri: String,
}

/// Get a free port from the OS
fn free_tcp_port() -> Option<u16> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let port = TcpListener::bind(addr).ok()?.local_addr().ok()?.port();
    Some(port)
}

pub async fn start_idp_server(provider: OidcProvider, wire_server_hostname: &str, redirect_uri: &str) -> IdpServer {
    let user = User {
        username: format!("alice_wire@{wire_server_hostname}"),
        password: "foo".to_string(),
        first_name: "Alice".to_string(),
        last_name: "Smith".to_string(),
        email: "alice.smith@some.provider".to_string(),
    };

    let hostname = match provider {
        OidcProvider::Authelia => "authelia.local".to_string(),
        OidcProvider::Keycloak => "keycloak".to_string(),
    };

    let config = IdpServerConfig {
        hostname,
        user,
        redirect_uri: redirect_uri.to_string(),
    };

    let port = free_tcp_port().unwrap();
    let server = match provider {
        OidcProvider::Authelia => authelia::start_server(&config, port).await,
        OidcProvider::Keycloak => keycloak::start_server(&config, port).await,
    };
    log::debug!("Started IdP server: {server:?}");
    server
}
