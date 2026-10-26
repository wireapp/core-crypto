use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};

use oauth2::{
    AuthUrl, ClientId, EndpointNotSet, EndpointSet, ExtraTokenFields, RedirectUrl, StandardRevocableToken,
    StandardTokenResponse, TokenUrl,
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse, BasicTokenType},
};
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    OauthCfg,
    ctx::{ctx_get_http_client, custom_oauth_client},
};

mod authelia;
mod keycloak;

const OAUTH_CLIENT_ID: &str = "wireapp";
const OAUTH_CLIENT_NAME: &str = "Wire";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum OidcProvider {
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
pub(crate) struct IdpServer {
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

/// The fields of an OpenID Connect token response in addition to the OAuth2 ones
///
/// See <https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse>
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdTokenFields {
    id_token: String,
}

impl ExtraTokenFields for IdTokenFields {}

/// An OAuth2 client for an OpenID provider, whose token responses include the ID token
type OidcClient = oauth2::Client<
    BasicErrorResponse,
    StandardTokenResponse<IdTokenFields, BasicTokenType>,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

/// The endpoints we use from the discovery document of an OpenID provider
///
/// See <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>
#[derive(Deserialize)]
struct ProviderMetadata {
    authorization_endpoint: String,
    token_endpoint: String,
}

/// Builds a client for the OpenID provider `issuer` from its discovery document
async fn oidc_client(issuer: &str, oauth_cfg: &OauthCfg) -> OidcClient {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let request = http::Request::get(url).body(Vec::new()).unwrap();
    let response = custom_oauth_client("discovery", ctx_get_http_client(), request)
        .await
        .unwrap();
    let metadata = serde_json::from_slice::<ProviderMetadata>(response.body()).unwrap();

    oauth2::Client::new(ClientId::new(oauth_cfg.client_id.clone()))
        .set_auth_uri(AuthUrl::new(metadata.authorization_endpoint).unwrap())
        .set_token_uri(TokenUrl::new(metadata.token_endpoint).unwrap())
        .set_redirect_uri(RedirectUrl::new(oauth_cfg.redirect_uri.clone()).unwrap())
}

/// Get a free port from the OS
fn free_tcp_port() -> Option<u16> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let port = TcpListener::bind(addr).ok()?.local_addr().ok()?.port();
    Some(port)
}

pub(crate) async fn start_idp_server(
    provider: OidcProvider,
    wire_server_hostname: &str,
    redirect_uri: &str,
) -> IdpServer {
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

pub(crate) async fn fetch_id_token(
    idp_server: &IdpServer,
    oauth_cfg: &OauthCfg,
    oidc_target: &Url,
    keyauth: &str,
    acme_audience: &str,
) -> String {
    match idp_server.provider {
        OidcProvider::Authelia => {
            authelia::fetch_id_token(idp_server, oauth_cfg, oidc_target, keyauth, acme_audience).await
        }
        OidcProvider::Keycloak => {
            keycloak::fetch_id_token(idp_server, oauth_cfg, oidc_target, keyauth, acme_audience).await
        }
    }
}
