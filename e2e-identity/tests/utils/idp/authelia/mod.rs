use std::net::SocketAddr;

use argon2::{
    Algorithm, Argon2, ParamsBuilder, Version,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use http::header;
use oauth2::{CsrfToken, PkceCodeChallenge, RedirectUrl, Scope};
use openidconnect::{
    IssuerUrl, Nonce,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use serde_json::json;
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, Mount, ReuseDirective, logs::consumer::logging_consumer::LoggingConsumer},
    runners::AsyncRunner,
};
use url::Url;

use crate::utils::{
    NETWORK, SHM,
    ctx::{ctx_get_http_client, ctx_get_http_client_builder, custom_oauth_client},
    idp::{IdpServer, IdpServerConfig, OAUTH_CLIENT_ID, OAUTH_CLIENT_NAME, OauthCfg, OidcProvider, User},
    rand_str,
};

fn compute_password_hash(password: &str) -> String {
    // Use parameters corresponding to the "Low Memory" situation:
    // https://www.authelia.com/reference/guides/passwords/#user--password-file
    let params = ParamsBuilder::new().m_cost(65536).p_cost(4).t_cost(3).build().unwrap();

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);

    // Return the digest as a PHC string ($argon2id$v=19$...).
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string()
}

fn authelia_users(user: &User) -> String {
    format!(
        r#"
users:
  {username}:
    disabled: false
    displayname: '{first_name} {last_name}'
    password: '{password}'
    email: '{email}'
"#,
        username = user.username,
        first_name = user.first_name,
        last_name = user.last_name,
        email = user.email,
        password = compute_password_hash(&user.password)
    )
}

fn authelia_config(hostname: &str, redirect_uri: &str, port: u16) -> String {
    format!(
        include_str!("config.template"),
        hostname = hostname,
        redirect_uri = redirect_uri,
        oauth_client_id = OAUTH_CLIENT_ID,
        oauth_client_name = OAUTH_CLIENT_NAME,
        port = port,
        jwt_secret = rand_str(64),
        session_secret = rand_str(64),
        storage_key = rand_str(64),
    )
}

pub(super) async fn start_server(config: &IdpServerConfig, port: u16) -> IdpServer {
    let host_volume = std::env::temp_dir().join(format!("authelia-{}", rand_str(12)));
    std::fs::create_dir_all(host_volume.join("config")).unwrap();
    std::fs::write(host_volume.join("config/users.yml"), authelia_users(&config.user)).unwrap();
    std::fs::write(
        host_volume.join("config/config.yml"),
        authelia_config(&config.hostname, &config.redirect_uri, port),
    )
    .unwrap();

    // This is a bit unfortunate. Authelia requires at least one RS256 key and the smallest
    // supported RSA modulus in jwt_simple is 2048. Depending on CPU and luck, it can take a couple
    // of seconds to generate a key pair. Oh well.
    let keypair = jwt_simple::prelude::RS256KeyPair::generate(2048).unwrap();
    let keypair_pem = keypair.to_pem().unwrap().as_bytes().to_owned();

    #[cfg(unix)]
    {
        // Set permissions so that the container can be used on macOS
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o777);
        std::fs::set_permissions(host_volume.join("config"), permissions).unwrap();
    }

    std::fs::write(host_volume.join("config/private.pem"), &keypair_pem).unwrap();

    let image = GenericImage::new("authelia/authelia", "4.39.15")
        .with_container_name("authelia.local")
        .with_network(NETWORK)
        .with_hostname("authelia.local")
        .with_mapped_port(port, port.tcp())
        .with_mount(Mount::bind_mount(
            host_volume.join("config").to_str().unwrap(),
            "/config",
        ))
        .with_log_consumer(LoggingConsumer::new())
        .with_reuse(ReuseDirective::Always)
        .with_cmd(vec![
            "authelia",
            "--config",
            "/config/config.yml",
            "--config.experimental.filters",
            "template",
        ])
        .with_shm_size(SHM);

    image.start().await.expect("starting Authelia will succeed");

    let hostname = config.hostname.clone();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let issuer = format!("http://{hostname}:{port}");
    let discovery_base_url = issuer.clone();

    IdpServer {
        provider: OidcProvider::Authelia,
        hostname,
        addr,
        issuer,
        discovery_base_url,
        user: config.user.clone(),
    }
}

pub(super) async fn fetch_id_token(
    idp_server: &IdpServer,
    oauth_cfg: &OauthCfg,
    oidc_target: &Url,
    keyauth: &str,
    acme_audience: &str,
) -> String {
    // Create HTTP client with cookie store enabled
    let client = ctx_get_http_client_builder().cookie_store(true).build().unwrap();

    let cookie = {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
        use serde_json::json;

        let host = &idp_server.hostname;
        let port = idp_server.addr.port();
        let authelia_url = format!("http://{host}:{port}/api/firstfactor");

        // Prepare login payload
        let payload = json!({
            "username": idp_server.user.username.clone(),
            "password": idp_server.user.password.clone(),
        });

        // Set headers
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        // Send login request
        let response = client
            .post(authelia_url)
            .headers(headers)
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());
        let cookie = response
            .cookies()
            .find(|cookie| cookie.name() == "authelia_session")
            .unwrap();
        format!("{}={}", cookie.name(), cookie.value())
    };

    // We cannot use oidc_target as-is, because it contains '/' as the last character,
    // causing an issuer URL mismatch. So remove the `/` before constructing an IssuerUrl.
    let mut url = oidc_target.to_string();
    url.pop();
    let issuer_url = IssuerUrl::new(url).unwrap();

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), &async |r| {
        custom_oauth_client("discovery", ctx_get_http_client(), r).await
    })
    .await
    .unwrap();

    let client_id = openidconnect::ClientId::new(oauth_cfg.client_id.clone());
    let redirect_url = RedirectUrl::new(oauth_cfg.redirect_uri.clone()).unwrap();
    let oidc_client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, None).set_redirect_uri(redirect_url);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // A variant of https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
    let extra = json!({
        "id_token": {
            "keyauth": { "essential": true, "value": keyauth },
            "acme_aud": { "essential": true, "value": acme_audience },
        }
    })
    .to_string();

    let (authz_url, ..) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes([
            Scope::new("profile".to_string()),
            Scope::new("email".to_string()),
            Scope::new("wire".to_string()),
        ])
        .add_extra_param("claims", extra)
        .set_pkce_challenge(pkce_challenge)
        .url();

    let authz_req = client
        .get(authz_url.as_str())
        .header(header::COOKIE, cookie)
        .build()
        .unwrap();

    // Perform an authorization request. The server will not redirect to the login prompt since
    // we're using an pre-authenticated session, indicated by the cookie.
    let resp = client.execute(authz_req).await.unwrap();
    let authz_code = resp.text().await.unwrap();

    let token_request = oidc_client
        .exchange_code(openidconnect::AuthorizationCode::new(authz_code))
        .unwrap()
        .set_pkce_verifier(pkce_verifier);

    // Authorization server validates Verifier & Challenge Codes
    let oauth_token_response = token_request
        .request_async(&async |r| custom_oauth_client("exchange-code", ctx_get_http_client(), r).await)
        .await
        .unwrap();

    use openidconnect::TokenResponse as _;
    oauth_token_response.id_token().unwrap().to_string()
}
