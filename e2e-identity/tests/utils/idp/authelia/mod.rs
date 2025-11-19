use std::net::SocketAddr;

use argon2::{
    Algorithm, Argon2, ParamsBuilder, Version,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, Mount, ReuseDirective, logs::consumer::logging_consumer::LoggingConsumer},
    runners::AsyncRunner,
};

use crate::utils::{
    NETWORK, SHM,
    idp::{IdpServer, IdpServerConfig, OAUTH_CLIENT_ID, OAUTH_CLIENT_NAME, OidcProvider, User},
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

pub async fn start_server(config: &IdpServerConfig, port: u16) -> IdpServer {
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

    let image = GenericImage::new("authelia/authelia", "refactor-claims-value-expression")
        .with_container_name("authelia.local")
        .with_network(NETWORK)
        .with_hostname("authelia.local")
        .with_mapped_port(port, port.tcp())
        .with_mount(Mount::bind_mount(
            host_volume.join("config").to_str().unwrap(),
            "/config",
        ))
        .with_log_consumer(LoggingConsumer::new())
        .with_copy_to("/config/private.pem", keypair_pem)
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
