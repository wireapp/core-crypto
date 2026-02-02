#![cfg(not(target_family = "wasm"))]

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr as _,
    sync::{Arc, Mutex},
};

use base64::Engine as _;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
};
use hyper_util::rt::TokioIo;
use rusty_jwt_tools::prelude::*;
use tokio::net::TcpListener;

fn generate_nonce() -> String {
    let nonce = uuid::Uuid::new_v4();
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(nonce)
}

type Nonces = HashMap<String, BackendNonce>;

async fn wire_api(nonces: &Mutex<Nonces>, req: Request<Incoming>) -> http::Result<Response<Full<Bytes>>> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();
    let paths = path.split('/').filter(|p| !p.is_empty()).collect::<Vec<&str>>();
    let header = |k: &str| {
        parts
            .headers
            .get(k)
            .and_then(|d| d.to_str().ok())
            .and_then(|v| base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(v).ok())
            .and_then(|v| String::from_utf8(v).ok())
            .unwrap_or_else(|| panic!("No header '{k}'"))
    };
    Ok(match (parts.method, paths.as_slice()) {
        (Method::GET, ["clients", device_id, "nonce"]) => {
            let nonce = generate_nonce();
            nonces
                .lock()
                .unwrap()
                .insert(device_id.to_string(), nonce.clone().into());
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(nonce.into()))?
        }
        (Method::POST, ["clients", device_id, "access-token"]) => {
            let bytes = body.collect().await.unwrap().to_bytes();
            let context: HashMap<String, String> = serde_json::from_slice(&bytes).unwrap();
            let client_id = &context["client-id"];
            let client_id = ClientId::try_from_uri(client_id).unwrap();

            let dpop = header("dpop");
            let backend_nonce = nonces.lock().unwrap()[*device_id].clone();

            // verify this tests has a valid API handler expecting the right deviceId encoding
            let received_device_id = u64::from_str_radix(device_id, 16).unwrap();
            assert_eq!(received_device_id, client_id.device_id);

            match generate_access_token(&context, &dpop, client_id, backend_nonce) {
                Ok(body) => {
                    let body = serde_json::to_vec(&body).unwrap().into();
                    Response::builder().status(StatusCode::OK).body(body).unwrap()
                }
                Err(_) => Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body("".into())
                    .unwrap(),
            }
        }
        (Method::GET, ["callback"]) => handle_callback(parts.uri).await?,
        _ => not_found()?,
    })
}

async fn handle_callback(uri: http::Uri) -> http::Result<Response<Full<Bytes>>> {
    let req_uri: url::Url = format!("http://localhost{uri}").parse().unwrap();
    let authorization_code = req_uri
        .query_pairs()
        .find_map(|(k, v)| match k.as_ref() {
            "code" => Some(v.to_string()),
            _ => None,
        })
        .unwrap();
    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(authorization_code.into())
        .unwrap();
    Ok(resp)
}

fn generate_access_token(
    ctx: &HashMap<String, String>,
    dpop: &str,
    client_id: ClientId,
    nonce: BackendNonce,
) -> RustyJwtResult<serde_json::Value> {
    let backend_kp: Pem = ctx["backend-kp"].as_str().into();
    let hash_alg: HashAlgorithm = ctx["hash-alg"].parse().unwrap();
    let htu: Htu = ctx["wire-server-uri"].as_str().try_into().unwrap();
    let handle = QualifiedHandle::from_str(ctx["handle"].as_str()).unwrap();
    let display_name = ctx["display_name"].as_str();
    let team: Team = ctx["team"].as_str().into();

    let leeway = 2;
    let max_expiry = 2082008461;
    let access_token = RustyJwtTools::generate_access_token(
        dpop,
        &client_id,
        handle,
        display_name,
        team,
        nonce,
        htu,
        Htm::Post,
        leeway,
        max_expiry,
        backend_kp,
        hash_alg,
        5,
        core::time::Duration::from_secs(360),
    )?;

    Ok(serde_json::json!({
        "expires_in": 2082008461,
        "token": access_token,
        "type": "DPoP"
    }))
}

fn not_found() -> http::Result<Response<Full<Bytes>>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Default::default())
}

pub(crate) async fn bind_socket() -> TcpListener {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let listener = TcpListener::bind(&addr).await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("{addr}");
    listener
}

pub(crate) async fn run_server(listener: TcpListener) {
    let nonces: Arc<Mutex<Nonces>> = Mutex::new(HashMap::new()).into();
    while let Ok((stream, _)) = listener.accept().await {
        let io = TokioIo::new(stream);
        let cloned = Arc::clone(&nonces);
        tokio::spawn(async move {
            let service = hyper::service::service_fn(|req| wire_api(&cloned, req));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("server error: {err}");
            }
        });
    }
}
