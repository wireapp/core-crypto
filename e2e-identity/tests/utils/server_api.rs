use crate::utils::rand_base64_str;
use base64::Engine;
use hyper::{Body, Method, Request, Response, StatusCode};
use rusty_jwt_tools::prelude::{BackendNonce, ClientId, HashAlgorithm, Htm, Htu, Pem};
use rusty_jwt_tools::RustyJwtTools;

// simulates wire-server database
static mut PREVIOUS_NONCE: &str = "";

pub async fn wire_api(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let path = req.uri().path();
    let paths = path.split('/').filter(|p| !p.is_empty()).collect::<Vec<&str>>();
    Ok(match (req.method(), paths.as_slice()) {
        (&Method::GET, ["clients", "token", "nonce"]) => {
            let nonce = rand_base64_str(32);
            let previous_nonce = Box::leak(Box::new(nonce.clone()));
            unsafe {
                PREVIOUS_NONCE = previous_nonce;
            }
            Response::builder().status(StatusCode::OK).body(nonce.into()).unwrap()
        }
        (&Method::POST, ["clients", .., "access-token"]) => {
            let header = |k: &str| {
                req.headers()
                    .get(k)
                    .and_then(|d| d.to_str().ok())
                    .and_then(|v| base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(v).ok())
                    .and_then(|v| String::from_utf8(v).ok())
                    .unwrap_or_else(|| panic!("No header '{k}'"))
            };
            let dpop = header("dpop");

            // cheats to share test context
            let client_id = header("client-id");
            let client_id: ClientId = client_id.as_str().try_into().unwrap();
            let backend_kp: Pem = header("backend-kp").into();
            let hash_alg: HashAlgorithm = header("hash-alg").parse().unwrap();
            let htu: Htu = header("wire-server-uri").as_str().try_into().unwrap();

            // fetch back the nonce we have generated at previous state
            let backend_nonce: BackendNonce = unsafe { PREVIOUS_NONCE.into() };

            let body = generate_access_token(&dpop, client_id, backend_nonce, htu, backend_kp, hash_alg);
            let body = serde_json::to_vec(&body).unwrap().into();
            Response::builder().status(StatusCode::OK).body(body).unwrap()
        }
        _ => not_found(),
    })
}

fn generate_access_token(
    dpop: &str,
    client_id: ClientId,
    nonce: BackendNonce,
    htu: Htu,
    backend_kp: Pem,
    hash_alg: HashAlgorithm,
) -> serde_json::Value {
    let leeway = 2;
    let max_expiry = 2082008461;
    let access_token = RustyJwtTools::generate_access_token(
        dpop,
        client_id,
        nonce,
        htu,
        Htm::Post,
        leeway,
        max_expiry,
        backend_kp,
        hash_alg,
    )
    .unwrap();
    serde_json::json!({
        "expires_in": 2082008461,
        "token": access_token,
        "type": "DPoP"
    })
}

fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("???".into())
        .unwrap()
}
