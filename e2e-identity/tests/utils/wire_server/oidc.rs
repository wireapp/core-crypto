use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};

pub async fn handle_callback(req: Request<Incoming>) -> http::Result<Response<Full<Bytes>>> {
    let req_uri = req.uri().clone();
    let req_uri: url::Url = format!("http://localhost{req_uri}").parse().unwrap();
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
