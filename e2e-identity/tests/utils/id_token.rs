use jwt_simple::prelude::*;
use serde_json::Value;

pub fn resign_id_token(
    existing_id_token: &str,
    existing_kp: RS256PublicKey,
    existing_kid: String,
    new_kp: RS256KeyPair,
    alter: impl FnOnce(JWTClaims<Value>) -> JWTClaims<Value>,
) -> String {
    let header = Token::decode_metadata(existing_id_token).unwrap();
    let header = JWTHeader {
        algorithm: header.algorithm().to_string(),
        key_id: Some(existing_kid),
        ..Default::default()
    };
    let mut claims = existing_kp.verify_token::<Value>(existing_id_token, None).unwrap();
    claims = alter(claims);
    new_kp.sign_with_header(claims, header).unwrap()
}
