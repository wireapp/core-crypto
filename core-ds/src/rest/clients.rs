use crate::models;
use crate::DsResult;
use actix_web::web;
use sea_orm::ActiveModelTrait;
use sea_orm::EntityTrait;
use sea_orm::Set;

#[derive(Debug, serde::Deserialize)]
pub struct RegisterClientPayload {
    identity: uuid::Uuid,
    display_name: String,
    key_packages: std::collections::HashMap<Vec<u8>, Vec<u8>>,
}

#[actix_web::post("/clients/register")]
pub async fn register_client(
    payload: web::Json<RegisterClientPayload>,
    state: web::Data<crate::AppState>,
) -> DsResult<web::Json<models::clients::Model>> {
    let payload = payload.into_inner();

    let client = models::clients::ActiveModel {
        identity: Set(payload.identity),
        display_name: Set(payload.display_name),
        ..Default::default()
    };

    let client = client.insert(&state.db).await?;

    let key_packages: Vec<models::client_keypackages::ActiveModel> = payload
        .key_packages
        .into_iter()
        .map(|(hash, kp)| models::client_keypackages::ActiveModel {
            client_id: Set(client.id),
            kp_tls_payload: Set(kp),
            hash: Set(hash),
            ..Default::default()
        })
        .collect();

    let _ = models::client_keypackages::Entity::insert_many(key_packages)
        .exec(&state.db)
        .await?;

    Ok(web::Json(client))
}
