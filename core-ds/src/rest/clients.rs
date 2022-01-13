use crate::{models, DsResult};
use actix_web::web;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

#[derive(Debug, serde::Deserialize)]
pub struct RegisterClientPayload {
    identity: uuid::Uuid,
    display_name: String,
    key_packages: std::collections::HashMap<Vec<u8>, Vec<u8>>,
}

#[actix_web::post("/clients")]
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

#[actix_web::get("/clients/{uuid}/keypackage")]
pub async fn list_client_keypackages(
    uuid: web::Path<uuid::Uuid>,
    state: web::Data<crate::AppState>,
) -> DsResult<Option<web::Json<models::client_keypackages::Model>>> {
    Ok(models::client_keypackages::Entity::find()
        .filter(models::client_keypackages::Column::Uuid.eq(uuid.into_inner()))
        .one(&state.db)
        .await?
        .map(|model| web::Json(model)))
}
