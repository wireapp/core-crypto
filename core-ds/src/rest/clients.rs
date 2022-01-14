use std::collections::HashMap;

use crate::{
    models::{self, clients, conversation_members},
    DsResult,
};
use actix_web::web;
use color_eyre::owo_colors::colored;
use redis::AsyncCommands;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set};

#[derive(Debug, serde::Deserialize)]
pub struct RegisterClientPayload {
    identity: uuid::Uuid,
    display_name: String,
    key_packages: HashMap<Vec<u8>, Vec<u8>>,
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

#[derive(Debug, serde::Serialize)]
pub struct Message {
    k: String,
    m: Vec<u8>,
    t: u64,
    c: Option<uuid::Uuid>,
}

#[actix_web::get("/recv")]
pub async fn recv_messages(
    uuid: actix_identity::Identity,
    state: web::Data<crate::AppState>,
) -> DsResult<impl actix_web::Responder> {
    if uuid.identity().is_none() {
        return Ok(actix_web::Either::Left(
            actix_web::HttpResponse::Unauthorized().finish(),
        ));
    }

    let uuid = uuid::Uuid::from_slice(&hex::decode(uuid.identity().unwrap())?)?;
    let client = clients::Entity::find()
        .filter(clients::Column::Uuid.eq(uuid))
        .one(&state.db)
        .await?;
    if client.is_none() {
        return Ok(actix_web::Either::Left(
            actix_web::HttpResponse::Unauthorized().finish(),
        ));
    }

    let client = client.unwrap();

    let conversations = conversation_members::Entity::find()
        .select_only()
        .column(conversation_members::Column::ConversationId)
        .filter(conversation_members::Column::ClientId.eq(client.id))
        .all(&state.db)
        .await?;

    let mut stream_ids: Vec<String> = conversations
        .iter()
        .map(|c| format!("mls_msgs.conversation.{}", c.conversation_id))
        .collect();
    stream_ids.push(format!("mls_msgs.client.{}", uuid));

    let mut conn = state.redis.get_async_connection().await?;
    let personal_messages: HashMap<String, HashMap<String, (String, String)>> = conn.xread(&stream_ids, &[">"]).await?;

    let ret: Vec<Message> = personal_messages.into_iter().try_fold(
        Vec::new(),
        |mut acc, (stream_name, ts_msgs)| -> DsResult<Vec<Message>> {
            let split_stream_name = stream_name.split('.').collect::<Vec<&str>>();

            let c: Option<uuid::Uuid> = if split_stream_name[1] == "conversation" {
                split_stream_name.get(2).map(|s| s.parse()).transpose()?
            } else {
                None
            };

            for (t, (k, v)) in ts_msgs.into_iter() {
                let (t, _) = t.split_once('-').unwrap();
                acc.push(Message {
                    k,
                    m: v.into_bytes(),
                    t: t.parse().map_err(|_| color_eyre::eyre::eyre!("could not parse int"))?,
                    c,
                });
            }

            Ok(acc)
        },
    )?;

    Ok(actix_web::Either::Right(web::Json(ret)))
}
