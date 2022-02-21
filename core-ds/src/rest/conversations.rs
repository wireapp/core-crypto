// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::{models, DsResult};
use actix_identity::Identity;
use actix_web::web;
use futures_util::TryStreamExt;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

#[derive(Debug, serde::Deserialize)]
pub struct CreateConversationPayload {
    pub title: Option<String>,
    pub description: Option<String>,
    pub clients: Vec<uuid::Uuid>,
    pub welcome_message: Option<Vec<u8>>,
    pub out_message: Option<Vec<u8>>,
}

#[actix_web::post("/conversations")]
pub async fn create_conversation(
    uuid: Identity,
    payload: web::Json<CreateConversationPayload>,
    state: web::Data<crate::AppState>,
) -> DsResult<impl actix_web::Responder> {
    if uuid.identity().is_none() {
        return Ok(actix_web::Either::Left(
            actix_web::HttpResponse::Unauthorized().finish(),
        ));
    }

    let uuid = uuid::Uuid::from_slice(&hex::decode(uuid.identity().unwrap())?)?;

    let client = models::clients::Entity::find()
        .filter(models::clients::Column::Uuid.eq(uuid))
        .one(&state.db)
        .await?;

    if client.is_none() {
        return Ok(actix_web::Either::Left(
            actix_web::HttpResponse::Unauthorized().finish(),
        ));
    }

    let client = client.unwrap();

    let mut payload = payload.into_inner();
    let conversation = models::conversations::ActiveModel {
        title: Set(payload.title.take()),
        description: Set(payload.description.take()),
        ..Default::default()
    };

    let conversation = conversation.insert(&state.db).await?;

    let mut conv_members = Vec::with_capacity(payload.clients.len() + 1);

    conv_members.push(models::conversation_members::ActiveModel {
        conversation_id: Set(conversation.id),
        client_id: Set(client.id),
        is_admin: Set(true),
        ..Default::default()
    });

    let mut clients_stream = models::clients::Entity::find()
        .filter(models::clients::Column::Uuid.is_in(payload.clients))
        .stream(&state.db)
        .await?;

    while let Some(client) = clients_stream.try_next().await? {
        conv_members.push(models::conversation_members::ActiveModel {
            conversation_id: Set(conversation.id),
            client_id: Set(client.id),
            ..Default::default()
        });
    }

    let _ = models::conversation_members::Entity::insert_many(conv_members.clone())
        .exec(&state.db)
        .await?;

    let mut redis = state.redis.get_async_connection().await?;
    let mut pipe = redis::pipe();
    pipe.atomic();
    if let Some(welcome_message) = payload.welcome_message.take() {
        for mut member in conv_members {
            let cid = member.client_id.take().unwrap();
            pipe.xadd(
                format!("mls_msgs.client.{}", cid),
                "*",
                &[("welcome", &welcome_message)],
            );
        }
    }

    if let Some(out_message) = payload.out_message.take() {
        pipe.xadd(
            format!("mls_msgs.conversation.{}", conversation.id),
            "*",
            &[("system", out_message)],
        );
    }

    pipe.query_async(&mut redis).await?;

    Ok(actix_web::Either::Right(web::Json(conversation)))
}
