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

use actix::ContextFutureSpawner;
use actix::WrapFuture;
use actix::{Context, Handler, Recipient};

use super::client::DsClientSessionId;

#[derive(Debug, actix::Message)]
#[repr(transparent)]
#[rtype(result = "()")]
pub struct Message(pub Vec<u8>);

#[derive(Debug, actix::Message)]
#[rtype(result = "()")]
pub struct Disconnect {
    pub id: DsClientSessionId,
}

#[derive(Debug, actix::Message)]
#[rtype(result = "DsClientSessionId")]
pub struct Connect {
    pub addr: Recipient<Message>,
}

#[derive(Debug, actix::Message)]
#[rtype(result = "()")]
pub struct SendMessage {
    pub cnv: uuid::Uuid,
    pub msg: Vec<u8>,
}

#[derive(Debug)]
pub struct DsMsgBroker {
    sessions: std::collections::HashMap<uuid::Uuid, Recipient<Message>>,
}

impl actix::Actor for DsMsgBroker {
    type Context = actix::Context<Self>;
}

impl Handler<Connect> for DsMsgBroker {
    type Result = actix::MessageResult<Connect>;

    fn handle(&mut self, msg: Connect, _: &mut Context<Self>) -> Self::Result {
        let uuid = uuid::Uuid::new_v4();
        self.sessions.insert(uuid, msg.addr);

        actix::MessageResult(DsClientSessionId(uuid))
    }
}

impl Handler<Disconnect> for DsMsgBroker {
    type Result = ();

    fn handle(&mut self, msg: Disconnect, _: &mut Context<Self>) {
        let _ = self.sessions.remove(&msg.id.0);
    }
}

impl Handler<SendMessage> for DsMsgBroker {
    type Result = ();

    fn handle(&mut self, msg: SendMessage, ctx: &mut Context<Self>) {
        //let SendMessage { cnv, msg } = msg;

        // TODO: Ask another actor (db?) for the member list
        // TODO Actually scrap that whole thing and rewrite it using redis streams (XREAD) on ws client side only
    }
}
