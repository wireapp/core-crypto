#![allow(dead_code)]

use actix_web_actors::ws;

pub struct DsWebsocketActor {
    identity: uuid::Uuid,
}

impl actix::Actor for DsWebsocketActor {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        // TODO: Join self conversation
        todo!()
    }
}

impl actix::StreamHandler<Result<ws::Message, ws::ProtocolError>> for DsWebsocketActor {
    fn handle(&mut self, _msg: Result<ws::Message, ws::ProtocolError>, _ctx: &mut Self::Context) {
        todo!()
    }
}

impl DsWebsocketActor {
    pub fn new() -> Self {
        Self {
            identity: uuid::Uuid::nil(),
        }
    }
}
