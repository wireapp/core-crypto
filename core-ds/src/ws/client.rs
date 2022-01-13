#![allow(dead_code)]

use actix::ActorContext;
use actix::ActorFutureExt;
use actix::Addr;
use actix::AsyncContext;
use actix::ContextFutureSpawner;
use actix::WrapFuture;
use actix_web_actors::ws;

const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug, Clone, Copy, actix::Message)]
#[repr(transparent)]
#[rtype(uuid::Uuid)]
pub struct DsClientSessionId(pub uuid::Uuid);

pub struct DsClientSession {
    id: DsClientSessionId,
    identity: uuid::Uuid,
    hb: std::time::Instant,
    addr: Addr<super::server::DsMsgBroker>,
}

impl actix::Actor for DsClientSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);

        let addr = ctx.address();

        self.addr
            .send(super::server::Connect { addr: addr.recipient() })
            .into_actor(self)
            .then(|res, act, ctx| {
                match res {
                    Ok(res) => act.id = res,
                    _ => ctx.stop(),
                }
                actix::fut::ready(())
            })
            .wait(ctx);
    }

    fn stopping(&mut self, _: &mut Self::Context) -> actix::Running {
        self.addr.do_send(super::server::Disconnect { id: self.id });
        actix::Running::Stop
    }
}

impl actix::Handler<super::server::Message> for DsClientSession {
    type Result = ();

    fn handle(&mut self, msg: super::server::Message, ctx: &mut Self::Context) {
        ctx.binary(msg.0);
    }
}

impl actix::StreamHandler<Result<ws::Message, ws::ProtocolError>> for DsClientSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        let msg = match msg {
            Ok(msg) => msg,
            Err(_) => {
                ctx.stop();
                return;
            }
        };

        match msg {
            ws::Message::Ping(msg) => {
                self.hb = std::time::Instant::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.hb = std::time::Instant::now();
            }
            ws::Message::Text(text) => {
                self.handle(Ok(ws::Message::Binary(text.into_bytes())), ctx);
            }
            ws::Message::Binary(_buf) => {
                todo!();
            }
            ws::Message::Close(reason) => {
                ctx.close(reason);
                ctx.stop();
            }
            ws::Message::Continuation(_) => {
                ctx.stop();
            }
            ws::Message::Nop => ()
        }
    }
}

impl DsClientSession {
    fn hb(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if std::time::Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                act.addr.do_send(super::server::Disconnect { id: act.id });
                ctx.stop();
                return;
            }

            ctx.ping(b"");
        });
    }
}
