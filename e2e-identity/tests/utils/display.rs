use itertools::Itertools;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct TestDisplay {
    pub title: String,
    pub events: Vec<Event>,
    pub markdown: Vec<String>,
    pub mermaid: Vec<String>,
    pub ctr: u32,
}

impl TestDisplay {
    pub fn clear() {
        let readme = Self::readme();
        std::fs::write(readme, "# Wire end to end identity example").unwrap();
    }

    pub fn new(title: String) -> Self {
        Self {
            title,
            events: vec![],
            markdown: vec![],
            mermaid: vec![],
            ctr: 0,
        }
    }

    pub fn step(&mut self, label: &str) {
        self.ctr += 1;
        let event = Event::Step(self.ctr, label.to_string());
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn chapter(&mut self, comment: &str) {
        let event = Event::Chapter(comment.to_string());
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn token(&mut self, token: &str) {
        let event = Event::Token(token.to_string());
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn req(&mut self, from: Actor, to: Actor, req: Option<&reqwest::Request>) {
        let event = Event::Request(from, to, req.map(Req::from));
        event.println();
        self.mermaid.push(event.mermaid());
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn resp(&mut self, from: Actor, to: Actor, resp: Option<&reqwest::Response>) {
        let event = Event::Response(from, to, resp.map(Resp::from));
        event.println();
        self.mermaid.push(event.mermaid());
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn body<T: serde::Serialize>(&mut self, body: &T) {
        let body = serde_json::to_string_pretty(body).unwrap();
        let acme_payload = serde_json::from_str::<rusty_acme::prelude::AcmeJws>(&body)
            .ok()
            .and_then(|jws| {
                let protected = base64::decode_config(jws.protected, base64::URL_SAFE_NO_PAD).ok()?;
                let protected = serde_json::from_slice::<serde_json::Value>(protected.as_slice()).ok()?;

                let payload = base64::decode_config(jws.payload, base64::URL_SAFE_NO_PAD).ok()?;
                let payload = serde_json::from_slice::<serde_json::Value>(payload.as_slice()).ok()?;

                let decoded = serde_json::json!({
                    "protected": protected,
                    "payload": payload
                });
                serde_json::to_string_pretty(&decoded).ok()
            });
        let event = Event::Body(body, acme_payload);
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display(self) {
        let readme = Self::readme();
        let mermaid = self.mermaid.join("\n");
        let mermaid = format!("\n```mermaid\nsequenceDiagram\n    autonumber\n{mermaid}\n```\n");
        let content = [self.title, mermaid, self.markdown.join("\n")].concat();

        let current = std::fs::read_to_string(&readme).unwrap();
        let content = format!("{current}\n{content}");
        std::fs::write(readme, content).unwrap();
    }

    fn readme() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md")
    }
}

#[derive(Debug)]
pub enum Event {
    Step(u32, String),
    Chapter(String),
    Token(String),
    Request(Actor, Actor, Option<Req>),
    Response(Actor, Actor, Option<Resp>),
    Body(String, Option<String>),
}

impl Event {
    pub fn println(&self) {
        match self {
            Event::Step(i, title) => println!("{i}. {title}"),
            Event::Chapter(comment) => println!("----- {comment} -----\n"),
            Event::Token(token) => println!("https://jwt.io/#id_token={token}\n"),
            Event::Request(_from, _to, Some(req)) => println!("=> {req:?}\n"),
            Event::Response(_from, _to, Some(resp)) => println!("<= {resp:?}"),
            Event::Body(body, Some(acme_payload)) => println!("{body}\n{acme_payload}\n"),
            Event::Body(body, None) => println!("{body}\n"),
            _ => {}
        }
    }

    pub fn markdown(&self) -> String {
        match self {
            Event::Chapter(comment) => format!("### {comment}"),
            Event::Step(i, title) => format!("#### {i}. {title}"),
            Event::Token(token) => format!("Token [here](https://jwt.io/#id_token={token})"),
            Event::Request(_from, _to, Some(req)) => format!("```http request\n{req:?}\n```"),
            Event::Response(_from, _to, Some(resp)) => format!("```http request\n{resp:?}\n```"),
            Event::Body(body, Some(acme_payload)) => {
                format!("```json\n{body}\n...decoded...\n{acme_payload}\n```")
            }
            Event::Body(body, None) => format!("```json\n{body}\n```"),
            _ => String::new(),
        }
    }

    pub fn mermaid(&self) -> String {
        match self {
            Event::Request(from, to, req) => {
                if let Some(req) = req {
                    format!("    {from}->>+{to}: {req}",)
                } else {
                    format!("    {from}->>+{to}: 200",)
                }
            }
            Event::Response(from, to, resp) => {
                if let Some(resp) = resp {
                    format!("    {from}->>-{to}: {resp}")
                } else {
                    format!("    {from}->>-{to}: 200")
                }
            }
            _ => unreachable!(),
        }
    }
}

const EXCEPT_HEADERS: [&str; 7] = [
    "date",
    "content-length",
    "dpop",
    "client-id",
    "backend-kp",
    "hash-alg",
    "wire-server-uri",
];

pub struct Req(String, String);

impl From<&reqwest::Request> for Req {
    fn from(req: &reqwest::Request) -> Self {
        let method = req.method().as_str();
        let url = req.url().as_str();
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .filter(|(k, _)| !EXCEPT_HEADERS.contains(k))
            .map(|(k, v)| format!("{k}: {v}"))
            .join("\n");
        let complete = format!("{method} {url}\n{headers}");
        let path = req.url().path();
        let simple = format!("{method} {path}");
        Self(complete, simple)
    }
}

impl std::fmt::Debug for Req {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for Req {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.1)
    }
}

pub struct Resp(String, String);

impl From<&reqwest::Response> for Resp {
    fn from(resp: &reqwest::Response) -> Self {
        let status = resp.status();

        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .filter(|(k, _)| !EXCEPT_HEADERS.contains(k))
            .map(|(k, v)| format!("{k}: {v}"))
            .join("\n");
        let complete = format!("{status:?}\n{headers}");
        let simple = format!("{status:?}");
        Self(complete, simple)
    }
}

impl std::fmt::Debug for Resp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::fmt::Display for Resp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.1)
    }
}

#[derive(Debug)]
pub enum Actor {
    WireClient,
    WireBe,
    AcmeBe,
}

impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Actor::WireClient => "wire-client",
            Actor::WireBe => "wire-server",
            Actor::AcmeBe => "acme-server",
        };
        write!(f, "{name}")
    }
}
