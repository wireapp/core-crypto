use std::{path::PathBuf, process::Command};

use base64::Engine;
use itertools::Itertools;
use jwt_simple::prelude::*;

use rusty_jwt_tools::prelude::*;

use crate::utils::rand_base64_str;

#[derive(Debug, Clone, Default)]
pub struct TestDisplay {
    pub title: String,
    pub events: Vec<Event>,
    pub markdown: Vec<String>,
    pub mermaid: Vec<String>,
    pub ctr: u32,
    pub is_active: bool,
}

impl TestDisplay {
    pub fn clear() {
        let readme = Self::readme();
        std::fs::write(readme, "# Wire end to end identity example").unwrap();
    }

    pub fn new(title: String, is_active: bool) -> Self {
        Self {
            title,
            events: vec![],
            markdown: vec![],
            mermaid: vec![],
            ctr: 0,
            is_active,
        }
    }

    pub fn set_active(&mut self) {
        self.is_active = true;
    }

    pub fn display_step(&mut self, label: &str) {
        self.ctr += 1;
        let event = Event::Step {
            number: self.ctr,
            title: label.to_string(),
        };
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_chapter(&mut self, comment: &str) {
        let event = Event::Chapter {
            comment: comment.to_string(),
        };
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_token(&mut self, label: &str, token: &str, alg: Option<JwsAlgorithm>, keypair: String) {
        let event = Event::Token {
            label: label.to_string(),
            token: token.to_string(),
            alg,
            pk: keypair,
        };
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_cert(&mut self, label: &str, cert: &[u8], csr: bool) {
        let event = if !csr {
            let cert = pem::Pem::new("CERTIFICATE", cert);
            let cert = pem::encode(&cert);
            Event::Certificate {
                label: label.to_string(),
                cert,
            }
        } else {
            let cert = pem::Pem::new("CERTIFICATE REQUEST", cert);
            let cert = pem::encode(&cert);
            Event::Csr {
                label: label.to_string(),
                cert,
            }
        };
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_req(
        &mut self,
        from: Actor,
        to: Actor,
        req: Option<&reqwest::Request>,
        url_pattern: Option<&'static str>,
    ) {
        let event = Event::Request {
            from,
            to,
            req: req.map(|r| Req::new(r, url_pattern)),
        };
        event.println();
        self.mermaid.push(event.mermaid());
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_operation(&mut self, actor: Actor, msg: &str) {
        let event = Event::Operation {
            actor,
            msg: msg.to_string(),
        };
        event.println();
        self.mermaid.push(event.mermaid());
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_resp(&mut self, from: Actor, to: Actor, resp: Option<&reqwest::Response>) {
        let event = Event::Response {
            from,
            to,
            resp: resp.map(Resp::from),
        };
        event.println();
        self.mermaid.push(event.mermaid());
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_body<T: serde::Serialize>(&mut self, body: &T) {
        let body = serde_json::to_string_pretty(body).unwrap();
        let acme_payload = serde_json::from_str::<rusty_acme::prelude::AcmeJws>(&body)
            .ok()
            .and_then(|jws| {
                let protected = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(jws.protected).ok()?;
                let protected = serde_json::from_slice::<serde_json::Value>(protected.as_slice()).ok()?;

                let payload = base64::prelude::BASE64_URL_SAFE_NO_PAD
                    .decode(jws.payload)
                    .ok()
                    .and_then(|payload| serde_json::from_slice::<serde_json::Value>(payload.as_slice()).ok())
                    .unwrap_or(serde_json::json!({}));

                let decoded = serde_json::json!({
                    "protected": protected,
                    "payload": payload
                });
                serde_json::to_string_pretty(&decoded).ok()
            });
        let event = Event::Body {
            raw: body,
            pretty: acme_payload,
        };
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_str(&mut self, value: &str, raw: bool) {
        let event = Event::Str {
            value: value.to_string(),
            raw,
        };
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display_note(&mut self, value: &str) {
        let event = Event::Note {
            value: value.to_string(),
        };
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn display(&mut self) {
        if self.is_active {
            let readme = Self::readme();
            let mermaid = self.mermaid.join("\n");
            let mermaid = format!("\n```mermaid\nsequenceDiagram\n    autonumber\n{mermaid}\n```\n");
            let content = [self.title.to_string(), mermaid, self.markdown.join("\n")].concat();

            let current = std::fs::read_to_string(&readme).unwrap();
            let content = format!("{current}\n{content}");
            std::fs::write(readme, content).unwrap();
        }
    }

    fn readme() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md")
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Step {
        number: u32,
        title: String,
    },
    Chapter {
        comment: String,
    },
    Token {
        label: String,
        token: String,
        // TODO: temporary until Dex supports EdDSA and not just RSA
        alg: Option<JwsAlgorithm>,
        pk: String,
    },
    Certificate {
        label: String,
        cert: String,
    },
    Csr {
        label: String,
        cert: String,
    },
    Operation {
        actor: Actor,
        msg: String,
    },
    Request {
        from: Actor,
        to: Actor,
        req: Option<Req>,
    },
    Response {
        from: Actor,
        to: Actor,
        resp: Option<Resp>,
    },
    Body {
        raw: String,
        pretty: Option<String>,
    },
    Str {
        value: String,
        raw: bool,
    },
    Note {
        value: String,
    },
}

impl Event {
    pub fn println(&self) {
        match self {
            Self::Step { number, title } => println!("{number}. {title}"),
            Self::Chapter { comment } => println!("----- {comment} -----\n"),
            Self::Token { label, token, .. } => println!("{label}: https://jwt.io/#id_token={token}\n"),
            Self::Certificate { label, cert } => {
                let (pretty, verify) = self.cert_pretty();
                println!("{label}\n{verify}\n```\n{cert}\n```\n```\n{pretty}\n```\n")
            }
            Self::Csr { label, cert } => println!("{label}:\n{cert}\n"),
            Self::Request { req: Some(req), .. } => println!("=> {req:?}\n"),
            Self::Response { resp: Some(resp), .. } => println!("<= {resp:?}"),
            Self::Body {
                raw,
                pretty: Some(acme_payload),
            } => println!("{raw}\n{acme_payload}\n"),
            Self::Body { raw, .. } => println!("{raw}\n"),
            Self::Str { value: body, .. } => println!("\n{body}\n"),
            _ => {}
        }
    }

    pub fn markdown(&self) -> String {
        match self {
            Self::Chapter { comment } => format!("### {comment}"),
            Self::Step { number, title } => format!("#### {number}. {title}"),
            Self::Token { label, token, alg, pk } => {
                let link = format!("See it on [jwt.io](https://jwt.io/#id_token={token})");
                let parts = token.split('.').collect::<Vec<&str>>();

                let json_pretty = |token: &str| {
                    let jwt = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(token).unwrap();
                    let jwt = serde_json::from_slice::<serde_json::Value>(&jwt[..]).unwrap();
                    serde_json::to_string_pretty(&jwt).unwrap()
                };

                const WIDTH: usize = 64;
                // insert EOL characters for a prettier display
                let pretty_token = token
                    .chars()
                    .chunks(WIDTH)
                    .into_iter()
                    .map(|mut c| c.join(""))
                    .join("\n");

                let header = format!("\n```json\n{}\n```", json_pretty(parts[0]));
                let body = format!("\n```json\n{}\n```\n", json_pretty(parts[1]));

                let signature_valid = match alg {
                    Some(alg) => {
                        let kp: Pem = pk.to_string().into();
                        let key = AnyPublicKey::from((*alg, &kp));
                        key.verify_token::<()>(token, None).map(|_| ())
                    }
                    None => {
                        // temporary solution
                        let pk = RS256PublicKey::from_pem(pk).unwrap();
                        pk.verify_token::<()>(token, None).map(|_| ())
                    }
                }
                .map(|_| "✅ Signature Verified")
                .unwrap_or("❌ Invalid Signature");

                format!(
                    r#"
<details>
<summary><b>{label}</b></summary>

{link}

Raw:
```text
{pretty_token}
```

Decoded:
{header}
{body}

{signature_valid} with key:
```text
{}
```

</details>

"#,
                    pk.trim()
                )
            }
            Self::Certificate { label, cert } => {
                let (pretty, verify) = self.cert_pretty();
                format!("###### {label}\n{verify}\n```\n{cert}\n```\n```\n{pretty}\n```\n")
            }
            Self::Csr { label, cert } => {
                let (pretty, verify) = self.cert_pretty();
                format!("###### {label}\n{verify}\n```\n{cert}\n```\n```\n{pretty}\n```\n")
            }
            Self::Request { req: Some(req), .. } => format!("```http request\n{req:?}\n```"),
            Self::Response { resp: Some(resp), .. } => format!("```http request\n{resp:?}\n```"),
            Self::Body {
                raw,
                pretty: Some(acme_payload),
            } => {
                format!("```json\n{raw}\n```\n```json\n{acme_payload}\n```")
            }
            Self::Body { raw, .. } => format!("```json\n{raw}\n```"),
            Self::Str { value, raw } => {
                if *raw {
                    value.to_string()
                } else {
                    format!("```text\n{value}\n```")
                }
            }
            Self::Note { value } => format!("Note: {value}"),
            _ => "".to_string(),
        }
    }

    pub fn mermaid(&self) -> String {
        match self {
            Self::Request { from, to, req, .. } => {
                let lock = req.as_ref().filter(|r| r.2).map(|_| "🔒").unwrap_or_default();
                let req = req.as_ref().map(|r| format!("{r}")).unwrap_or("200".to_string());
                format!("    {from}->>+{to}: {lock} {req}",)
            }
            Self::Response { from, to, resp } => {
                let resp = resp.as_ref().map(|r| format!("{r}")).unwrap_or("200".to_string());
                format!("    {from}->>-{to}: {resp}")
            }
            Self::Operation { actor, msg } => format!("    {actor}->>{actor}: {msg}"),
            _ => unreachable!(),
        }
    }

    fn cert_pretty(&self) -> (String, String) {
        let (extension, cert, mut pretty_args, mut verify_args) = match self {
            Event::Certificate { cert, .. } => (
                "pem",
                cert.to_string(),
                vec!["x509", "-text", "-noout", "-in"],
                vec!["x509", "-verify", "-in"],
            ),
            Event::Csr { cert, .. } => (
                "csr",
                cert.to_string(),
                vec!["req", "-text", "-noout", "-in"],
                vec!["req", "-verify", "-in"],
            ),
            _ => unreachable!(),
        };
        let path = std::env::temp_dir().join(format!("cert-{}.{extension}", rand_base64_str(12)));
        std::fs::write(&path, cert).unwrap();
        let path_str = path.to_str().unwrap();

        pretty_args.push(path_str);
        verify_args.push(path_str);

        let out = Command::new("openssl").args(pretty_args).output().unwrap();
        let pretty_out = String::from_utf8(out.stdout).unwrap();

        let out = Command::new("openssl").args(verify_args).output().unwrap();
        let verify = if out.status.success() { "✅" } else { "❌" };
        let verify = format!("openssl -verify {verify}");

        (pretty_out, verify)
    }
}

const EXCEPT_HEADERS: [&str; 2] = ["date", "content-length"];

#[derive(Clone)]
pub struct Req(String, String, bool);

impl Req {
    pub fn new(req: &reqwest::Request, url_pattern: Option<&'static str>) -> Self {
        let is_tls = matches!(req.url().scheme(), "https");
        let method = req.method().as_str();
        let url = req.url().as_str();
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .filter(|(k, _)| !EXCEPT_HEADERS.contains(k))
            .map(|(k, v)| format!("{k}: {v}"))
            .join("\n");
        let url = format!("{method} {url}");

        let url = if let Some(pattern) = url_pattern {
            // calculate at which position to insert the url pattern
            let path_len = req.url().path().len();
            let position = url.len() - path_len;
            let whitespaces = vec![" "; position].join("");
            format!("{url}\n{whitespaces}{pattern}")
        } else {
            url
        };

        let complete = format!("{url}\n{headers}").trim().to_string();
        let path = req.url().path();
        let simple = format!("{method} {path}").trim().to_string();
        Self(complete, simple, is_tls)
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

#[derive(Clone)]
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

#[derive(Debug, Clone)]
pub enum Actor {
    WireClient,
    WireServer,
    AcmeServer,
    IdentityProvider,
}

impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Actor::WireClient => "wire-client",
            Actor::WireServer => "wire-server",
            Actor::AcmeServer => "acme-server",
            Actor::IdentityProvider => "IdP",
        };
        write!(f, "{name}")
    }
}
