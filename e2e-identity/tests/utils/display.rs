use base64::Engine;
use itertools::Itertools;
use std::path::PathBuf;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::X509Certificate;

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

    pub fn token(&mut self, label: &str, token: &str) {
        let event = Event::Token(label.to_string(), token.to_string());
        event.println();
        self.markdown.push(event.markdown());
        self.events.push(event);
    }

    pub fn cert(&mut self, label: &str, cert: &str) {
        let event = Event::Certificate(label.to_string(), cert.to_string());
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
                let protected = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(jws.protected).ok()?;
                let protected = serde_json::from_slice::<serde_json::Value>(protected.as_slice()).ok()?;

                let payload = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(jws.payload).ok()?;
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
    Token(String, String),
    Certificate(String, String),
    Request(Actor, Actor, Option<Req>),
    Response(Actor, Actor, Option<Resp>),
    Body(String, Option<String>),
}

impl Event {
    pub fn println(&self) {
        match self {
            Event::Step(i, title) => println!("{i}. {title}"),
            Event::Chapter(comment) => println!("----- {comment} -----\n"),
            Event::Token(label, token) => println!("{label}: https://jwt.io/#id_token={token}\n"),
            Event::Certificate(label, _) => println!("{label}:\n{}\n", self.cert_pem()),
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
            Event::Token(label, token) => format!("[{label}](https://jwt.io/#id_token={token})"),
            Event::Certificate(label, _) => format!(
                "###### {label}\n```\n{}\n```\n```\n{}\n```\n",
                self.cert_pem(),
                self.cert_pretty()
            ),
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

    fn cert_pretty(&self) -> String {
        match self {
            Event::Certificate(_, _) => {
                let cert = self.cert_pem();
                let cert = x509_parser::prelude::parse_x509_pem(cert.as_bytes());
                if let Ok((_, cert)) = cert {
                    let cert = cert.parse_x509().unwrap();
                    let version = cert.version;
                    let serial = cert.tbs_certificate.raw_serial_as_string();
                    let subject = cert.subject();
                    let issuer = cert.issuer();
                    let not_before = cert.validity().not_before;
                    let not_after = cert.validity().not_after;
                    let is_valid = cert.validity().is_valid();
                    let extensions = Self::cert_extensions(&cert);
                    format!(
                        r#"
version: {version}
serial: {serial}
subject: {subject}
issuer: {issuer}
validity:
  not before: {not_before}
  not after: {not_after}
  is valid: {is_valid}
extensions:
{extensions}
                "#
                    )
                } else {
                    "Invalid certificate".to_string()
                }
            }
            _ => unreachable!(),
        }
    }

    fn cert_extensions(cert: &X509Certificate) -> String {
        cert.extensions()
            .iter()
            .filter_map(|e| {
                match e.parsed_extension() {
                    ParsedExtension::SubjectAlternativeName(san) => Some(
                        san.general_names
                            .iter()
                            .map(|n| match n {
                                GeneralName::DNSName(dns) => format!("  SAN:DNSName: {dns}"),
                                GeneralName::URI(uri) => format!("  SAN:URI: {uri}"),
                                GeneralName::OtherName(oid, name) => format!(
                                    "  SAN:OtherName: {oid} {}",
                                    std::str::from_utf8(name).unwrap_or_default()
                                ),
                                GeneralName::RFC822Name(email) => format!("  SAN:RFC822Name: {email}"),
                                GeneralName::X400Address(x400) => format!("  SAN:X400Address: {x400:?}"),
                                GeneralName::DirectoryName(dn) => format!("  SAN:DirectoryName: {dn}"),
                                GeneralName::EDIPartyName(edipn) => format!("  SAN:EDIPartyName: {edipn:?}"),
                                GeneralName::IPAddress(ip) => format!("  SAN:IPAddress: {ip:?}"),
                                GeneralName::RegisteredID(id) => format!("  SAN:RegisteredID: {id}"),
                            })
                            .join("\n"),
                    ),
                    ParsedExtension::KeyUsage(ku) => Some(format!("  KeyUsage:{ku}")),
                    ParsedExtension::SubjectKeyIdentifier(ski) => Some(format!("  SubjectKeyIdentifier:{ski:x}")),
                    ParsedExtension::BasicConstraints(bc) => Some(format!(
                        "  BasicConstraints:Ca:{}\n  PathLenConstraint:{}",
                        bc.ca,
                        bc.path_len_constraint.unwrap_or_default()
                    )),
                    _ => None,
                    /*ParsedExtension::UnsupportedExtension { .. } => {}
                    ParsedExtension::IssuerAlternativeName(_) => {}
                    ParsedExtension::ParseError { .. } => {}
                    ParsedExtension::AuthorityKeyIdentifier(_) => {}
                    ParsedExtension::NameConstraints(_) => {}
                    ParsedExtension::CertificatePolicies(_) => {}
                    ParsedExtension::PolicyMappings(_) => {}
                    ParsedExtension::PolicyConstraints(_) => {}
                    ParsedExtension::ExtendedKeyUsage(_) => {}
                    ParsedExtension::CRLDistributionPoints(_) => {}
                    ParsedExtension::InhibitAnyPolicy(_) => {}
                    ParsedExtension::AuthorityInfoAccess(_) => {}
                    ParsedExtension::NSCertType(_) => {}
                    ParsedExtension::NsCertComment(_) => {}
                    ParsedExtension::CRLNumber(_) => {}
                    ParsedExtension::ReasonCode(_) => {}
                    ParsedExtension::InvalidityDate(_) => {}
                    ParsedExtension::SCT(_) => {}
                    ParsedExtension::Unparsed => {}*/
                }
            })
            .join("\n")
    }

    fn cert_pem(&self) -> String {
        match self {
            Event::Certificate(_, cert) => {
                format!("-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----")
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
