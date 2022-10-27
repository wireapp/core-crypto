use super::local::Handle;
use ordered_float::OrderedFloat;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum PrimitiveProtocolValue {
    Undefined,
    Null,
    String(String),
    Number(OrderedFloat<f64>),
    Boolean(bool),
    BigInt(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum LocalValueInternal {
    Array(Vec<LocalValueInternal>),
    Date(String),
    Map(BTreeMap<String, LocalValueInternal>),
    Object(BTreeMap<String, LocalValueInternal>),
    RegExp { pattern: String, flags: Option<String> },
    Set(BTreeSet<LocalValueInternal>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum LocalValue {
    Primitive(PrimitiveProtocolValue),
    LocalValueInternal(LocalValueInternal),
}

pub type InternalId = u64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RemoteValue {
    RemoteValueInternal(RemoteValueInternal),
    Primitive(PrimitiveProtocolValue),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
// FIXME: Wrong annotation. There's no content to parse so it cannot work
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum RemoteValueType {
    Symbol,
    Array,
    Object,
    Function,
    Map,
    Set,
    WeakMap,
    WeakSet,
    Iterator,
    Generator,
    Error,
    Proxy,
    Promise,
    TypedArray,
    ArrayBuffer,
    Node,
    Window,
}
//FIXME: Those two are wrong. RemoteValueType should contain instances of RemoteValue
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteValueInternal {
    #[serde(rename = "type")]
    pub value_type: RemoteValueType,
    pub handle: Option<Handle>,
    pub internal_id: Option<u64>,
    pub value: Option<ConcreteRemoteValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
pub enum ConcreteRemoteValue {
    ListRemoteValue(Vec<RemoteValue>),
    MappingRemoteValueString(BTreeMap<String, RemoteValue>),
    MappingRemoteValueSymm(BTreeMap<RemoteValue, RemoteValue>),
    NodeProperties(Box<NodeProperties>),
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeProperties {
    pub node_type: u64,
    pub child_node_count: u64,
    pub attributes: Option<BTreeMap<String, String>>,
    pub children: Option<Vec<RemoteValueInternal>>,
    pub local_name: Option<String>,
    pub namespace_uri: Option<String>,
    pub node_value: Option<String>,
    pub shadow_root: Option<RemoteValueInternal>,
}
