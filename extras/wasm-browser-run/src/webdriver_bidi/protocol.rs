#[derive(Debug, Clone)]
pub enum PrimitiveProtocolValue {
    Undefined,
    Null,
    String(String),
    Number(u64),
    Boolean(bool),
    BigInt(u64),
}

#[derive(Debug, Clone)]
pub enum LocalValue<K, V> {
    Array(Vec<V>),
    Date(String),
    Map(std::collections::HashMap<K, V>),
    Object(std::collections::HashMap<K, V>),
    RegExp(String),
    Set(std::collections::HashSet<V>),
}

#[derive(Debug, Clone)]
pub enum RemoteValue {
    Primitive(PrimitiveProtocolValue),
    Symbol,
    Array,
    Object,
    Function,
}
