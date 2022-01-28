use std::str::FromStr;

use crate::CryptoError;

trait Identifier<'a>: std::fmt::Debug + std::hash::Hash + TryFrom<&'a [u8]> + Into<Vec<u8>> {}

#[derive(Debug, Hash, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct QualifiedUuid {
    pub(crate) domain: String,
    pub(crate) uuid: uuid::Uuid,
}

// TODO: Separate types for conversation/member uuid structs

impl Identifier<'_> for QualifiedUuid {}

impl<'a> TryFrom<&'a [u8]> for QualifiedUuid {
    type Error = CryptoError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let str_self = std::str::from_utf8(value)?;
        str_self.parse()
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for QualifiedUuid {
    fn into(self) -> Vec<u8> {
        let mut ret = vec![];
        ret.extend_from_slice(self.uuid.hyphenated().to_string().as_bytes());
        ret.push(b'@');
        ret.extend_from_slice(&self.domain.into_bytes());

        ret
    }
}

impl QualifiedUuid {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut ret = vec![];
        ret.extend_from_slice(self.uuid.as_hyphenated().to_string().as_bytes());
        ret.push(b'@');
        ret.extend_from_slice(self.domain.as_bytes());

        ret
    }
}

impl std::fmt::Display for QualifiedUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.uuid, self.domain)
    }
}

impl FromStr for QualifiedUuid {
    type Err = crate::CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed: Vec<&str> = s.split('@').take(2).collect();

        // Shortcircuit: Something bad happened
        if parsed.is_empty() {
            return Err(CryptoError::MalformedIdentifier(s.into()));
        }

        let uuid = parsed[0].parse()?;

        // If we don't have a domain to qualify the user UUID, error out
        if parsed.len() == 1 {
            return Err(CryptoError::MalformedIdentifier(s.into()));
        }

        Ok(Self {
            domain: parsed[1].into(),
            uuid,
        })
    }
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ZeroKnowledgeUuid(uuid::Uuid);

impl<'a> TryFrom<&'a [u8]> for ZeroKnowledgeUuid {
    type Error = CryptoError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let str_self = std::str::from_utf8(value)?;
        str_self.parse()
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for ZeroKnowledgeUuid {
    fn into(self) -> Vec<u8> {
        self.as_bytes()
    }
}

impl ZeroKnowledgeUuid {
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl From<uuid::Uuid> for ZeroKnowledgeUuid {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl std::ops::Deref for ZeroKnowledgeUuid {
    type Target = uuid::Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for ZeroKnowledgeUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<QualifiedUuid> for ZeroKnowledgeUuid {
    fn from(quuid: QualifiedUuid) -> Self {
        let domain_namespace_uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, quuid.domain.as_bytes());
        let nk_uuid = uuid::Uuid::new_v5(&domain_namespace_uuid, quuid.uuid.as_bytes());
        Self(nk_uuid)
    }
}

impl FromStr for ZeroKnowledgeUuid {
    type Err = crate::CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let quuid = QualifiedUuid::from_str(s)?;
        Ok(quuid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{QualifiedUuid, ZeroKnowledgeUuid};
    use std::str::FromStr as _;

    #[test]
    fn quuid_can_parse_qualified_uuid() {
        let domain = "test.wire.com";
        let uuid = uuid::Uuid::new_v4().hyphenated().to_string();

        let quuid = QualifiedUuid::from_str(&format!("{}@{}", uuid, domain)).unwrap();
        assert_eq!(domain, quuid.domain);
        assert_eq!(uuid.parse::<uuid::Uuid>().unwrap(), quuid.uuid);
    }

    #[test]
    #[should_panic]
    fn quuid_can_parse_unqualified_uuid() {
        let uuid = uuid::Uuid::new_v4().hyphenated().to_string();

        let _quuid = QualifiedUuid::from_str(&uuid).unwrap();
    }

    #[test]
    fn zku_can_passthrough_uuid() {
        let uuid_string = uuid::Uuid::new_v4().hyphenated().to_string();
        let zkuuid: ZeroKnowledgeUuid = uuid::Uuid::from_str(&uuid_string).unwrap().into();
        assert_eq!(*zkuuid, uuid::Uuid::from_str(&uuid_string).unwrap());
    }

    #[test]
    #[should_panic]
    fn zku_can_parse_unqualified_uuid() {
        let uuid_string = uuid::Uuid::new_v4().hyphenated().to_string();
        let _parsed_uuid = uuid_string.parse::<uuid::Uuid>().unwrap();
        let _zkuuid: ZeroKnowledgeUuid = uuid_string.parse().unwrap();
    }

    #[test]
    fn zku_can_parse_qualified_uuid() {
        let domain = "test.wire.com";
        let uuid_string = uuid::Uuid::new_v4().hyphenated().to_string();

        let zkuuid: ZeroKnowledgeUuid = format!("{}@{}", uuid_string, domain).parse().unwrap();
        let domain_uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, domain.as_bytes());
        let wrapped_uuid = uuid::Uuid::new_v5(&domain_uuid, uuid_string.parse::<uuid::Uuid>().unwrap().as_bytes());
        assert_eq!(*zkuuid, wrapped_uuid);
    }
}
