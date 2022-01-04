use std::str::FromStr;

use crate::CryptoError;

#[derive(Debug, Hash, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct QualifiedUuid {
    domain: Option<String>,
    uuid: uuid::Uuid,
}

impl QualifiedUuid {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = vec![];
        ret.extend_from_slice(self.uuid.as_bytes());
        if let Some(domain) = self.domain.as_ref() {
            ret.extend_from_slice(domain.as_bytes());
        }

        ret
    }
}

impl std::fmt::Display for QualifiedUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(domain) = self.domain.as_ref() {
            write!(f, "{}@{}", self.uuid, domain)
        } else {
            self.uuid.fmt(f)
        }
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

        // If we don't have a domain to qualify the user UUID, just parse it
        if parsed.len() == 1 {
            return Ok(Self {
                domain: None,
                uuid,
            });
        }

        Ok(Self {
            domain: Some(parsed[1].into()),
            uuid,
        })
    }
}

#[repr(transparent)]
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZeroKnowledgeUuid(uuid::Uuid);

impl ZeroKnowledgeUuid {
    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Vec<u8> {
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
    fn from(mut quuid: QualifiedUuid) -> Self {
        match quuid.domain.take() {
            Some(domain) => {
                let domain_namespace_uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, domain.as_bytes());
                let nk_uuid = uuid::Uuid::new_v5(&domain_namespace_uuid, quuid.uuid.as_bytes());
                Self(nk_uuid)
            },
            // If we don't have a domain to qualify the user UUID, make a OID v5 UUID out of it
            // None => Ok(Self(uuid::Uuid::new_v5(
            //     &uuid::Uuid::NAMESPACE_OID,
            //     quuid.uuid.as_bytes(),
            // ))),
            // Or maybe just wrap it?
            None => Self(quuid.uuid)
        }
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
    use std::str::FromStr as _;
    use super::{ZeroKnowledgeUuid, QualifiedUuid};

    #[test]
    fn quuid_can_parse_qualified_uuid() {
        let domain = "test.wire.com";
        let uuid = "ef09751c-94fe-4b68-8581-0a0ff645f8f4";

        let quuid = QualifiedUuid::from_str(&format!("{}@{}", uuid, domain)).unwrap();
        assert_eq!(domain, quuid.domain.unwrap());
        assert_eq!(uuid.parse::<uuid::Uuid>().unwrap(), quuid.uuid);
    }

    #[test]
    fn quuid_can_parse_unqualified_uuid() {
        let uuid = "2125d710-6a17-49a4-8ee0-11fdf95a6a96";

        let quuid = QualifiedUuid::from_str(uuid).unwrap();
        assert!(quuid.domain.is_none());
        assert_eq!(uuid.parse::<uuid::Uuid>().unwrap(), quuid.uuid);
    }

    #[test]
    fn zku_can_passthrough_uuid() {
        let uuid_string = "e7addfa1-fed8-4a28-ab20-f38e3bf4c42c";
        let zkuuid: ZeroKnowledgeUuid = uuid::Uuid::from_str(uuid_string).unwrap().into();
        assert_eq!(*zkuuid, uuid::Uuid::from_str(uuid_string).unwrap());
    }

    #[test]
    fn zku_can_parse_unqualified_uuid() {
        let uuid_string = "03d1e75d-8e73-4980-987e-716180ab823e";
        let parsed_uuid = uuid_string.parse::<uuid::Uuid>().unwrap();
        let zkuuid: ZeroKnowledgeUuid = uuid_string.parse().unwrap();
        assert_eq!(*zkuuid, parsed_uuid);
    }

    #[test]
    fn zku_can_parse_qualified_uuid() {
        let domain = "test.wire.com";
        let uuid_string = "e928c128-6f30-403e-8827-96863a592f3c";

        let zkuuid: ZeroKnowledgeUuid = format!("{}@{}", uuid_string, domain).parse().unwrap();
        let domain_uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, domain.as_bytes());
        let wrapped_uuid = uuid::Uuid::new_v5(&domain_uuid, uuid_string.parse::<uuid::Uuid>().unwrap().as_bytes());
        assert_eq!(*zkuuid, wrapped_uuid);
    }
}
