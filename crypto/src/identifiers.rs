use std::str::FromStr;

use crate::CryptoError;

#[repr(transparent)]
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZeroKnowledgeUuid(uuid::Uuid);

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

impl FromStr for ZeroKnowledgeUuid {
    type Err = crate::CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed: Vec<&str> = s.split('@').take(2).collect();

        // Shortcircuit: Something bad happened
        if parsed.is_empty() {
            return Err(CryptoError::MalformedIdentifier(s.into()));
        }

        // If we don't have a domain to qualify the user UUID, just parse it
        if parsed.len() == 1 {
            return Ok(Self(uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_OID,
                parsed[0].as_bytes(),
            )));
        }

        let domain_str = parsed[0];
        let user_uuid_str = parsed[1];
        let domain_namespace_uuid =
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, domain_str.as_bytes());
        let nk_uuid = uuid::Uuid::new_v5(&domain_namespace_uuid, user_uuid_str.as_bytes());
        Ok(Self(nk_uuid))
    }
}
