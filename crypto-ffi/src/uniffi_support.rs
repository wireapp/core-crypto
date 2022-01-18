use crate::UniffiCustomTypeWrapper;

impl UniffiCustomTypeWrapper for core_crypto::identifiers::QualifiedUuid {
    type Wrapped = String;

    fn wrap(val: Self::Wrapped) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.parse()?)
    }

    fn unwrap(obj: Self) -> Self::Wrapped {
        obj.to_string()
    }
}

impl UniffiCustomTypeWrapper for core_crypto::identifiers::ZeroKnowledgeUuid {
    type Wrapped = String;

    fn wrap(val: Self::Wrapped) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.parse()?)
    }

    fn unwrap(obj: Self) -> Self::Wrapped {
        obj.to_string()
    }
}

impl UniffiCustomTypeWrapper for core_crypto::prelude::ClientId {
    type Wrapped = String;

    fn wrap(val: Self::Wrapped) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.parse()?)
    }

    fn unwrap(obj: Self) -> Self::Wrapped {
        obj.to_string()
    }
}
