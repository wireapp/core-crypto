use crate::UniffiCustomTypeConverter;

impl UniffiCustomTypeConverter for core_crypto::identifiers::QualifiedUuid {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.parse()?)
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

impl UniffiCustomTypeConverter for core_crypto::identifiers::ZeroKnowledgeUuid {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.parse()?)
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

impl UniffiCustomTypeConverter for core_crypto::prelude::ClientId {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.parse()?)
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}
