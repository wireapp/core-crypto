//! This module contains the expansion of the `#[derive(core_crypto_macros::Entity)]` macro
//! for `PersistedMlsGroup`.
//!
//! That macro doesn't generate the legacy trait impls anymore, so we just expanded them and
//! pasted them in here.

// somehow in the macro expansions some unused braces get generated and it's not worth
// fixing them here.
#![allow(unused_braces)]

use crate::{
    connection::idb_migration::legacy::{connection, traits},
    entities::PersistedMlsGroup,
    traits::{BorrowPrimaryKey, KeyType},
};

impl traits::EntityBase for PersistedMlsGroup {
    type ConnectionType = connection::KeystoreDatabaseConnection;
    const COLLECTION_NAME: &'static str = "mls_groups";
    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::PersistedMlsGroup(self.into())
    }
}
impl traits::Entity for PersistedMlsGroup {
    #[allow(
        mismatched_lifetime_syntaxes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn get<'life0, 'life1, 'async_trait>(
        conn: &'life0 mut Self::ConnectionType,
        key: &'life1 Self::PrimaryKey,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<Option<Self>>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<crate::CryptoKeystoreResult<Option<Self>>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __ret: crate::CryptoKeystoreResult<Option<Self>> =
                { <Self as traits::EntityGetBorrowed>::get_borrowed(conn, key).await };
            #[allow(unreachable_code)]
            __ret
        })
    }
    #[allow(
        mismatched_lifetime_syntaxes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn count<'life0, 'async_trait>(
        conn: &'life0 mut Self::ConnectionType,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<u32>> + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<crate::CryptoKeystoreResult<u32>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __ret: crate::CryptoKeystoreResult<u32> = { conn.storage().count::<Self>().await };
            #[allow(unreachable_code)]
            __ret
        })
    }
    #[allow(
        mismatched_lifetime_syntaxes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn load_all<'life0, 'async_trait>(
        conn: &'life0 mut Self::ConnectionType,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<Vec<Self>>> + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<crate::CryptoKeystoreResult<Vec<Self>>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __ret: crate::CryptoKeystoreResult<Vec<Self>> = { conn.storage().get_all().await };
            #[allow(unreachable_code)]
            __ret
        })
    }
}
impl traits::EntityGetBorrowed for PersistedMlsGroup {
    #[allow(
        mismatched_lifetime_syntaxes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn get_borrowed<'life0, 'life1, 'async_trait>(
        conn: &'life0 mut Self::ConnectionType,
        key: &'life1 Self::BorrowedPrimaryKey,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<Option<Self>>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<crate::CryptoKeystoreResult<Option<Self>>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __ret: crate::CryptoKeystoreResult<Option<Self>> = {
                let key = <&Self::BorrowedPrimaryKey as KeyType>::bytes(&key);
                let key = key.as_ref();
                { conn.storage().get(key).await }
            };
            #[allow(unreachable_code)]
            __ret
        })
    }
}
impl<'a> traits::EntityDatabaseMutation<'a> for PersistedMlsGroup {
    type Transaction = connection::TransactionWrapper<'a>;
    type AutoGeneratedFields = ();
    #[allow(
        mismatched_lifetime_syntaxes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn save<'life0, 'async_trait>(
        &'a self,
        tx: &'life0 Self::Transaction,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<()>> + 'async_trait>>
    where
        'a: 'async_trait,
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) = ::core::option::Option::None::<crate::CryptoKeystoreResult<()>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __self = self;
            let __ret: crate::CryptoKeystoreResult<()> = { { tx.save(__self).await } };
            #[allow(unreachable_code)]
            __ret
        })
    }
    #[allow(
        mismatched_lifetime_syntaxes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn count<'life0, 'async_trait>(
        tx: &'life0 Self::Transaction,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<u32>> + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<crate::CryptoKeystoreResult<u32>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __ret: crate::CryptoKeystoreResult<u32> = { { tx.count::<Self>().await } };
            #[allow(unreachable_code)]
            __ret
        })
    }
    #[allow(
        mismatched_lifetime_syntaxes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn delete<'life0, 'life1, 'async_trait>(
        tx: &'life0 Self::Transaction,
        id: &'life1 Self::PrimaryKey,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<bool>> + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<crate::CryptoKeystoreResult<bool>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __ret: crate::CryptoKeystoreResult<bool> =
                { <Self as traits::EntityDeleteBorrowed>::delete_borrowed(tx, id).await };
            #[allow(unreachable_code)]
            __ret
        })
    }
}
impl<'a> traits::EntityDeleteBorrowed<'a> for PersistedMlsGroup {
    #[allow(
        mismatched_lifetime_syntaxes,
        clippy::async_yields_async,
        clippy::diverging_sub_expression,
        clippy::let_unit_value,
        clippy::needless_arbitrary_self_type,
        clippy::no_effect_underscore_binding,
        clippy::shadow_same,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds,
        clippy::used_underscore_binding
    )]
    fn delete_borrowed<'life0, 'life1, 'async_trait>(
        tx: &'life0 <Self as traits::EntityDatabaseMutation<'a>>::Transaction,
        id: &'life1 <Self as BorrowPrimaryKey>::BorrowedPrimaryKey,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<bool>> + 'async_trait>>
    where
        for<'pk> &'pk <Self as BorrowPrimaryKey>::BorrowedPrimaryKey: KeyType,
        'a: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            if let ::core::option::Option::Some(__ret) =
                ::core::option::Option::None::<crate::CryptoKeystoreResult<bool>>
            {
                #[allow(unreachable_code)]
                return __ret;
            }
            let __ret: crate::CryptoKeystoreResult<bool> = {
                let key = <&<Self as BorrowPrimaryKey>::BorrowedPrimaryKey as KeyType>::bytes(&id);
                let key = key.as_ref();
                { tx.delete::<Self>(key).await }
            };
            #[allow(unreachable_code)]
            __ret
        })
    }
}
pub(crate) struct PersistedMlsGroupDecrypt {
    id: Vec<u8>,
    parent_id: Option<Vec<u8>>,
    state: Vec<u8>,
}
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::absolute_paths
)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for PersistedMlsGroupDecrypt {
        fn deserialize<__D>(__deserializer: __D) -> _serde::__private228::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
                __field2,
                __ignore,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private228::Formatter,
                ) -> _serde::__private228::fmt::Result {
                    _serde::__private228::Formatter::write_str(__formatter, "field identifier")
                }
                fn visit_u64<__E>(self, __value: u64) -> _serde::__private228::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private228::Ok(__Field::__field0),
                        1u64 => _serde::__private228::Ok(__Field::__field1),
                        2u64 => _serde::__private228::Ok(__Field::__field2),
                        _ => _serde::__private228::Ok(__Field::__ignore),
                    }
                }
                fn visit_str<__E>(self, __value: &str) -> _serde::__private228::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "id" => _serde::__private228::Ok(__Field::__field0),
                        "parent_id" => _serde::__private228::Ok(__Field::__field1),
                        "state" => _serde::__private228::Ok(__Field::__field2),
                        _ => _serde::__private228::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(self, __value: &[u8]) -> _serde::__private228::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"id" => _serde::__private228::Ok(__Field::__field0),
                        b"parent_id" => _serde::__private228::Ok(__Field::__field1),
                        b"state" => _serde::__private228::Ok(__Field::__field2),
                        _ => _serde::__private228::Ok(__Field::__ignore),
                    }
                }
            }
            #[automatically_derived]
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(__deserializer: __D) -> _serde::__private228::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: _serde::__private228::PhantomData<PersistedMlsGroupDecrypt>,
                lifetime: _serde::__private228::PhantomData<&'de ()>,
            }
            #[automatically_derived]
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = PersistedMlsGroupDecrypt;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private228::Formatter,
                ) -> _serde::__private228::fmt::Result {
                    _serde::__private228::Formatter::write_str(__formatter, "struct PersistedMlsGroupDecrypt")
                }
                #[inline]
                fn visit_seq<__A>(self, mut __seq: __A) -> _serde::__private228::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 = match _serde::de::SeqAccess::next_element::<Vec<u8>>(&mut __seq)? {
                        _serde::__private228::Some(__value) => __value,
                        _serde::__private228::None => {
                            return _serde::__private228::Err(_serde::de::Error::invalid_length(
                                0usize,
                                &"struct PersistedMlsGroupDecrypt with 3 elements",
                            ));
                        }
                    };
                    let __field1 = match _serde::de::SeqAccess::next_element::<Option<Vec<u8>>>(&mut __seq)? {
                        _serde::__private228::Some(__value) => __value,
                        _serde::__private228::None => {
                            return _serde::__private228::Err(_serde::de::Error::invalid_length(
                                1usize,
                                &"struct PersistedMlsGroupDecrypt with 3 elements",
                            ));
                        }
                    };
                    let __field2 = match _serde::de::SeqAccess::next_element::<Vec<u8>>(&mut __seq)? {
                        _serde::__private228::Some(__value) => __value,
                        _serde::__private228::None => {
                            return _serde::__private228::Err(_serde::de::Error::invalid_length(
                                2usize,
                                &"struct PersistedMlsGroupDecrypt with 3 elements",
                            ));
                        }
                    };
                    _serde::__private228::Ok(PersistedMlsGroupDecrypt {
                        id: __field0,
                        parent_id: __field1,
                        state: __field2,
                    })
                }
                #[inline]
                fn visit_map<__A>(self, mut __map: __A) -> _serde::__private228::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::__private228::Option<Vec<u8>> = _serde::__private228::None;
                    let mut __field1: _serde::__private228::Option<Option<Vec<u8>>> = _serde::__private228::None;
                    let mut __field2: _serde::__private228::Option<Vec<u8>> = _serde::__private228::None;
                    while let _serde::__private228::Some(__key) =
                        _serde::de::MapAccess::next_key::<__Field>(&mut __map)?
                    {
                        match __key {
                            __Field::__field0 => {
                                if _serde::__private228::Option::is_some(&__field0) {
                                    return _serde::__private228::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("id"),
                                    );
                                }
                                __field0 = _serde::__private228::Some(_serde::de::MapAccess::next_value::<Vec<u8>>(
                                    &mut __map,
                                )?);
                            }
                            __Field::__field1 => {
                                if _serde::__private228::Option::is_some(&__field1) {
                                    return _serde::__private228::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("parent_id"),
                                    );
                                }
                                __field1 = _serde::__private228::Some(_serde::de::MapAccess::next_value::<
                                    Option<Vec<u8>>,
                                >(&mut __map)?);
                            }
                            __Field::__field2 => {
                                if _serde::__private228::Option::is_some(&__field2) {
                                    return _serde::__private228::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("state"),
                                    );
                                }
                                __field2 = _serde::__private228::Some(_serde::de::MapAccess::next_value::<Vec<u8>>(
                                    &mut __map,
                                )?);
                            }
                            _ => {
                                let _ = _serde::de::MapAccess::next_value::<_serde::de::IgnoredAny>(&mut __map)?;
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::__private228::Some(__field0) => __field0,
                        _serde::__private228::None => _serde::__private228::de::missing_field("id")?,
                    };
                    let __field1 = match __field1 {
                        _serde::__private228::Some(__field1) => __field1,
                        _serde::__private228::None => _serde::__private228::de::missing_field("parent_id")?,
                    };
                    let __field2 = match __field2 {
                        _serde::__private228::Some(__field2) => __field2,
                        _serde::__private228::None => _serde::__private228::de::missing_field("state")?,
                    };
                    _serde::__private228::Ok(PersistedMlsGroupDecrypt {
                        id: __field0,
                        parent_id: __field1,
                        state: __field2,
                    })
                }
            }
            #[doc(hidden)]
            const FIELDS: &[&str] = &["id", "parent_id", "state"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "PersistedMlsGroupDecrypt",
                FIELDS,
                __Visitor {
                    marker: _serde::__private228::PhantomData::<PersistedMlsGroupDecrypt>,
                    lifetime: _serde::__private228::PhantomData,
                },
            )
        }
    }
};
impl traits::Decrypting<'static> for PersistedMlsGroupDecrypt {
    type DecryptedForm = PersistedMlsGroup;
    fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> crate::CryptoKeystoreResult<PersistedMlsGroup> {
        Ok(PersistedMlsGroup {
            parent_id: self
                .parent_id
                .as_ref()
                .map(|parent_id| Ok::<_, crate::CryptoKeystoreError>(parent_id.to_owned()))
                .transpose()?,
            state: <PersistedMlsGroup as traits::DecryptData>::decrypt_data(cipher, &self.id, &self.state)?,
            id: self.id,
        })
    }
}
impl traits::Decryptable<'static> for PersistedMlsGroup {
    type DecryptableFrom = PersistedMlsGroupDecrypt;
}
pub(crate) struct PersistedMlsGroupEncrypt<'a> {
    id: &'a [u8],
    parent_id: Option<Vec<u8>>,
    state: Vec<u8>,
}
#[doc(hidden)]
#[allow(
    non_upper_case_globals,
    unused_attributes,
    unused_qualifications,
    clippy::absolute_paths
)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'a> _serde::Serialize for PersistedMlsGroupEncrypt<'a> {
        fn serialize<__S>(&self, __serializer: __S) -> _serde::__private228::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            let mut __serde_state = _serde::Serializer::serialize_struct(
                __serializer,
                "PersistedMlsGroupEncrypt",
                false as usize + 1 + 1 + 1,
            )?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "id", &self.id)?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "parent_id", &self.parent_id)?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "state", &self.state)?;
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
impl<'a> traits::Encrypting<'a> for PersistedMlsGroup {
    type EncryptedForm = PersistedMlsGroupEncrypt<'a>;
    fn encrypt(&'a self, cipher: &aes_gcm::Aes256Gcm) -> crate::CryptoKeystoreResult<PersistedMlsGroupEncrypt<'a>> {
        Ok(PersistedMlsGroupEncrypt {
            id: &self.id,
            parent_id: self
                .parent_id
                .as_ref()
                .map(|parent_id| Ok::<_, crate::CryptoKeystoreError>(parent_id.to_owned()))
                .transpose()?,
            state: <Self as traits::EncryptData>::encrypt_data(self, cipher, &self.state)?,
        })
    }
}
