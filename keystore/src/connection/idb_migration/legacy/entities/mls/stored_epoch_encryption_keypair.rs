//! This module contains the expansion of the `#[derive(core_crypto_macros::Entity)]` macro
//! for `V33StoredEpochEncryptionKeypair`.
//!
//! That macro doesn't generate the legacy trait impls anymore, so we just expanded them and
//! pasted them in here, then edited as lightly and automatically as possible to make things compile cleanly.

// somehow in the macro expansions some unused braces get generated and it's not worth
// fixing them here.
#![allow(unused_braces, renamed_and_removed_lints)]

use crate::{
    connection::idb_migration::legacy::{self, traits::KeyType},
    migrations::V33StoredEpochEncryptionKeypair,
    traits::BorrowPrimaryKey,
};

impl legacy::traits::EntityBase for V33StoredEpochEncryptionKeypair {
    type ConnectionType = legacy::connection::KeystoreDatabaseConnection;
    const TABLE_NAME: &'static str = "mls_epoch_encryption_keypairs";
}
impl legacy::traits::Entity for V33StoredEpochEncryptionKeypair {
    #[allow(
        elided_named_lifetimes,
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
                { <Self as legacy::traits::EntityGetBorrowed>::get_borrowed(conn, key).await };
            #[allow(unreachable_code)]
            __ret
        })
    }
    #[allow(
        elided_named_lifetimes,
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
        elided_named_lifetimes,
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
impl legacy::traits::EntityGetBorrowed for V33StoredEpochEncryptionKeypair {
    #[allow(
        elided_named_lifetimes,
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
        key: Self::BorrowedPrimaryKey<'life1>,
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
                let key = <Self::BorrowedPrimaryKey<'life1> as KeyType>::bytes(&key);
                let key = key.as_ref();
                { conn.storage().get(key).await }
            };
            #[allow(unreachable_code)]
            __ret
        })
    }
}
impl<'a> legacy::traits::EntityDatabaseMutation<'a> for V33StoredEpochEncryptionKeypair {
    type Transaction = legacy::connection::TransactionWrapper<'a>;
    type AutoGeneratedFields = ();
    #[allow(
        elided_named_lifetimes,
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
        elided_named_lifetimes,
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
        elided_named_lifetimes,
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
                { <Self as legacy::traits::EntityDeleteBorrowed>::delete_borrowed(tx, id).await };
            #[allow(unreachable_code)]
            __ret
        })
    }
}
impl<'a> legacy::traits::EntityDeleteBorrowed<'a> for V33StoredEpochEncryptionKeypair {
    #[allow(
        elided_named_lifetimes,
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
        tx: &'life0 <Self as legacy::traits::EntityDatabaseMutation<'a>>::Transaction,
        id: <Self as BorrowPrimaryKey>::BorrowedPrimaryKey<'life1>,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = crate::CryptoKeystoreResult<bool>> + 'async_trait>>
    where
        for<'pk> <Self as BorrowPrimaryKey>::BorrowedPrimaryKey<'pk>: KeyType,
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
                let key = <<Self as BorrowPrimaryKey>::BorrowedPrimaryKey<'life1> as KeyType>::bytes(&id);
                let key = key.as_ref();
                { tx.delete::<Self>(key).await }
            };
            #[allow(unreachable_code)]
            __ret
        })
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct V33StoredEpochEncryptionKeypairDecrypt {
    id: Vec<u8>,
    keypairs: Vec<u8>,
}

impl legacy::traits::Decrypting<'static> for V33StoredEpochEncryptionKeypairDecrypt {
    type DecryptedForm = V33StoredEpochEncryptionKeypair;
    fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> crate::CryptoKeystoreResult<V33StoredEpochEncryptionKeypair> {
        Ok(V33StoredEpochEncryptionKeypair {
            keypairs: <V33StoredEpochEncryptionKeypair as legacy::traits::DecryptData>::decrypt_data(
                cipher,
                &self.id,
                &self.keypairs,
            )?,
            id: self.id,
        })
    }
}
impl legacy::traits::Decryptable<'static> for V33StoredEpochEncryptionKeypair {
    type DecryptableFrom = V33StoredEpochEncryptionKeypairDecrypt;
}

#[derive(serde::Serialize)]
pub(crate) struct V33StoredEpochEncryptionKeypairEncrypt<'a> {
    id: &'a [u8],
    keypairs: Vec<u8>,
}

impl<'a> legacy::traits::Encrypting<'a> for V33StoredEpochEncryptionKeypair {
    type EncryptedForm = V33StoredEpochEncryptionKeypairEncrypt<'a>;
    fn encrypt(
        &'a self,
        cipher: &aes_gcm::Aes256Gcm,
    ) -> crate::CryptoKeystoreResult<V33StoredEpochEncryptionKeypairEncrypt<'a>> {
        Ok(V33StoredEpochEncryptionKeypairEncrypt {
            id: &self.id,
            keypairs: <Self as legacy::traits::EncryptData>::encrypt_data(self, cipher, &self.keypairs)?,
        })
    }
}
