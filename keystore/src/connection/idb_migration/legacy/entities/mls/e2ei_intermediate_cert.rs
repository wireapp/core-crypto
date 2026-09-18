//! This module contains the expansion of the `#[derive(core_crypto_macros::Entity)]` macro
//! for `E2eiCrl`.
//!
//! That macro doesn't generate the legacy trait impls anymore, so we just expanded them and
//! pasted them in here, then edited as lightly and automatically as possible to make things compile cleanly.

// somehow in the macro expansions some unused braces get generated and it's not worth
// fixing them here.
#![allow(unused_braces, renamed_and_removed_lints)]

use zeroize::Zeroize;

use crate::{
    CryptoKeystoreResult,
    connection::idb_migration::legacy::{self, traits::KeyType},
    traits::{BorrowPrimaryKey, PrimaryKey},
};

#[derive(Zeroize)]
#[zeroize(drop)]
#[expect(unreachable_pub)]
pub struct E2eiIntermediateCert {
    // key to identify the CA cert; Using a combination of SKI & AKI extensions concatenated like so is suitable:
    // `SKI[+AKI]`
    pub ski_aki_pair: String,
    pub content: Vec<u8>,
}

impl legacy::traits::EntityBase for E2eiIntermediateCert {
    type ConnectionType = legacy::connection::KeystoreDatabaseConnection;
    const TABLE_NAME: &'static str = "e2ei_intermediate_certs";
}
impl legacy::traits::Entity for E2eiIntermediateCert {
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
impl legacy::traits::EntityGetBorrowed for E2eiIntermediateCert {
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
impl<'a> legacy::traits::EntityDatabaseMutation<'a> for E2eiIntermediateCert {
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
impl<'a> legacy::traits::EntityDeleteBorrowed<'a> for E2eiIntermediateCert {
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
pub(crate) struct E2eiIntermediateCertDecrypt {
    ski_aki_pair: String,
    content: Vec<u8>,
}

impl legacy::traits::Decrypting<'static> for E2eiIntermediateCertDecrypt {
    type DecryptedForm = E2eiIntermediateCert;
    fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> crate::CryptoKeystoreResult<E2eiIntermediateCert> {
        Ok(E2eiIntermediateCert {
            content: <E2eiIntermediateCert as legacy::traits::DecryptData>::decrypt_data(
                cipher,
                &self.ski_aki_pair,
                &self.content,
            )?,
            ski_aki_pair: self.ski_aki_pair,
        })
    }
}
impl legacy::traits::Decryptable<'static> for E2eiIntermediateCert {
    type DecryptableFrom = E2eiIntermediateCertDecrypt;
}

#[derive(serde::Serialize)]
pub(crate) struct E2eiIntermediateCertEncrypt<'a> {
    ski_aki_pair: &'a str,
    content: Vec<u8>,
}

impl<'a> legacy::traits::Encrypting<'a> for E2eiIntermediateCert {
    type EncryptedForm = E2eiIntermediateCertEncrypt<'a>;
    fn encrypt(&'a self, cipher: &aes_gcm::Aes256Gcm) -> crate::CryptoKeystoreResult<E2eiIntermediateCertEncrypt<'a>> {
        Ok(E2eiIntermediateCertEncrypt {
            ski_aki_pair: &self.ski_aki_pair,
            content: <Self as legacy::traits::EncryptData>::encrypt_data(self, cipher, &self.content)?,
        })
    }
}

impl PrimaryKey for E2eiIntermediateCert {
    type PrimaryKey = String;

    fn primary_key(&self) -> Self::PrimaryKey {
        self.ski_aki_pair.clone()
    }
}

impl BorrowPrimaryKey for E2eiIntermediateCert {
    type BorrowedPrimaryKey<'a> = &'a str;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        &self.ski_aki_pair
    }
}

impl E2eiIntermediateCert {
    pub(crate) fn save(&self, tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
        let mut stmt =
            tx.prepare_cached("INSERT OR REPLACE INTO e2ei_intermediate_certs (ski_aki_pair, content) VALUES (?, ?)")?;
        stmt.execute((&self.ski_aki_pair, &self.content))?;
        Ok(())
    }
}
