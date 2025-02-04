use crate::entity_derive::{ColumnType, IdColumnType, IdTransformation, KeyStoreEntityFlattened};
use quote::quote;

impl quote::ToTokens for KeyStoreEntityFlattened {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let entity_base_impl = self.entity_base_impl();
        let entity_generic_impl = self.entity_generic_impl();
        let entity_wasm_impl = self.entity_wasm_impl();
        let entity_transaction_ext_impl = self.entity_transaction_ext_impl();
        tokens.extend(quote! {
            #entity_base_impl
            #entity_generic_impl
            #entity_wasm_impl
            #entity_transaction_ext_impl
        });
    }
}
impl KeyStoreEntityFlattened {
    fn entity_base_impl(&self) -> proc_macro2::TokenStream {
        let Self {
            collection_name,
            struct_name,
            ..
        } = self;

        // Identical for both wasm and non-wasm
        quote! {
            #[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
            #[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
            impl crate::entities::EntityBase for #struct_name {
                type ConnectionType = crate::connection::KeystoreDatabaseConnection;
                type AutoGeneratedFields = ();
                const COLLECTION_NAME: &'static str = #collection_name;

                fn to_missing_key_err_kind() -> crate::MissingKeyErrorKind {
                    crate::MissingKeyErrorKind::#struct_name
                }

                fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
                    crate::transaction::dynamic_dispatch::Entity::#struct_name(self)
                }
            }
        }
    }

    fn entity_generic_impl(&self) -> proc_macro2::TokenStream {
        let Self {
            collection_name,
            struct_name,
            id,
            id_type,
            id_name,
            id_transformation,
            blob_columns,
            blob_column_names,
            all_columns,
            optional_blob_columns,
            optional_blob_column_names,
            ..
        } = self;

        let string_id_conversion = matches!(id_type, IdColumnType::String).then(|| {
            quote! { let #id: String = id.try_into()?; }
        });

        let id_to_byte_slice = match id_type {
            IdColumnType::String => quote! {self.#id.as_bytes() },
            IdColumnType::Bytes | IdColumnType::Blob => quote! { &self.#id.as_slice() },
        };

        let id_field_find_one = match id_type {
            IdColumnType::String | IdColumnType::Blob => quote! { #id, },
            IdColumnType::Bytes => quote! { #id: id.to_bytes(), },
        };

        let id_slice = match id_type {
            IdColumnType::String => quote! { #id.as_str() },
            IdColumnType::Bytes | IdColumnType::Blob => quote! { #id.as_slice() },
        };

        let id_input_transformed = match id_transformation {
            Some(IdTransformation::Hex) => quote! { id.as_hex_string() },
            Some(IdTransformation::Sha256) => todo!(),
            None => id_slice,
        };

        let destructure_row = match id_transformation {
            Some(IdTransformation::Hex) => quote! { let (rowid, #id): (_, String) = row?; },
            Some(IdTransformation::Sha256) => todo!(),
            None => quote! { let (rowid, #id) = row?; },
        };

        let id_from_transformed = match id_transformation {
            Some(IdTransformation::Hex) => {
                quote! { let #id = <Self as crate::entities::EntityIdStringExt>::id_from_hex(&#id)?; }
            }
            Some(IdTransformation::Sha256) => todo!(),
            None => quote! {},
        };

        let find_all_query = format!("SELECT rowid, {id_name} FROM {collection_name} ");

        let find_one_query = format!("SELECT rowid FROM {collection_name} WHERE {id_name} = ?");

        let count_query = format!("SELECT COUNT(*) FROM {collection_name}");

        quote! {
            #[cfg(not(target_family = "wasm"))]
            #[async_trait::async_trait]
            impl crate::entities::Entity for #struct_name {
                fn id_raw(&self) -> &[u8] {
                    #id_to_byte_slice
                }

                async fn find_all(
                    conn: &mut Self::ConnectionType,
                    params: crate::entities::EntityFindParams,
                ) -> crate::CryptoKeystoreResult<Vec<Self>> {
                    let mut conn = conn.conn().await;
                    let transaction = conn.transaction()?;
                    let query = #find_all_query.to_string() + &params.to_sql();

                    let mut stmt = transaction.prepare_cached(&query)?;
                    let mut rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                    use std::io::Read as _;
                    rows.map(|row| {
                        #destructure_row
                        #id_from_transformed

                        #(
                            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, #collection_name, #blob_column_names, rowid, true)?;
                            let mut #blob_columns = Vec::with_capacity(blob.len());
                            blob.read_to_end(&mut #blob_columns)?;
                            blob.close()?;
                        )*

                        #(
                            let mut #optional_blob_columns = None;
                            if let Ok(mut blob) =
                                transaction.blob_open(rusqlite::DatabaseName::Main, #collection_name, #optional_blob_column_names, rowid, true)
                            {
                                if !blob.is_empty() {
                                    let mut blob_data = Vec::with_capacity(blob.len());
                                    blob.read_to_end(&mut blob_data)?;
                                    #optional_blob_columns.replace(blob_data);
                                }
                                blob.close()?;
                            }
                        )*

                        Ok(Self { #id
                            #(
                            , #all_columns
                            )*
                        })
                    }).collect()
                }

                async fn find_one(
                    conn: &mut Self::ConnectionType,
                    id: &crate::entities::StringEntityId,
                ) -> crate::CryptoKeystoreResult<Option<Self>> {
                    let mut conn = conn.conn().await;
                    let transaction = conn.transaction()?;
                    use rusqlite::OptionalExtension as _;

                   #string_id_conversion

                    let mut rowid: Option<i64> = transaction
                        .query_row(&#find_one_query, [#id_input_transformed], |r| {
                            r.get::<_, i64>(0)
                        })
                        .optional()?;

                    use std::io::Read as _;
                    if let Some(rowid) = rowid.take() {
                        #(
                            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, #collection_name, #blob_column_names, rowid, true)?;
                            let mut #blob_columns = Vec::with_capacity(blob.len());
                            blob.read_to_end(&mut #blob_columns)?;
                            blob.close()?;
                        )*

                        #(
                            let mut #optional_blob_columns = None;
                            if let Ok(mut blob) =
                                transaction.blob_open(rusqlite::DatabaseName::Main, #collection_name, #optional_blob_column_names, rowid, true)
                            {
                                if !blob.is_empty() {
                                    let mut blob_data = Vec::with_capacity(blob.len());
                                    blob.read_to_end(&mut blob_data)?;
                                    #optional_blob_columns.replace(blob_data);
                                }
                                blob.close()?;
                            }
                        )*

                        Ok(Some(Self {
                            #id_field_find_one
                            #(
                                #blob_columns,
                            )*
                            #(
                                #optional_blob_columns,
                            )*
                        }))
                    } else {
                        Ok(None)
                    }
                }

                async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
                    let conn = conn.conn().await;
                    conn.query_row(&#count_query, [], |r| r.get(0)).map_err(Into::into)
                }
            }
        }
    }

    fn entity_wasm_impl(&self) -> proc_macro2::TokenStream {
        let Self {
            collection_name,
            struct_name,
            id,
            id_type,
            blob_columns,
            ..
        } = self;

        let id_to_byte_slice = match id_type {
            IdColumnType::String => quote! {self.#id.as_bytes() },
            IdColumnType::Bytes | IdColumnType::Blob => quote! { self.#id.as_slice() },
        };

        quote! {
            #[cfg(target_family = "wasm")]
            #[async_trait::async_trait(?Send)]
            impl crate::entities::Entity for #struct_name {
                fn id_raw(&self) -> &[u8] {
                    #id_to_byte_slice
                }

                async fn find_all(conn: &mut Self::ConnectionType, params: crate::entities::EntityFindParams) ->  crate::CryptoKeystoreResult<Vec<Self>> {
                    let storage = conn.storage();
                    storage.get_all(#collection_name, Some(params)).await
                }

                async fn find_one(conn: &mut Self::ConnectionType, id: &crate::entities::StringEntityId) ->  crate::CryptoKeystoreResult<Option<Self>> {
                    conn.storage().get(#collection_name, id.as_slice()).await
                }

                async fn count(conn: &mut Self::ConnectionType) ->  crate::CryptoKeystoreResult<usize> {
                    conn.storage().count(#collection_name).await
                }

                fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> crate::CryptoKeystoreResult<()> {
                    use crate::connection::DatabaseConnection as _;
                    #(
                        self.#blob_columns = self.encrypt_data(cipher, self.#blob_columns.as_slice())?;
                        Self::ConnectionType::check_buffer_size(self.#blob_columns.len())?;
                    )*
                    Ok(())
                }

                fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> crate::CryptoKeystoreResult<()> {
                    #(
                        self.#blob_columns = self.decrypt_data(cipher, self.#blob_columns.as_slice())?;
                    )*
                    Ok(())
                }
            }
        }
    }

    fn entity_transaction_ext_impl(&self) -> proc_macro2::TokenStream {
        let Self {
            collection_name,
            struct_name,
            id,
            id_name,
            all_columns,
            all_column_names,
            blob_columns,
            blob_column_names,
            optional_blob_columns,
            optional_blob_column_names,
            id_transformation,
            no_upsert,
            id_type,
            ..
        } = self;

        let upsert_pairs: Vec<_> = all_column_names
            .iter()
            .map(|col| format! { "{col} = excluded.{col}"})
            .collect();
        let upsert_postfix = (!no_upsert)
            // UPSERT (ON CONFLICT DO UPDATE) with RETURNING to get the rowid
            .then(|| format!(" ON CONFLICT({id_name}) DO UPDATE SET {}", upsert_pairs.join(", ")))
            .unwrap_or_default();

        let column_list = all_columns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        let import_id_string_ext = match id_transformation {
            Some(IdTransformation::Hex) => quote! { use crate::entities::EntityIdStringExt as _; },
            Some(IdTransformation::Sha256) => todo!(),
            None => quote! {},
        };

        let upsert_query = format!(
            "INSERT INTO {collection_name} ({id_name}, {column_list}) VALUES (?{}){upsert_postfix} RETURNING rowid",
            ", ?".repeat(self.all_columns.len()),
        );

        let self_id_transformed = match id_transformation {
            Some(IdTransformation::Hex) => quote! { self.id_hex() },
            Some(IdTransformation::Sha256) => todo!(),
            None => quote! { self.#id },
        };

        let delete_query = format!("DELETE FROM {collection_name} WHERE {id_name} = ?");

        let id_slice_delete = match id_type {
            IdColumnType::String => quote! { id.try_as_str()? },
            IdColumnType::Bytes | IdColumnType::Blob => quote! { id.as_slice() },
        };

        let id_input_transformed_delete = match id_transformation {
            Some(IdTransformation::Hex) => quote! { id.as_hex_string() },
            Some(IdTransformation::Sha256) => todo!(),
            None => id_slice_delete,
        };

        quote! {
            #[cfg(target_family = "wasm")]
            #[async_trait::async_trait(?Send)]
            impl crate::entities::EntityTransactionExt for #struct_name {}

            #[cfg(not(target_family = "wasm"))]
            #[async_trait::async_trait]
            impl crate::entities::EntityTransactionExt for #struct_name {
                async fn save(&self, transaction: &crate::connection::TransactionWrapper<'_>) -> crate::CryptoKeystoreResult<()> {
                    use crate::entities::EntityBase as _;
                    use rusqlite::ToSql as _;
                    use crate::connection::DatabaseConnection as _;

                    #(
                        crate::connection::KeystoreDatabaseConnection::check_buffer_size(self.#blob_columns.len())?;
                    )*
                    #(
                      crate::connection::KeystoreDatabaseConnection::check_buffer_size(
                            self.#optional_blob_columns.as_ref().map(|v| v.len()).unwrap_or_default()
                      )?;
                    )*

                    #import_id_string_ext

                    let sql = #upsert_query;

                    let rowid_result: Result<i64, rusqlite::Error> =
                        transaction.query_row(&sql, [
                        #self_id_transformed.to_sql()?
                        #(
                            ,
                            rusqlite::blob::ZeroBlob(self.#blob_columns.len() as i32).to_sql()?
                        )*
                        #(
                            ,
                            rusqlite::blob::ZeroBlob(self.#optional_blob_columns.as_ref().map(|v| v.len() as i32).unwrap_or_default()).to_sql()?
                        )*
                    ], |r| r.get(0));

                    use std::io::Write as _;
                    match rowid_result {
                        Ok(rowid) => {
                            #(
                                let mut blob = transaction.blob_open(
                                    rusqlite::DatabaseName::Main,
                                    #collection_name,
                                    #blob_column_names,
                                    rowid,
                                    false,
                                )?;

                                blob.write_all(&self.#blob_columns)?;
                                blob.close()?;
                            )*

                            #(
                                let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, #collection_name, #optional_blob_column_names, rowid, false)?;
                                if let Some(#optional_blob_columns) = self.#optional_blob_columns.as_ref() {
                                    blob.write_all(#optional_blob_columns)?;
                                }
                                blob.close()?;
                            )*

                            Ok(())
                        }
                        Err(rusqlite::Error::SqliteFailure(e, _)) if e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE => {
                            Err(crate::CryptoKeystoreError::AlreadyExists)
                        }
                        Err(e) => Err(e.into()),
                    }
                }

                async fn delete_fail_on_missing_id(
                    transaction: &crate::connection::TransactionWrapper<'_>,
                    id: crate::entities::StringEntityId<'_>,
                ) -> crate::CryptoKeystoreResult<()> {
                    use crate::entities::EntityBase as _;
                    let deleted = transaction.execute(&#delete_query, [#id_input_transformed_delete])?;

                    if deleted > 0 {
                        Ok(())
                    } else {
                        Err(Self::to_missing_key_err_kind().into())
                    }
                }
            }
        }
    }
}
