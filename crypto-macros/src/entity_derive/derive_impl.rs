use itertools::Itertools as _;
use proc_macro2::TokenStream;
use quote::quote;

use crate::entity_derive::Entity;

impl quote::ToTokens for Entity {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(self.impl_primary_key());
        tokens.extend(self.impl_entity());
        tokens.extend(self.impl_entity_get_borrowed());
        tokens.extend(self.impl_entity_database_mutation());
        tokens.extend(self.impl_entity_delete_borrowed());
    }
}

impl Entity {
    /// `impl PrimaryKey for MyEntity` and `impl BorrowPrimaryKey for MyEntity`
    fn impl_primary_key(&self) -> TokenStream {
        let Self {
            struct_name, id_column, ..
        } = self;

        let primary_key = id_column.column_type.owned();
        let borrowed_primary_key = id_column.column_type.borrowed();
        let pk_field_name = &id_column.field_name;

        quote! {
            impl crate::traits::PrimaryKey for #struct_name {
                type PrimaryKey = #primary_key;

                fn primary_key(&self) -> Self::PrimaryKey {
                    self.#pk_field_name.clone()
                }
            }

            impl crate::traits::BorrowPrimaryKey for #struct_name {
                type BorrowedPrimaryKey = #borrowed_primary_key;

                fn borrow_primary_key(&self) -> &Self::BorrowedPrimaryKey {
                    &self.#pk_field_name
                }
            }
        }
    }

    /// Returns `(sql_statement, fields_params, sql_map_err)` shared by both the async and unified save impls.
    fn sql_insert_parts(&self) -> (String, TokenStream, Option<TokenStream>) {
        let Self {
            upsert,
            collection_name,
            id_column,
            other_columns,
            ..
        } = self;

        let or_replace = upsert.then_some("OR REPLACE").unwrap_or_default();
        let sql_column_names = std::iter::once(id_column.sql_name())
            .chain(other_columns.iter().map(|column| column.sql_name()))
            .join(", ");
        let sql_field_placeholders = std::iter::repeat_n("?", other_columns.len() + 1).join(", ");
        let sql_statement = format!(
            "INSERT {or_replace} INTO {collection_name} ({sql_column_names}) VALUES ({sql_field_placeholders})"
        );
        let fields = std::iter::once(id_column.store_expression())
            .chain(other_columns.iter().map(|column| column.store_expression()))
            .map(|tokens| quote!(#tokens,))
            .collect::<TokenStream>();

        let sql_map_err = (!upsert).then_some(quote! {
            .map_err(|_| crate::CryptoKeystoreError::AlreadyExists(Self::COLLECTION_NAME))
        });

        (sql_statement, fields, sql_map_err)
    }

    /// `impl Entity for MyEntity`
    fn impl_entity(&self) -> TokenStream {
        let Self {
            collection_name,
            struct_name,
            id_column,
            other_columns,
            ..
        } = self;

        let field_assignments = std::iter::once(id_column.field_assignment())
            .chain(other_columns.iter().map(|column| column.field_assignment()));

        quote! {
            impl crate::traits::Entity for #struct_name {
                const COLLECTION_NAME: &'static str = #collection_name;

                fn get(conn: &rusqlite::Connection, key: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<Option<Self>> {
                    <Self as crate::traits::EntityGetBorrowed>::get_borrowed(conn, key)
                }

                fn count(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<u32> {
                    crate::entities::helpers::count_helper::<Self>(conn)
                }

                fn load_all(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<Vec<Self>> {
                    crate::entities::helpers::load_all_helper::<Self, _>(conn, |row| {
                        Ok(Self {
                            #( #field_assignments, )*
                        })
                    })
                }
            }
        }
    }

    /// `impl EntityGetBorrowed for MyEntity`
    fn impl_entity_get_borrowed(&self) -> TokenStream {
        let Self {
            struct_name,
            id_column,
            other_columns,
            ..
        } = self;

        let pk_column_name = id_column
            .column_name
            .clone()
            .unwrap_or_else(|| id_column.field_name.to_string());

        let field_assignments = std::iter::once(id_column.field_assignment())
            .chain(other_columns.iter().map(|column| column.field_assignment()));

        quote! {
            impl crate::traits::EntityGetBorrowed for #struct_name {
                fn get_borrowed(conn: &rusqlite::Connection, key: &Self::BorrowedPrimaryKey)
                    -> crate::CryptoKeystoreResult<Option<Self>>
                where
                    for<'pk> &'pk Self::BorrowedPrimaryKey: crate::traits::KeyType,
                {
                    let key = <&Self::BorrowedPrimaryKey as crate::traits::KeyType>::bytes(&key);
                    let key = key.as_ref();
                    crate::entities::helpers::get_helper::<Self, _>(conn, #pk_column_name, key, |row| {
                        Ok(Self {
                            #( #field_assignments, )*
                        })
                    })
                }
            }
        }
    }

    /// `impl EntityDatabaseMutation for MyEntity`
    fn impl_entity_database_mutation(&self) -> TokenStream {
        let Self { struct_name, .. } = self;

        let (sql_statement, fields, sql_map_err) = self.sql_insert_parts();

        quote! {
            impl crate::traits::EntityDatabaseMutation for #struct_name {
                type AutoGeneratedFields = ();

                fn save(&self, tx: &rusqlite::Transaction) -> crate::CryptoKeystoreResult<()> {
                    let mut stmt = tx.prepare_cached(#sql_statement)?;
                    stmt.execute(rusqlite::params![#fields])#sql_map_err?;
                    Ok(())
                }

                fn count(tx: &rusqlite::Transaction) -> crate::CryptoKeystoreResult<u32> {
                    crate::entities::helpers::count_helper_tx::<Self>(tx)
                }

                fn delete(tx: &rusqlite::Transaction, id: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<bool> {
                    <Self as crate::traits::EntityDeleteBorrowed>::delete_borrowed(tx, id)
                }
            }
        }
    }

    /// `impl EntityDeleteBorrowed for MyEntity`
    fn impl_entity_delete_borrowed(&self) -> TokenStream {
        let Self {
            struct_name, id_column, ..
        } = self;

        let id_column_name = id_column.sql_name();

        quote! {
            impl crate::traits::EntityDeleteBorrowed for #struct_name {
                fn delete_borrowed(
                    tx: &rusqlite::Transaction,
                    id: &<Self as crate::traits::BorrowPrimaryKey>::BorrowedPrimaryKey,
                ) -> crate::CryptoKeystoreResult<bool>
                where
                    for<'pk> &'pk <Self as crate::traits::BorrowPrimaryKey>::BorrowedPrimaryKey: crate::traits::KeyType,
                {
                    let key = <&<Self as crate::traits::BorrowPrimaryKey>::BorrowedPrimaryKey as crate::traits::KeyType>::bytes(&id);
                    let key = key.as_ref();
                    crate::entities::helpers::delete_helper::<Self>(tx, #id_column_name, key)
                }
            }
        }
    }
}
