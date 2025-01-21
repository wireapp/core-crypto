mod derive_impl;
mod parse;

use proc_macro2::Ident;

/// Representation of a struct annotated with `#[derive(Entity)]`.
pub(super) struct KeyStoreEntity {
    /// Name of the type to implement the trait on
    struct_name: Ident,
    /// Database table name
    collection_name: String,
    /// The ID column
    id: IdColumn,
    /// All other columns
    columns: Columns,
    /// Whether to fail on inserting conflicting ids instead of using upsert semantics (default: false)
    no_upsert: bool,
}

impl KeyStoreEntity {
    /// Convert Keystore entity to a flattened version that is more verbose but can be used more easily in `quote!()`.
    pub(super) fn flatten(self) -> KeyStoreEntityFlattened {
        let all_columns = self
            .columns
            .0
            .iter()
            .map(|column| column.name.clone())
            .collect::<Vec<_>>();

        let blob_columns = self
            .columns
            .0
            .iter()
            .filter(|column| column.column_type == ColumnType::Bytes)
            .map(|column| column.name.clone())
            .collect::<Vec<_>>();

        let optional_blob_columns = self
            .columns
            .0
            .iter()
            .filter(|column| column.column_type == ColumnType::OptionalBytes)
            .map(|column| column.name.clone())
            .collect::<Vec<_>>();

        let all_column_names = all_columns.iter().map(ToString::to_string).collect();
        let blob_column_names = blob_columns.iter().map(ToString::to_string).collect();
        let optional_blob_column_names = optional_blob_columns.iter().map(ToString::to_string).collect();

        let id = self.id.name;
        let id_name = self.id.column_name.unwrap_or_else(|| id.to_string());
        let id_type = self.id.column_type;

        KeyStoreEntityFlattened {
            struct_name: self.struct_name,
            collection_name: self.collection_name,
            no_upsert: self.no_upsert,
            id,
            id_type,
            id_name,
            id_transformation: self.id.transformation,
            all_columns,
            all_column_names,
            blob_columns,
            blob_column_names,
            optional_blob_columns,
            optional_blob_column_names,
        }
    }
}

/// Less abstract version of [KeyStoreEntity] that has all the fields flattened
/// ready for usage in `quote!()`.
pub(super) struct KeyStoreEntityFlattened {
    struct_name: Ident,
    collection_name: String,
    id: Ident,
    id_name: String,
    id_type: IdColumnType,
    id_transformation: Option<IdTransformation>,
    all_columns: Vec<Ident>,
    all_column_names: Vec<String>,
    blob_columns: Vec<Ident>,
    blob_column_names: Vec<String>,
    optional_blob_columns: Vec<Ident>,
    optional_blob_column_names: Vec<String>,
    no_upsert: bool,
}

enum IdColumnType {
    String,
    Bytes,
}

struct IdColumn {
    name: Ident,
    column_type: IdColumnType,
    /// Only present if it differs from the name
    column_name: Option<String>,
    /// If the ID cannot be stored as-is because of indexing limitations
    transformation: Option<IdTransformation>,
}

enum IdTransformation {
    Hex,
    Sha256,
}

struct Columns(Vec<Column>);

struct Column {
    name: Ident,
    column_type: ColumnType,
}

#[derive(PartialEq, Eq)]
enum ColumnType {
    String,
    Bytes,
    OptionalBytes,
}

#[test]
fn test_parsing() {
    use quote::ToTokens;
    // Example struct to test parsing
    let parsed: KeyStoreEntity = syn::parse_quote! {
        #[derive(Entity)]
        #[entity(collection_name = "mls_groups")]
        pub struct PersistedMlsGroup {
            #[id(hex, column = "id_hex")]
            pub id: Vec<u8>,
            pub state: Vec<u8>,
            pub parent_id: Option<Vec<u8>>,
        }
    };

    // Parse the DeriveInput into KeyStoreEntity
    assert_eq!(parsed.collection_name, "mls_groups");
    assert!(matches!(parsed.id.transformation, Some(IdTransformation::Hex)));
    assert_eq!(parsed.id.column_name, Some("id_hex".to_string()));
    assert_eq!(parsed.columns.0.len(), 2);

    let parsed = parsed.flatten();

    let code = parsed.to_token_stream().to_string();
    // write code to file for testing
    std::fs::write("output.rs", code.to_string()).unwrap();
}
