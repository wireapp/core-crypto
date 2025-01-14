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

        let blob_column_names = blob_columns.iter().map(ToString::to_string).collect();
        let all_column_names = all_columns.iter().map(ToString::to_string).collect();

        let id = self.id.name;
        let id_name = id.to_string();
        let id_type = self.id.column_type;

        KeyStoreEntityFlattened {
            struct_name: self.struct_name,
            collection_name: self.collection_name,
            no_upsert: self.no_upsert,
            id,
            id_type,
            id_name,
            all_columns,
            all_column_names,
            blob_columns,
            blob_column_names,
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
    id_type: ColumnType,
    all_columns: Vec<Ident>,
    all_column_names: Vec<String>,
    blob_columns: Vec<Ident>,
    blob_column_names: Vec<String>,
    no_upsert: bool,
}

// Now identical to column, but
// subject to change once more diverse entities are supported.
struct IdColumn {
    name: Ident,
    column_type: ColumnType,
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
}
