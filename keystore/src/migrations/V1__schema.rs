use barrel::{types, Migration, backend::Sqlite};

pub fn migration() -> String {
    let mut m = Migration::new();

    m.create_table("mls_keys", |t| {
        t.add_column("uuid", types::varchar(255).unique(true));
        t.add_column("key", types::binary());
    });

    m.create_table("proteus_prekeys", |t| {
        t.add_column("id", types::integer().unique(true));
        t.add_column("key", types::binary());
    });

    m.make::<Sqlite>()
}
