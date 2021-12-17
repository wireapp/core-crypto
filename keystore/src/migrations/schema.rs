use barrel::{types, Migration, backend::Sqlite};

pub fn migration() -> String {
    let mut m = Migration::new();

    m.create_table("mls_keys", |t| {
        t.add_column("uuid", types::string().unique(true));
        t.add_column("key", types::binary());
    });


    m.make::<Sqlite>()
}
