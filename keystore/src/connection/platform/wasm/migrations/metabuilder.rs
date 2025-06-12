use idb::{
    Database,
    builder::{DatabaseBuilder, ObjectStoreBuilder},
};
use indexmap::IndexMap;

/// Like [`DatabaseBuilder`], but with more flexibility.
///
/// Specifically, [`DatabaseBuilder`] is append-only.
/// This is insufficient for our versioning scheme.
///
/// [`Metabuilder`] is a drop-in replacement of [`DatabaseBuilder`].
pub(super) struct Metabuilder {
    name: String,
    version: Option<u32>,
    object_stores: IndexMap<String, ObjectStoreBuilder>,
}

impl Metabuilder {
    /// Create a new instance of [`Metabuilder`].
    pub(super) fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            version: Default::default(),
            object_stores: Default::default(),
        }
    }

    /// Sets the version of the database.
    pub(super) fn version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }

    /// Adds an object store.
    pub(super) fn add_object_store(mut self, object_store: ObjectStoreBuilder) -> Self {
        let name = object_store.name().to_owned();
        let _previous_object_store_for_name = self.object_stores.insert(name, object_store);
        debug_assert!(
            _previous_object_store_for_name.is_none(),
            "we probably don't want to be overwriting object stores at any point"
        );
        self
    }

    /// Builds the database.
    pub(super) async fn build(self) -> Result<Database, idb::Error> {
        let mut builder = DatabaseBuilder::new(&self.name);
        if let Some(version) = self.version {
            builder = builder.version(version);
        }
        for object_store in self.object_stores.into_values() {
            builder = builder.add_object_store(object_store);
        }
        builder.build().await
    }
}
