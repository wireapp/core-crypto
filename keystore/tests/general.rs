mod common;

#[cfg(test)]
mod tests {
    use super::common::*;

    #[test]
    fn can_create_and_init_store() {
        let store = setup("general");
        teardown(store);
    }

    #[cfg(feature = "ios-wal-compat")]
    #[test]
    fn can_preserve_wal_compat_for_ios() {
        let _store = setup("ios-wal-compat");
    }
}
