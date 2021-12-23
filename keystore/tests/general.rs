mod common;

#[cfg(test)]
mod tests {
    use super::common::*;

    #[test]
    fn can_create_and_init_store() {
        let _ = setup("general");

        teardown("general");
    }
}
