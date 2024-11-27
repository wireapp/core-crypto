use super::error::{Error, Result};

/// Unique identifier of a User (human person holding some devices).
/// This contradicts the initial design requirements of this project since it was supposed to be
/// agnostic from Wire.
/// End-to-end Identity re-shuffled that... But we still want to keep this isolated from the rest
/// of the crate that's why this should remain here and be used cautiously, having the context quoted
/// above in mind.
/// For example in `wireapp://LcksJb74Tm6N12cDjFy7lQ!8e6424430d3b28be@wire.com` the [UserId] is `LcksJb74Tm6N12cDjFy7lQ`
#[derive(Debug, Clone, Copy, Eq, PartialEq, derive_more::Deref)]
pub struct UserId<'a>(&'a [u8]);

impl UserId<'_> {
    const USER_ID_DELIMITER: u8 = b':';
}

impl<'a> TryFrom<&'a str> for UserId<'a> {
    type Error = Error;

    fn try_from(client_id: &'a str) -> Result<Self> {
        client_id.as_bytes().try_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for UserId<'a> {
    type Error = Error;

    fn try_from(id: &'a [u8]) -> Result<Self> {
        let found = id
            .splitn(2, |&b| b == Self::USER_ID_DELIMITER)
            .next()
            .ok_or(Error::InvalidUserId)?;
        if found.len() == id.len() {
            return Err(Error::InvalidUserId);
        }
        Ok(Self(found))
    }
}

impl TryFrom<UserId<'_>> for String {
    type Error = Error;

    fn try_from(uid: UserId<'_>) -> Result<Self> {
        Ok(std::str::from_utf8(&uid).map_err(|_| Error::InvalidUserId)?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn should_parse_client_id() {
        let user_id = "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com";
        let user_id = UserId::try_from(user_id).unwrap();
        assert_eq!(user_id, UserId("LcksJb74Tm6N12cDjFy7lQ".as_bytes()));
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn should_fail_when_invalid() {
        let user_id = "LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@world.com";
        let user_id = UserId::try_from(user_id);
        assert!(matches!(user_id.unwrap_err(), Error::InvalidUserId));
    }
}
