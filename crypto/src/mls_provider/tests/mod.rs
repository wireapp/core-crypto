use super::Error;
use crate::EntropySeed;

mod crypto;
mod fixtures;

#[test]
fn entropy_seed_requires_an_exact_length() {
    let expected = EntropySeed::EXPECTED_LEN;

    assert_eq!(
        EntropySeed::try_from_slice(&vec![0xab; expected]).as_deref(),
        Ok(&vec![0xab; expected][..]),
        "a seed of exactly the expected length is accepted verbatim"
    );

    // A seed which is too long must be rejected rather than truncated: silently dropping the
    // tail would leave a caller who gathered more entropy than we consume with no way to know.
    for actual in [0, 1, expected - 1, expected + 1, 2 * expected] {
        assert_eq!(
            EntropySeed::try_from_slice(&vec![0xab; actual]),
            Err(Error::EntropySeedLength { actual, expected }),
            "a seed of {actual} bytes must be rejected"
        );
    }
}
