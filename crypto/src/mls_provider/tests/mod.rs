use rstest::rstest;

use super::Error;
use crate::EntropySeed;

mod crypto;
mod fixtures;

#[test]
fn entropy_seed_accepts_the_exact_length_verbatim() {
    let expected = EntropySeed::EXPECTED_LEN;

    assert_eq!(
        EntropySeed::try_from_slice(&vec![0xab; expected]).as_deref(),
        Ok(&vec![0xab; expected][..]),
        "a seed of exactly the expected length is accepted verbatim"
    );
}

// A seed which is too long must be rejected rather than truncated: silently dropping the
// tail would leave a caller who gathered more entropy than we consume with no way to know.
#[rstest]
#[case::empty(0)]
#[case::one_byte(1)]
#[case::one_byte_short(EntropySeed::EXPECTED_LEN - 1)]
#[case::one_byte_long(EntropySeed::EXPECTED_LEN + 1)]
#[case::twice_the_expected_length(2 * EntropySeed::EXPECTED_LEN)]
fn entropy_seed_requires_an_exact_length(#[case] actual: usize) {
    let expected = EntropySeed::EXPECTED_LEN;
    assert_eq!(
        EntropySeed::try_from_slice(&vec![0xab; actual]),
        Err(Error::EntropySeedLength { actual, expected }),
        "a seed of {actual} bytes must be rejected"
    );
}
