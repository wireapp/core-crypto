# Testing Guidelines for CoreCrypto

## What to test

Tests are useful for several use cases, most commonly:

- demonstrating that a piece of code is correct
- maintaining behaviors over time and refactoring
- reproducing bugs

### What not to test

Tests which demonstrate correctness of library code are not useful. Don't test the library! The library must test
itself. We assume at all levels of abstraction that underlying library code is correct.

- `keystore` crate tests are responsible for testing the keystore, but not e.g. `sqlite`.
- `crypto` crate tests are responsible for testing `crypto` implementations, but not e.g. the keystore.
- `ffi` crate tests should not duplicate `crypto` crate tests except insofar as the `ffi` crate is changing `crypto`
  crate behavior instead of simply delegating calls.

We are not aiming for 100% code coverage; no test should be written for the sole purpose of exercising every codepath.

### Levels of Abstraction

CoreCrypto uses primarily unit testing in the Cargo sense of tests that have visibility of module-private functions.
From a test-design perspective, we aim to mainly test at two levels:

- proper low-level function/unit tests which demonstrate that a particular function behaves correctly
- high-level scenario tests which tests that the system at a high level behaves properly

When designing a test, it is important to choose the proper level of abstraction. The first level should be rare and
confined to pseudomathematical functions or other simple cases. Scenario tests are more important, both for
demonstrating correct system behavior and to ensure that refactorings don't unnecessarily break the test suite.

### Helpers

We have a `TestContext` struct as well as several ancillary structs which are designed to ease development of scenario
tests. Ensure you are familiar with these before writing a new test.

Tests intended to cover cryptographic operations should use `#[rstest_reuse::apply(all_cred_cipher)]` as their
initializer. This automatically creates several tests running in parallel, each of which is set up with a distinct
ciphersuite. For tests not intended to validate cryptographic operations, this is not usually necessary.

## Tests must assert correct behavior

Test cases are written and named to demonstrate correct behavior. Failures are informative of incorrect behavior.

Never write a test which succeeds by demonstrating bad behavior. Write tests to demonstrate correct behavior, and let
them fail until the behavior is fixed. (Most often the fix will immediately follow the failing test.)

Tests written to reproduce a bug should fail on the old code and the pass with the fix.

## Reducing duplication

Tests sometimes cover a variety of related scenarios. These cases should be written to be able to fail independently,
not as loops within a single test.

This repository uses `rstest` and `rstest_reuse` to facilitate those cases.

```rust
#[rstest]
#[case::zero(0)]
#[case::one(1)] // this case fails without stopping the test; 0 and 2 both succeed
#[case::two(2)]
fn my_test(#[case] value: u32) {
    assert_eq!(value % 2, 0);
}
```

Cases should have names where a meaningful name is possible. For simple coverage of e.g. mathematical functions where no
meaningful name is available, it is OK to leave the cases anonymous.

## Async

Rust's testing harness does not offer native async testing capability. We use `smol` to write async tests.

The normal case for an async test looks like this:

```rust
#[macro_rules_attribute::apply(smol_macros::test)]
async fn my_test() {
    // etc
}
```

This can be combined with `rstest` as follows:

```rust
#[rstest]
#[test_attr(macro_rules_attribute::apply(smol_macros::test))]
#[case(1)]
async fn my_test(#[case] value: u32) {
    assert_eq!(value, 1);
}
```

Occasionally we need a small async bridge for setup or teardown in an otherwise synchronous test. In that case use
`smol::block_on`:

```rust
#[test]
fn my_test() {
    let value = smol::block_on(async { 1 });
    // many lines of synchronous test follow here
}
```

This approach should be rare and limited. Do not use it to enclose the entire test body.

## Helpers

### Exposing private libary code for tests

Sometimes it is desirable to expose private library behavior to the tests. Do not make module-private things
crate-public so that tests can access them. Instead, make a separate helper which is only compiled for tests which is
crate-public:

```rust
/// This is wrong:
pub(crate) fn this_should_be_module_private() {}

/// Instead, write it like this:
fn this_is_module_private() {}

/// Only crate-visible when running tests
#[cfg(test)]
pub(crate) fn this_is_module_private_test() {
    this_is_module_private()
}
```

### Shared test helpers

> [!NOTE]
> This section applies to _shared_ helpers. A helper which exists for the benefit of a single test case should be
> written immediately before that case.

Sometimes it is useful to abstract out shared test helpers. When doing so, those should be separated from the actual
tests:

```rust
#[cfg(test)]
mod test_helpers {
    //! This helpers module doesn't contain any tests

    pub(super) const VALUE: u32 = 1;
}

#[cfg(test)]
mod tests {
    //! this test module contains some number of tests, and can refer to the helper

    use super::test_helpers::VALUE;
}
```

Just as with any helper, shared test helpers accessed from multiple places in the module tree should be written
somewhere near the common root.

Keep helpers as private as their callers allow. A child `tests` module can access its parent's private items directly,
so no particular visibility specifier is required.

## Pinning

Some existing tests wrap their body in `Box::pin(async move { ... }).await`. That's a workaround for tests that
overflowed the stack, not house style, so don't copy it unless your test overflows.
