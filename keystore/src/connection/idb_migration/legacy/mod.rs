//! Legacy database implementations.
//!
//! We need to keep all this so that it is possible to migrate from any arbitrary
//! legacy IDB database state we can find; at the same time, we don't need or want
//! to adjust the implementation going forward, so testing is of questionable value.

// There's a lot of legacy stuff that just got copied directly without modification.
// There's also a lot of legacy stuff that got copied in based on `cargo export` etc,
// because the macro used to generate the classic entities and now it does not.
// There's also a bunch of stuff which isn't actually used anymore except in tests.
//
// We've preserved the tests because deleting those feels like bad behavior. But given
// that several methods are only now used in tests, sorting out what is or is not
// actually used in these modules is a pain. So we avoid that by deciding we don't care.
#![expect(unused)]

pub(crate) mod connection;
pub(crate) mod entities;
pub(crate) mod traits;
