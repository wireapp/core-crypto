#![allow(dead_code)]

pub(crate) mod mls;
pub(crate) mod proteus_bench;

use criterion::Criterion;
pub(crate) use mls::*;

// number of criterion sample
pub(crate) const SAMPLE_SIZE: usize = 10;

// number of clients in a group
pub(crate) const GROUP_RANGE: std::ops::Range<usize> = GROUP_MIN..GROUP_MAX;
pub(crate) const GROUP_MAX: usize = 100 + GROUP_MIN + 1;
pub(crate) const GROUP_MIN: usize = 1;
pub(crate) const GROUP_STEP: usize = 20;

// size (in bytes) of application messages
pub(crate) const MSG_RANGE: std::ops::Range<usize> = MSG_MIN..MSG_MAX;
pub(crate) const MSG_MAX: usize = 10_000 + MSG_MIN + 1;
pub(crate) const MSG_MIN: usize = 10;
pub(crate) const MSG_STEP: usize = 2000;

// pending proposal constants
pub(crate) const PENDING_RANGE: std::ops::Range<usize> = PENDING_MIN..PENDING_MAX;
pub(crate) const PENDING_MAX: usize = 100 + PENDING_MIN + 1;
pub(crate) const PENDING_MIN: usize = 1;
pub(crate) const PENDING_STEP: usize = 20;

pub(crate) fn criterion() -> Criterion {
    Criterion::default().sample_size(SAMPLE_SIZE)
}
