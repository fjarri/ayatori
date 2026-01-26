#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(any(test, feature = "dev"))]
pub mod dev;

mod error;
pub mod protocol;
pub mod session;

// We need the `dev` module for tests, but it is gated behind a feature
// and cannot be enabled by default for integration tests.
// Hence the integration tests live here.
#[cfg(test)]
mod tests;
