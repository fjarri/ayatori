#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    clippy::mod_module_files,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    unused_qualifications,
    missing_debug_implementations
)]

extern crate alloc;

mod entities;
mod errors;
mod execution;
mod flat_representation;
mod graph_representation;
mod traits;

pub mod protocol_author_api;
pub mod protocol_user_api;

#[cfg(any(test, feature = "dev"))]
pub mod dev;

// We need the `dev` module for tests, but it is gated behind a feature
// and cannot be enabled by default for integration tests.
// Hence the integration tests live here.
#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests;
