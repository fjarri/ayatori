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
// Explicitly allow that since we don't mind test panicking, and it just makes them more readable
#[allow(clippy::indexing_slicing)]
// We need to write node functions matching certain signatures,
// and in some tests their signatures are too restricitve for the contents.
#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
// A lot of single character names in tests.
#[allow(clippy::similar_names)]
mod tests;
