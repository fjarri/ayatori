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
#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

extern crate alloc;

mod entities;
mod execution;
mod flat_representation;
mod graph_representation;
mod traits;

pub mod protocol_author_api;
pub mod protocol_user_api;

#[cfg(feature = "dev")]
pub mod dev;
