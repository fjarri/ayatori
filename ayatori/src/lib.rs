#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod entities;
mod error;
mod execution;
mod flat_representation;
mod graph_representation;
mod traits;

pub mod protocol_author_api;
pub mod protocol_user_api;

#[cfg(feature = "dev")]
pub mod dev;
