#![no_std]
// We need to write node functions matching certain signatures,
// and in some tests their signatures are too restricitve for the contents.
#![allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
// A lot of single character names in tests.
#![allow(clippy::similar_names)]

extern crate alloc;

pub mod distributed_rng;
pub mod echo_broadcast;
pub mod evidence_generation;
pub mod logic_fork;
pub mod messages;
pub mod nested_protocol;
pub mod secret_reveal;
pub mod tokio;
