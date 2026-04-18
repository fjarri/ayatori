#![no_std]
// We need to write node functions matching certain signatures,
// and in some tests their signatures are too restricitve for the contents.
#![allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
// A lot of single character names in tests.
#![allow(clippy::similar_names)]

extern crate alloc;

mod distributed_rng;
mod echo_broadcast;
mod evidence_generation;
mod logic_fork;
mod messages;
mod nested_protocol;
mod secret_reveal;
