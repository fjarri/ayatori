#![no_std]
// We need to write node functions matching certain signatures,
// and in some tests their signatures are too restricitve for the contents.
#![allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
// A lot of single character names in tests.
#![allow(clippy::similar_names, clippy::many_single_char_names)]
// Do not need this for the examples
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

extern crate alloc;

pub mod distributed_rng;
pub mod session_runner;
