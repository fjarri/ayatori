//! An implementation of reliable broadcast as a composable `ayatori` protocol.

#![no_std]

// Wire types in this crate use fixed-size integers which need to be converted to `usize` for internal usage.
// This condition ensures that that a valid object received from a remote party is always considered valid.
//
// Otherwise it would be possible for a 16-bit platform to produce a malicious behavior evidence
// that would not be verifiable by a 32/64-bit platform.
const _ASSERT_USIZE: () = assert!(
    size_of::<usize>() >= 4,
    "This crate requires a platform with a usize of at least 4 bytes (e.g., 32-bit or 64-bit)"
);

extern crate alloc;

mod merkle_tree;
mod protocol;
mod sharding;

pub use protocol::ReliableBroadcast;
