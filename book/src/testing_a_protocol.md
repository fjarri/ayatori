# Testing a protocol

`ayatori` contains a set of tools for testing protocols, located in the [`dev`](dev) module (activated by the `dev` feature flag).


## Helper entities

[`SessionParameters`](protocol_author_api::SessionParameters) contains a number of associated types describing the signing scheme, hashing, and wire format.
[`dev`](dev) module includes types that can be used there, with all the required traits implemented, along with the [`TestSessionParams`](dev::TestSessionParams) type that uses all of them.


## Session executor

In production sessions will typically be executed in an asynchronous environment (and, of course, on multiple machines), but for tests it is much more convenient to have all of them run synchronously in a single process.
The provided [`run_sessions_sync`](dev::run_sessions_sync) function takes a vector of sessions and runs them to completion, returning the resulting reports.
The messages sessions send to each other are internally shuffled to ensure a more realistic environment and possibly uncover certain logic errors.

Also available is an async executor for `tokio` runtime: [`run_sessions_async`](dev::tokio::run_sessions_async), but it is mainly intended for testing async session runners (such as provided [`tokio::run_session`](protocol_user_api::tokio::run_session) and [`tokio::par_run_session`](protocol_user_api::tokio::par_run_session)) rather than protocols themselves.

This is how we would write a test for the protocol described in [the previous chapter](writing_a_protocol.md), checking that the happy path finished with the expected result (all protocols are successful, the results are equal):
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:happy_path}}
```


## Testing failures

You may have noticed that [`run_sessions_sync`](dev::run_sessions_sync) takes [`Session`](protocol_user_api::Session) objects instead of signers and private/shared data.
This is intentional; the way one would test protocol failures is to instrument the protocol graph for one party changing its behavior in some way (e.g. making it send some invalid value).
This is done by using [`Session::new_with_replacements`](protocol_user_api::Session::new_with_replacements) along with [`Replacement`](dev::Replacement) objects.

[`Replacement`](dev::Replacement) works by finding a node by its slot name and replacing its associated function.
In our protocol we have a possible sender-attributable failure when computing `commitment_correct`; let us test that it actually triggers on an invalid message.

