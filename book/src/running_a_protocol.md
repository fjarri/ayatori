# Running a protocol

`ayatori` is a sans-IO library, which means the public API leaves the decisions about synchronous/concurrent execution, and about specific transport and concurrency libraries to the user.
Given an [`ExecutableProtocol`](protocol_user_api::ExecutableProtocol) and its public and private data, the user is supposed to create a [`Session`](protocol_user_api::Session) object.
The object then consumes incoming [`Message`](protocol_user_api::Message) objects from other nodes and emits [`Task`](protocol_user_api::Task) objects.
The user runs the encapsulated operation and gives the result back to the session.
This repeats until the session emits a finalization task, or is terminated by the user (e.g. when some timeout expires).

In this chapter we will write a simple async session runner using `tokio` to illustrate the process.
The full executable code can be found in `book-examples/src/session_runner.rs`.


### Session runner

The signature of the runner will be a little overcomplicated because we need to comply to the requirements of [`run_sessions_async`](dev::tokio::run_sessions_async) which we will use to execute multiple sessions concurrently using our runner.
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:signature}}
```
Even though we are returning a `Result`, we are omitting all the error processing code.
Refer to the documentation of specific errors for the details about how are they supposed to be handled.
We are also required to take in a cancellation token, which we will use in the body of the function, but it is not essential to the example.

The rest of the parameters we do need: an RNG, a queue for outgoing messages (`tx`), and a queue for incoming messages (`rx`), and the session we are executing (mutable).

The result is a [`SessionReport`](protocol_user_api::SessionReport) object containing the actual outcome, and the attributable and provable errors registered along the way.

The whole body of the function is an event loop.
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:event_loop}}
```
In it, we will repeatedly perform the following actions:
- Drain all the available tasks and execute them;
- Check if the session is finalizable (if it is, exit the loop);
- Get incoming messages from the channel and pass them to the session.


### Processing tasks

In an inner loop, we will get tasks from the session until there are any.
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_loop}}
```
Depending on the task, we need to perform certain actions.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_deterministic}}
```
A computation task: execute and give the result back to the session.
This corresponds to a computation node in the protocol graph.
Note that it can be offloaded to another `tokio` task, or a thread pool.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_randomized}}
```
This is similar to the computation task above, but this one takes an RNG.
We extract these tasks to their own variant because offloading such tasks to another threads requires forking an RNG, and it is not trivial.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_send}}
```
This tasks requests that the user sends the message in the task.
The destination can be obtained from [`Message::destination()`](protocol_user_api::Message::destination) method.
Note that the destination will be the party's public key; matching it to the address for the transport layer (e.g., an IP address) is the user's responsibility.
We are also pushing to the channel not a [`Message`](protocol_user_api::Message) itself, but a [`MessageOut`](protocol_user_api::tokio::MessageOut) wrapper, because we use the same channel to report non-fatal errors (e.g. malformed messages), as will be illustrated below.

Incorporating the result of a task back into the session may result in a message-attributable error, which we report to the same outgoing channel:
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_result}}
```
The error contains IDs of offending messages which the calling code may use to identify offending parties, if the chosen transport method allows it.
Message IDs are sent with incoming messages, as shown in the next snippet.


### Attempting to finalize

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:try_finalize}}
```
Here we attempt to finalize the session.
Note that the method consumes the session object.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:try_finalize_in_progress}}
```
If the session is in progress, we will receive back the session object.
This means we continue on with the event loop.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:try_finalize_reached_output}}
```
This means that the output slot has been filled.
We can now [`finalize()`](protocol_user_api::ReachedOutputSession::finalize) returning the output, but it is also possible to continue on with the loop, accumulating more information.
This can be important for protocols with threshold conditions, and it is a decision the calling code must make.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:try_finalize_stalled}}
```
This signals that the session cannot possibly reach the result (generally, because some nodes committed malicious actions and were banned, making some collect nodes unreachable), and can thus be finalized.
Again, the calling code can make the decision to continue on with the loop, potentially accumulating more reports of malicious actions of other nodes.


### Receiving messages

When all the available tasks are popped, we stand by waiting for messages (or an external cancellation).
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:get_message}}
```
Again, we are receiving not a [`Message`](protocol_user_api::Message) itself, but a [`MessageIn`](protocol_user_api::tokio::MessageIn) wrapper, which may contain other external commands besides actual messages.

The intended process with message IDs is the following.
When receiving a [`Message`](protocol_user_api::Message), the user generates a random [`MessageId`](protocol_user_api::MessageId) and associates it with the transport address of the sender.
The message ID is passed to the session along with the message itself via [`Session::add_message`](protocol_user_api::Session::add_message).
If some error happens that cannot be attributed to a party, but can be attributed to the message itself (in the simplest case, a malformed message), the message ID is reported in the error.
In other words, the error is escalated to the user, for them to deal with according to the context.
If they maintain a mapping of transport addresses to party IDs, they can ban the offending party.
If the transport layer has its own message authentication machinery, the fault may be provable.
