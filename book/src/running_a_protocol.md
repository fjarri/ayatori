# Running a protocol

`ayatori` is a sans-IO library, which means the public API leaves the decisions about synchronous/concurrent execution, and about specific transport and concurrency libraries to the user.
Given an [`ExecutableProtocol`](protocol_user_api::ExecutableProtocol) and its public and private data, the user is supposed to create a [`Session`](protocol_user_api::Session) object.
The object then consumes incoming [`Message`](protocol_user_api::Message) objects from other nodes and emits [`Task`](protocol_user_api::Task) objects.
The user runs the encapsulated operation and gives the update back to the session.
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
- Get a task from the session;
- Execute the task, producing an update to the session state;
- Apply the update, and depending on the new session state finalize it or continue;
- When there are no more tasks, get an incoming message from the channel and pass it to the session, or store it in `cached_update` if it is an external update, to be applied at the start of the next iteration.

The external updates may be a request to ban a party (for some user-specific reasons), or an update containing the result of attempting to send a message to a remote party (either a success or a failure).


### Processing tasks

In an inner loop, we will get tasks from the session while there are any.
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_loop}}
```
Depending on the task, we need to perform certain actions.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_deterministic}}
```
A deterministic task is something that does not require passing on an RNG.
Note that it can be offloaded to another `tokio` task, or a thread pool.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_randomized}}
```
This is similar to the computation task above, but this one takes an RNG.
We extract these tasks to their own variant because offloading such tasks to another threads requires forking an RNG, and it is not trivial.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_send}}
```
This tasks requests that the user sends the message contained in the task to a remote party.
After the message is sent successfully, or failed to be sent (because the remote party is unavailable), the resulting update must be sent to the incoming channel as [`SessionUpdate`](protocol_user_api::SessionUpdate) variant.

Note that the message destination will be the party's public key; matching it to the address for the transport layer (e.g., an IP address) is the user's responsibility.
We are also pushing to the channel not a [`SendTask`](protocol_user_api::SendTask) itself, but a [`MessageOut`](protocol_user_api::tokio::MessageOut) wrapper, because we use the same channel to report non-fatal errors (e.g. malformed messages), as will be illustrated below.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:task_loop_end}}
```
If there were no tasks, and the cached task was empty, we break the loop and continue on to waiting for external messages.


### Processing the session update

After the task is executed, its result needs to be incorporated back into the session as a [`SessionUpdate`](protocol_user_api::SessionUpdate).
This consumes the session object and may return it back, or finalize the session, depending on the result.
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:with_update}}
```

The most common variant is the result having been successfully stored, and the session is still in progress:
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:with_update_in_progress}}
```

If there was a message-attributable error, we report it to the same outgoing channel:
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:with_update_message_error}}
```
The error contains IDs of offending messages which the calling code may use to identify offending parties, if the chosen transport method allows it.
Message IDs are sent with incoming messages, as will be demonstrated later.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:with_update_reached_output}}
```
This means that the output slot has been filled.
We can now [`finalize()`](protocol_user_api::ReachedOutputSession::finalize) returning the output, but it is also possible to continue on with the loop, accumulating more information.
This can be important for protocols with threshold conditions, and it is a decision the calling code must make.

```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:with_update_unfinishable}}
```
This signals that the session cannot possibly reach the result (generally, because some nodes committed malicious actions and were banned, making some collect nodes unreachable), and thus has to be finalized.


### Receiving messages

When all the available tasks are popped, we stand by waiting for messages (or an external cancellation).
```rust,ignore
{{#include ../../book-examples/src/session_runner.rs:get_message}}
```
Again, we are receiving not a [`Message`](protocol_user_api::Message) itself, but a [`SessionUpdate`](protocol_user_api::SessionUpdate) object, which may contain other external commands besides actual messages.

The intended process with message IDs is the following.
When receiving a [`Message`](protocol_user_api::Message), the user generates a random [`MessageId`](protocol_user_api::MessageId) and associates it with the transport address of the sender.
The message ID is passed to the session along with the message itself via [`Session::add_message`](protocol_user_api::Session::add_message).
If some error happens that cannot be attributed to a party, but can be attributed to the message itself (in the simplest case, a malformed message), the message ID is reported in the error.
In other words, the error is escalated to the user, for them to deal with according to the context.
If they maintain a mapping of transport addresses to party IDs, they can ban the offending party.
If the transport layer has its own message authentication machinery, the fault may be provable.
