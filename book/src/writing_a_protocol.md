# Writing a protocol

(*Note:* The full executable example for this chapter is located in `book-examples/src/distributed_rng.rs`.
Here we review it in parts.)

Let us build a slightly more sophisticated distributed RNG protocol based on the example from the previous chapter.
We will also add a private and a shared input for illustrative purposes.


## Graph notation

In our notation the protocol looks like
```py
# Private inputs:
# - the nonce modulus `y`
# Public shared inputs:
# - the random share modulus `x`
# - the set of all participants `P`

my_b = RNG() % x # a part of the total random number
my_r = RNG() % y # a random nonce

# We commit to the value `b` using a random nonce `r`.
# To avoid overcomplicating the example, the "commitment" is just an addition.
my_c = my_b + my_r

# Broadcast the commitment
c_broadcasted = <broadcast>(:c, my_c, P)
c[*] = <receive>(*, :c)

all_c = <collect>(c, P)
    when c_broadcasted

# Only after we sent out our commitment and got back all the other commitments,
# we can send the random part and the nonce
b_broadcasted = <broadcast>(:b, my_b, P)
    when all_c
r_broadcasted = <broadcast>(:r, my_r, P)
    when all_c

b[*] = <receive>(*, :b)
r[*] = <receive>(*, :c)

commitment_correct[*] =
    if b[*] + r[*] != c[*]:
        return <sender-attributable error>

all_commitment_correct = <collect>(commitment_correct, P)
    when b_broadcasted, r_broadcasted

all_b = <collect>(b, P)
    when b_broadcasted

result = sum(values(all_b)) % x
    when all_commitment_correct
```


## `ComposableProtocol` implementation

The core of the protocol definition in `ayatori` is an imlementation of [`ComposableProtocol`](protocol_author_api::ComposableProtocol).
This trait defines a protocol that may be included as a subgraph in a larger protocol, but not necessarily executed by itself.

```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:composable}}
```

[`BuildData`](protocol_author_api::ComposableProtocol::BuildData) contains the subset of the public shared data that is necessary to build the protocol graph.
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:composable-build-data}}
```
In our case this is just the set of the protocol participants.

[`OutputNode`](protocol_author_api::ComposableProtocol::OutputNode) declares the type of the exit node of the protocol (that is, the return type of [`ComposableProtocol::build`](protocol_author_api::ComposableProtocol::build)).
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:composable-output-node}}
```
For our protocol it is a scalar computation node.

[`signature()`](protocol_author_api::ComposableProtocol::signature) returns a [`ProtocolSignature`](protocol_author_api::ProtocolSignature) object which is essentially a set of names by which the protocol's inputs will be available during the build.
These are the names you can use to query [`ArgNodes`](protocol_author_api::ArgNodes) to get the node containing the corresponding input.
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:composable-signature}}
```
In this example, we take two inputs: `x` and `y`.
At this point we do not make the distinction between public and private inputs since a [`ComposableProtocol`](protocol_author_api::ComposableProtocol) can be called from some outer protocol and receive some intermediate nodes as arguments.

And finally, [`build()`](protocol_author_api::ComposableProtocol::build) is the method that builds the protocol graph.
It takes the input argument nodes (as [`ArgNodes`](protocol_author_api::ArgNodes)), the shared build data, and the party-specific build data ([`PartyBuildData`](protocol_author_api::PartyBuildData)), and returns the exit node.
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:composable-build}}
```
(The party-specific build data, which for now is just the party ID, is encapsulated in that structure to prevent the user from changing it when calling subprotocols.)

We will now go through the graph building method section by section and match it with the graph notation we provided above.
You will notice that because of Rust's strictly typed nature, very limited reflection capabilities, and lack of some syntactic sugar, some statements will look a little awkward.

First we will get the protocol inputs --- the build data, and the nodes for `x` and `y`.
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-get-inputs}}
```

Now we can create the random number share `b`:
```py
my_b = RNG() % x
```
translates to
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-b}}
```
[`compute_scalar_with_rng`](protocol_author_api::compute_scalar_with_rng) is a scalar computation node constructor.
We pass it a function that will be called when the node is being executed, and the external `x` argument.
Arguments aree associated with names, and these names are used to fetch the actual values of the arguments from the [`Args`](protocol_author_api::Args) object inside the function during execution.
Note that you need to specify the type of the argument (`u32`), and it will be checked in runtime (unfortunately, a compile-time check is currently unavailable, and is impossible without some macro magic).

The `.into()` calls convert the specific argument nodes into [`ComputeScalarArg`](protocol_author_api::ComputeScalarArg) enums, and the final `.into()` converts the list into a [`ComputeScalarArgs`](protocol_author_api::ComputeScalarArgs) enum.
These conversions statically ensure that the arguments have correct node types (since not every node can be an argument to a scalar computation).

The nonce `r` is created in the same way:
```py
my_r = RNG() % y
```
which translates to
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-r}}
```

With these two, we can calculate the commitment `c`:
```py
my_c = my_b + my_r
```
which translates to
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-c}}
```
The calculation of `c` does not need an RNG, so it uses a different constructor, [`compute_scalar`](protocol_author_api::compute_scalar).

Now that we have our `c`, it is time to send it out.
```py
c_broadcasted = <broadcast>(:c, my_c, P)
c[*] = <receive>(*, :c)
```
which translates to
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-send-c}}
```
The first line declares a protocol message --- a format of a piece of data that will be sent to other nodes or received from them.
That includes the message name (which must be unique among other messages, but lives in a separate namespace from slot names) and the message type (which, naturally, must be `serde`-(de)serializable).
The next line broadcasts the value from the node `my_c` using the message format `message_c` to `all_parties`.
And finally, we declare that we also expect to receive messages of the format `message_c`, with them being stored in the mapping node `c`.
The last two lines almost directly correspond to the graph notation.

Before we do anything, we must wait until we receive all the commitments.
```py
all_c = <collect>(c, P)
    when c_broadcasted
```
which translates to
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-collect-c}}
```
Again, the Rust version is pretty much identical to the graph notation.

The dependency on `c_broadcasted` illustrates an important nuance related to the specifics of translating graph notation to actual code.
While it is easy to start thinking of the graph notation as a list of instructions, one must remember that it is *declarative*, not imperative.
In order for the `broadcast()` to be included in the graph, `c_broadcasted` must be used somewhere as an argument or a dependency, otherwise Rust compiler will complain about an unused variable (and rightly so).
Attaching it to `collect()` specifically is a stylistic choice (for this protocol, at least).

After we got all the commitments, we send out `b` and `c`:
```py
b_broadcasted = <broadcast>(:b, my_b, P)
    when all_c
r_broadcasted = <broadcast>(:r, my_r, P)
    when all_c
b[*] = <receive>(*, :b)
r[*] = <receive>(*, :c)
```
which translates to
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-send-b-r}}
```
The statements here have all been discussed previously.

After receiving `b` and `r` for each ID, we can check the corresponding commitment:
```py
commitment_correct[*] =
    if b[*] + r[*] != c[*]:
        return <sender-attributable error>
```
which translates to
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-check-commitment}}
```
When for some ID, `b[ID]`, `r[ID]`, and `c[ID]` are available, the closure will be called with the arguments `b`, `r`, and `c` set to these values.
If the check fails, we return a new [`SenderAttributableError`](protocol_author_api::SenderAttributableError), because the party that sent mismatched values is at fault.

Note that if an error is returned, the result is *not* saved to `commitment_correct`, and therefore the following `collect` will never be able to execute (since it requires elements from all parties).
The execution environment can detect it, and terminate the execution with the corresponding status.

Finally, after all the checks have succeeded, we can calculate and return the result:
```py
all_commitment_correct = <collect>(commitment_correct, P)
    when b_broadcasted, r_broadcasted
all_b = <collect>(b, P)
    when b_broadcasted
result = sum(values(all_b)) % x
    when all_commitment_correct
```
which translates to
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:build-finalize}}
```

An important detail here is the usage of [`Args::get_map`](protocol_author_api::Args::get_map).
Since the argument `b` comes from the node `all_b`, which is a result of `collect()`, its value is not just an opaque value as a computation result would be, but a `BTreeMap<Id, T>`, where `T` must be specified by the user when calling `get_map()`.


## `ExecutableProtocol` implementation

In order for a protocol to be executable in a session, it must also implement [`ExecutableProtocol`](protocol_author_api::ExecutableProtocol).
Where [`ComposableProtocol`](protocol_author_api::ComposableProtocol) declares the protocol's inputs and outputs in terms of graph nodes, [`ExecutableProtocol`](protocol_author_api::ExecutableProtocol) connects them to external types.

First, let us declare the private data type and the logic of decomposing it into input nodes:
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:executable-private-data}}
```

Similarly, we declare the public shared data and its decomposition into input nodes:
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:executable-shared-data}}
```

We also need to provide a way to get the build data from the shared data
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:executable-build-data}}
```
and the set of all participants (for the purpose of filtering incoming messages to prevent denial of service attacks).
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:executable-participants}}
```

Finally, we declare the output type:
```rust,ignore
{{#include ../../book-examples/src/distributed_rng.rs:executable-output}}
```

That is it, the protocol is now ready for execution --- see [the next chapter](running_a_protocol.md) for details.
