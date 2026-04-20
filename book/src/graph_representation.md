# Graph representation

In this section we will outline the high-level notation for describing protocols.
It closely resembles the notation used in cryptographic papers (sans the round concept) and potentially can be used there.
On the other hand, it directly matches the API used to define protocols in `ayatori` (or at least as close as Rust syntax allows it to).


## Introduction

Before jumping into formalism, let us consider a simple distributed RNG protocol as an example.
In our notation, it would looks like
```ignore
my_x = RNG() % modulus
sent_x = <broadcast>(:x, my_x, P)
x[*] = <receive>(*, :x)
xs = <collect>(x, P)
result = sum(values(xs)) % modulus
    when all_sent
```
Here, `RNG()` is a function returning a random integer, `modulus` is some integer modulus, and `P` is the set of IDs of the protocol participants.
We use angle brackets to denote the built-in operations, distinguishing them from the logic supplied by the user.

In the example above each line defines a **node** which performs some operation, the result(s) of which are stored in a **slot** (the variable to the left of the equation sign).
Slot names are unique in the graph.
The edges of the graph are implicitly defined by slots used as arguments in the following nodes.
The protocol is executed by repeatedly finding a node that has all its arguments available, performing the corresponding operation, and storing the result in the associated slot.
The execution terminates when the output slot is filled (in our case, `result`).

Let us now review the example line by line.

```ignore
my_x = RNG() % modulus
```
is a **scalar computation** node.
It performs some calculation *once* and stores the result in a **scalar slot** named `my_x`, after which the node is removed from the graph.

```ignore
sent_x = <broadcast>(:x, my_x, P)
```
broadcasts the value from the slot `my_x`, marked with the label `:x`, to all of the parties in the set `P` (which in our example includes the party whose execution we are following).
`sent_x` is a scalar slot, and gets filled (the specific value does not matter at the moment, since we do not use the value itself, only the fact of its existence) when the broadcast is finished.

```ignore
x[*] = <receive>(*, :x)
```
declares that we are expecting to receive values labeled as `:x`.
Note that we do not specify here from which parties we expect them; this will be inferred from the following `<collect>` node that takes `x` as the argument.
We are using `*` as a placeholder for a party ID, meaning that we can execute this operation *multiple times* for whatever ID is necessary (but no more than once for any given ID) and save the result (the received message) as an entry to the **mapping slot** `x`.

```ignore
xs = <collect>(x, P)
```
This line declares that the scalar slot `xs` is created when `x` contains entries for every party from `P`.
The value of `xs` will be a mapping `ID -> x[ID]`, where `x[ID]` is the value received from the party `ID`.

Note an important disctinction between a mapping slot, and a scalar slot that contains a mapping.
The former is a **build-time** property, meaning that it affects where the slot can be used in the graph and how it will be treated during the protocol execution (for example, only a mapping slot can be used as an argument to `<collect>`).
The contents of a scalar slot are opaque, so the fact that it contains a mapping does not change the protocol execution; it's a *runtime* property --- only the user-defined functions that take that slot as an argument will need to be aware of that.

At this point it also should be clear why we did not specify the parties from which we expect messages in `<receive>` --- if we need `x` from every party in `P` in `<collect>` it follows that we expect the messages from every party in `P` in `<receive>`.
So specifying that earlier would be redundant.

```ignore
all_sent = <collect>(sent_x, P)
```
Similarly to the previous line, this means that the scalar slot `all_sent` is created when the mapping `sent_x` has entries for each ID in `P`.

```ignore
result = sum(values(xs)) % modulus
    when all_sent
```
When the slot `xs` is created, and all the messages are sent, we can calculate our combined random number.
The `when` part here is a **dependency** --- the values in `all_sent` do not directly participate in the computation (they are empty values anyway), but we require them to be present before the node is processed.
In other words, `result` is not filled until all the messages are sent out.

From the graph perspective, dependencies are equivalent to unused arguments, but separating them provides additional information.
Namely, it declares that they don't need to be considered when only the result of the node's execution is required, and the order of the execution is irrelevant, such as during the verification of a proof of malicious behavior (which executed a part of the graph leading to the failure).


## Nodes and slots

Having seen an example, it is time to take a step back and consider the formal concepts.

The protocol is a directed acyclic graph with one exit node --- the protocol output.
The entry nodes are protocol inputs (either public shared ones, or private and party-specific ones) and expected messages from other parties.

Every node has an associated storage slot where it saves the results of its associated action.
There are two types of slots, scalar and mapping ones.
A scalar slot contains one value, a mapping one contains a map of party IDs to values.

Consequently, there are three types of nodes.
First, scalar nodes which take scalar arguments and produce a scalar result.
These are pretty straightforward: as soon as their arguments become available, they can be processed.

Second, mapping nodes, which take scalar or mapping arguments and produce a mapping result.
This means that the associated action is executed for multiple IDs separately, taking the entries keyed by this ID from its mapping arguments, and storing the result under the same key in its associated slot.
For example, if we have a mapping computation
```ignore
z = f(x, y)
```
where `x` is a scalar slot, and `y` is a mapping slot, `f` will be called multiple times:
```ignore
z[id1] = f(id1, x, y[id1])
z[id2] = f(id2, x, y[id2])
z[id3] = f(id3, x, y[id3])
...
```
The specific set of IDs with which it is called is determined by the **sinks**, the nodes that have party ID sets explicitly associated with them.
The set of IDs required by sinks determines the domain of all upstream mapping nodes.
Collect nodes and outgoing message nodes serve as sinks.

Collect nodes bridge the gap between scalar and mapping nodes, accumulating the entries of a mapping into a scalar.
This can happen when entries with all the required IDs are available, or perhaps some threshold quantity of them.

As mentioned above, collect nodes are sinks, and the set of IDs they require is propagated to the mapping nodes that feed data to them.
For example, using the function above, if we have
```ignore
z = f(x, y)
w = collect(z, P)
```
it indicates that `f` will be called for each ID from `P` (subject to the availability of `x` and the entry with each ID in `y`).

Another possible type of sink are outgoing message nodes (such as `<direct_message>` in the distributed RNG example above).
These also require the set of IDs to be specified explicitly and propagate it to all the mapping nodes that lead to them.

(*Note:* often, the outgoing and incoming messages are symmetric.
That is, we expect to receive a message with some label from the same group of nodes it was sent to.
In this case `<direct_message>` does not need to have the set of IDs specified and can just inherit it from the `<receive>` node, which in turn inherits it from the `<collect>` it feeds into.)


## Protocol failures

Naturally, in the real world there are many things that can go wrong when executing a protocol.
We separate these into attributable and unattributable.

**Unattributable errors** cannot be attributed to the actions of a specific party.
By actions here we mean specifically the actions within the mathematical framework of the protocol, that is sending invalid messages.
In this category, `ayatori` distinguishes runtime errors and spurious errors.

**Runtime errors** are failures caused by bugs in the code or some misconfiguration of the environment.
When one occurs, the user (the code executing the protocol) is expected to terminate the protocol immediately, because at that point the results become unreliable.

**Spurious errors** are failures caused by combined independent actions of multiple nodes.
For example, imagine that multiple nodes are generating elliptic curve scalars to be added together to form a signing key.
If they happen to randomly add up to zero (and the corresponding curve points to the infinity point), discovering that in the course of the protocol is a spurious error.
Of course, normally these errors are extremely improbable, but there is a way to report them.

All errors in scalar computations are considered to be unattributable, and these are the only two failure options.

Mapping computation failures, on the other hand, can be **attributable**.
Normally they are attributable to the ID for which the computation is executed (we call those **sender-attributable**), because the mapping element arguments to that computation originally came from that party.
We assume that if a computation has some collect nodes upstream, the data feeding into those from other parties has been already vetted and did not contribute to the failure.

Sometimes a computation may report a **third party attributable** failure, that is a failure caused by a party other than the one from which the messages came from.
An example of that is echo-broadcasting, where a party A may receive a message from party B containing a signed broadcast from party C.
If party A finds that the signed broadcast it received from C differs from the one B reported, and they are both properly signed, it is a failure attributable to party C.


## Provable failures

If a failure is attributable, in some cases it may be **provable**.
This means that a party can publish a self-contained evidence such that anyone (even not a participant in the original protocol execution) can use that evidence and the publicly available data (specifically, the public shared inputs to the protocol) to prove that a party with the given ID (or someone in control of its signing key, to be precise) created and signed messages that lead to a protocol failure.

Within the graph representation, it is possible to tell exactly if a sender-attributable failure is also provable.
We build a subgraph starting from the arguments of the node and ignoring any dependencies on the way.
We consider the failure provable if:
- None of the computations in the intermediate nodes used an RNG;
- No private protocol inputs are present;
- None of the intermediate nodes is a collect node.

The evidence will then include the corresponding messages from the guilty party's ID, and verifying it will simply be computing the part of the graph leading to the failure and seeing if the failure is reproduced.

Some failures require a **secret reveal**; that is, if the failure is detected, the party who detected it must include some private information to the evidence.
The verification in this case is a little more complicated, since the exit node verifying the evidence is different from the one that originally detects the failure.

Similarly, for third party attributable failures, the protocol must declare an associated evidence verification function that will use whatever arbitrary data is collected at the time of the failure.
In the echo-broadcasting example above that would be two signed messages from party C with different contents.


## Forks and merges

Sometimes it is necessary to conditionally split the protocol execution.
In the round-based approach a common case for this are error rounds.
Sometimes when a scalar computation fails, a party can generate a proof of its own correct behavior, and send it to other parties.
Then it waits for the same proofs from other parties to come back, and the party who did not send one, or sent an incorrect one, is necessarily at fault.
Of course, we do not want to do all this work if no failure was detected.

In the graph representation this is handled by fork and merge nodes.
A **fork node** is a scalar computation that can return one of two possible values, or both of them (so it is *not* a strict boolean branch).
This means that it has two output slots which may or may not receive data (but at least one is guaranteed to be filled):
```ignore
success | error = f(...)
```
Now we can define the correctness proof generation path with `error` as an argument, and it will only be activated if `error` was returned by `f`.

Since the protocol exit is a single node, the diverged paths must be merged back into one.
This is done via a **merge node**:
```ignore
x = <merge>(success, error)
```
The slot `x` will be filled if either `success` or `error` or both are available, and will contain an enum with the corresponding three variants.

The "both" variant is needed in cases where only some threshold of nodes must behave correctly; this way the protocol can both return the intended output, and report the nodes that failed to send the correctness proof.
