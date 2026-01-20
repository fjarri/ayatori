# Introduction

## Round-based protocols

A common way to represent distributed cryptographic protocols is to arrange them in rounds.
During each round, a node sends out some messages, receives messages from other nodes, makes some checks and calculations, based on which it may halt or continue on to the next round.
For a protocol implementor translating this model to code leads to a number of problems that require writing large amounts of boilerplate and complicated logic.


### Obscure data dependencies

It is not uncommon, for example, for some value to be received in Round 1 and then used in Round 4.
The protocol implementor needs to pass this value through the rounds adding noise to the intermediate code.
And when someone is reading the code for Round 4, they may wonder where did that variable come from, and have to search through the whole code of the protocol, or its description in the paper.

It is less complicated in libraries where a protocol is represented as a single function (e.g. `round-based` in Rust).
But these libraries have their own problems --- they cannot provide features necessary for production, like saving/restoring the protocol state, caching out of order messages, or simulating verifiable broadcasts.


### Combining protocols

Occasionally it is necessary to combine several protocols into a single one.
They can be either chained one after the other (for example, Presigning and Signing joined into InteractiveSigning), or merged in parallel (KeyRefresh and AuxGen).
Either way, it requires some non-trivial code to do generically.


### One party owning multiple shares of secret data

In some threshold protocols it is useful to allow parties to hold several secret shares, to give them different "power".
Naturally, a protocol implementor would just want to run several separate sessions of the protocol on the same node, one with its own share, so that no additional code needs to be written.
While that works, it is inefficient - two instances running on the same node do not need to generate ZK proofs for each other, or even sign messages.
But adding checks for that on every level requires a lot of custom work for each specific protocol.


### Echo broadcast piggybacking

Echo-broadcasting is needed to simulate verifiable broadcast, or to collect signed echo of signed messages necessary to generate a verifiable evidence of malicious behavior.
Theoretically, echos can be sent along with the messages from the next round, but it is not always possible: if it is the last round, a separate echo round is still needed.


### Adjusting execution to the context.

Many protocols require so called "verifiable broadcast" (where every node can be ensured the other nodes received the same broadcast), but most transport layers used in practice don't support it.
In this case it can be emulated by the echo broadcast (or perhaps by some other means), but the protocol writer does not need to worry about that.

Echo broadcast may still be necessary if messages from all nodes are required to prove some node's fault; in this case the system can mark a piece of data to be echo-broadcasted.
If the user does not need faults to be provable, these messages can be omitted.

Finally, the transport layer may not even support broadcasting in general (not uncommon).
In this case the broadcast is emulated by direct messages, transparently to the user.


### Simpler echo round logic

Normally the echo round is a special case in the execution since it has to operate with signed messages unlike all the other rounds who only see the payloads.
With the graph approach it can be expressed in the same terms as the regular rounds and integrated in the general execution flow.


### Writing tests for verifiable evidence of malicious behavior

If some check fails when a message is received, this message, signed by its sender, and possibly some previous ones from the same sender, can be bundled together to construct a verifiable evidence of malicious behavior.
Anyone can take that blob of data and verify that the guilty party indeed sent contradictory information.

Writing the logic to generate these evidences is a lengthy process.
One needs to specify which messages to include for which error, whether some values need to be echo-broadcasted (if reproducing the failed check requires messages from all nodes), and then basically writing anew a part of the round logic leading to the failed check.


### Proving some faults during the echo round.

Since the echo round does not know about the contents of the shared associated data for the session,
it cannot construct evidence for some of the faults (e.g. if a node sent echos for some IDs that do not actually participate in the session).
With the graph approach the ID sets have a special status and can be used in the evidence.


### Threshold echo round logic (can this be resolved with graphs?)

Imagine two nodes sending sets of echo messages that each constitute a quorum, but their intersection doesn't, so we don't have consensus on the broadcasts.


## Protocol graphs

There is a way to avoid these issues by choosing a different representation for a protocol.
The main idea is that rounds are a low-level detail neither cryptographers nor protocol implementors are interested in.
The important information are the dependencies between data generated during the protocol.
This is what matters for security proofs from the cryptographers' point of view, and what can be used to split messages into rounds automatically, if desired.


### Problems to solve

- Signed messages access for echos - special case, or accessible to everyone?
- Subprotocol calls
- Are scalar/maps enough or do we need 2D maps?


### Low-level notation

The "assembly language" is what all the high level syntactic sugar is reduced to.
The data is kept in named slots, which can hold scalars or mappings of ids to scalars.
The executed program is a list of conditions, triggered by data being written in some set of slots - either received, or calculated locally.
The associated action can calculate a new value and save it in a slot, send a value, or terminate the execution.

A single condition can be:
- A. a scalar slot getting a value written
- B. a mapping slot getting a value written in a single entry
- C. a mapping slot reaching some quorum of keys with data

A full conditional expression can have any number of conditions of type A and C, but if conditions of type B are present, they're only activated if all of them correspond to the same ID.
The first type (quorum condition) is only successfully executed once (but it can fail with "not enough data", then it can be executed again when the data is updated).
The second type (singular condition) can be successfully executed multiple times, but only once for each ID.

[There's a choice between more generality (slots can be updated, e.g. in Bracha's protocol when new info comes in), and allowing 2D mappings ((ID, ID) -> VALUE) that can only be written in once (no updates allowed, easier to handle conditions, and no need for update callbacks). Let's stick with a more general representation for now.]

An action can result in a following:
- write a value in a slot
- send a value to an ID
- broadcast a value ot a set of IDs
- return "not enough data"
- fail

[What level makes the choice between direct/broadcast (if broadcast transport is not available)?]
[What level manages signing messages?]
[Do we want to manage encryption, or leave it to the transport?]
[How do we attribute failues? Introduce "vetted" values?]
[Can we construct evidences at this level, or will it have to be a level higher where the actual graph is available?]


### High-level notation

Any protocol can be represented as a sequence of statements
```py
Y <- C(X)
```
that is, "when I have data `X` I can calculate `Y`".
Here `X` can be data previously generated on this node, or received from other nodes.

Note that `X` and `Y` here are not variables but identifiers of data pieces, unique in the protocol.

This is a very crude first approximation, now we will add some detail to it.
First, we will consider what types of variables we can have:
- Scalars
- Concrete mappings (IID -> value), which have all the values from a certain set of IID present (e.g. collected from other nodes)
- Ephemeral mappings, basically a computation parametrized by an IID which will may be called for some IIDs but not for others, depending on which nodes dropped out during the protocol.
- RNG (a special variable that will affect evidence generation)
- Sets of IIDs (or, more, accurately quorums, that is objects that contain the information of the all nodes in the set, whether some subset of nodes is enough, and whether some subset of nodes being banned makes it impossible to reach quorum)
- Labels for sent data, to be used in `receive()`
