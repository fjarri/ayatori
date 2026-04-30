# Introduction

## Round-based protocols

A common way to represent distributed cryptographic protocols is to arrange them in rounds.
During each round, a node sends out some messages, receives messages from other nodes, and makes some checks and calculations, based on which it may halt or continue on to the next round.
For a protocol implementor translating this model to code leads to a number of problems that require writing large amounts of boilerplate and complicated logic.


### Obscure data dependencies

It is not uncommon, for example, for some value to be received in Round 1 and then used in Round 4.
The protocol implementor needs to pass this value through the rounds, which adds noise to the intermediate code.
And when someone is reading the code for Round 4, they may wonder where did that variable come from, and have to search through the whole code of the protocol, or its description in the paper.

It is less complicated in libraries where a protocol is represented as a single function (e.g. [`round-based`](https://crates.io/crates/round-based)).
But these libraries have their own problems --- they cannot provide features necessary for production, like saving/restoring the protocol state, caching out of order messages, or simulating verifiable broadcasts (the latter can be implemented manually in some cases).


### Combining protocols

Occasionally it is necessary to combine several protocols into a single one.
They can be either chained one after the other, or merged in parallel, or perhaps one protocol can be integrated into a larger protocol as a part of it.
Either way, it requires some non-trivial code to do generically.

For a parallel execution, messages from both protocols must be merged together; if the number of rounds differes, empty rounds must be added.
For a sequential execution the switch between the last round of the first protocol and the first round of the second protocol becomes a pain point because a party may receive some messages from the second protocol while it is still processing the last round of the first one.
Embedded execution has the same problem, plus it is impossible to merge its messages with the messages of the outer protocol even if data dependencies allow it.


### One party owning multiple shares of secret data

In some threshold protocols it is useful to allow parties to hold several secret shares, to give them different "power".
Naturally, a protocol implementor can just run several separate sessions of the protocol on the same node, one with its own share, so that no additional code needs to be written.
While that works, it is inefficient - two instances running on the same node do not need to generate ZK proofs for each other, or even sign messages.
But adding checks for that on every level requires a lot of custom work for each specific protocol.


### Message piggybacking

There are sometimes additional service messages that need to be sent beyond what the protocol prescribes.
An example would be when echo-broadcasting is used to simulate verifiable broadcast, or when messages from other nodes need to be signed by one node to allow creating a verifiable evidence of malicious behavior.
Theoretically, these service messages can be sent along with the messages from the next round, but it is not always possible: if it is the last round, a separate echo round is still needed.
Either way, implementing them requires writing additional boilerplate.


### Adapting execution to the context.

Depending on the application, the same protocol may be executed differently at the low level.
If verifiable aborts are not required in a specific application, some messages and proofs may be omitted.
If broadcasting is not supported by the transport layer, broadcasts can be converted into direct messages.
Round-based approach to protocols makes it harder to adjust to such situations without writing custom code.


### Writing tests for verifiable evidence of malicious behavior

If some check fails when a message is received, this message, signed by its sender, and possibly some previous ones from the same sender, can be bundled together to construct a verifiable evidence of malicious behavior.
Anyone can take that blob of data and verify that the guilty party indeed sent contradictory information.

Writing the logic to generate these evidences is a lengthy process.
One needs to specify which messages to include for which error, whether some values need to be echoed (if reproducing the failed check requires messages from all nodes), and then basically write anew a part of the round logic leading to the failed check.


## Protocol graphs

There is a way to avoid the issues described above by choosing a different representation for a protocol.
The main idea behind `ayatori` is that rounds are a low-level detail neither cryptographers nor protocol implementors are really interested in.
The important information are the dependencies between data generated during the protocol (for example, "only send out `y` when `x` is received and `f(x)` did not result in an error").
This is what matters for security proofs from the cryptographers' point of view, and what can be used to split messages into rounds automatically, if desired.

Thus we model a multi-party protocol as a directed acyclic gragh where nodes produce values stored in associated named slots, and edges represent data dependencies. Slots can contain either scalars (opaque values) or mappings of parties to scalars.
