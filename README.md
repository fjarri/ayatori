# Graph-based framework for distributed cryptographic protocols

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![License][license-image]
[![Build Status][build-image]][build-link]
[![Coverage][coverage-image]][coverage-link]


*Rounds? Where we're going, we don't need rounds!*

Most cryptographic papers describe multi-party protocols in terms of rounds.
The main idea of this crate is to treat rounds as a low-level implementation detail the user need not worry about, and instead focus on dependencies between data ("when I receive `x`, calculate and send out `y`").
The crate will bundle the messages internally.

This approach opens up many features that are hard to implement using the round-based formalism.
See [the book](https://publicfields.net/ayatori) for more details.
The goal of the project is to bring the implementation of the protocol close to its description in the paper to simplify audit, and to make sure everything that can be handled automatically (signing messages, preventing denial of service and replay attacks, generating evidence of malicious behavior etc) is done so.

The example below describes a simple protocol where each party generates a random number and sends it out to other parties.
After a party receives all the numbers, it sums them up and returns the result.

Note that some parts of the code are omitted for illustrative purposes;
fully working examples can be found in the [`integration-tests`](https://github.com/fjarri/ayatori/tree/master/integration-tests) crate in the repository.

```rust
# use std::collections::BTreeSet;
# use ayatori::protocol_author_api::*;
#
#[derive(Debug)]
pub struct TestProtocol;

# impl<SP: SessionParameters> ExecutableProtocol<SP> for TestProtocol {
#     type PrivateData = ();
#     type SharedData = PartyGroup<SP::Verifier>;
#     type Output = u64;
#
#     fn make_private_inputs(_private_data: &Self::PrivateData) -> PrivateInputs {
#         PrivateInputs::new()
#     }
#
#     fn make_public_inputs(_shared_data: &Self::SharedData) -> PublicInputs {
#         PublicInputs::new()
#     }
#
#     fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
#         shared_data.clone()
#     }
#
#     fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier> {
#         shared_data.ids().cloned().collect()
#     }
# }
#
impl<SP: SessionParameters> ComposableProtocol<SP> for TestProtocol {
#    type OutputNode = Node<ComputeScalar<SP>>;
#    type BuildData = PartyGroup<SP::Verifier>;
#
#    fn signature() -> ProtocolSignature {
#        ProtocolSignature::new()
#    }
#
    fn build(
        _party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        let message_x = ProtocolMessage::new::<u64>("x");

        let all_parties = build_data;

        let my_x = compute_scalar_with_rng("my_x", |rng, _args| Ok(rng.next_u64() % 10), &[]);
        let x_broadcasted = broadcast(&message_x, &my_x, all_parties);
        let x = receive(&message_x);
        let all_x = collect(&x, all_parties).with_dependency(&x_broadcasted);

        Ok(compute_scalar(
            "output",
            |args| {
                let xs = args.get_map::<u64>("x")?;
                Ok(xs.values().copied().sum::<u64>())
            },
            &[("x", (&all_x).into())],
        ))
    }
}

// A test that simply executes the protocol
// and checks that all the parties output the same value.

# use rand_chacha::ChaCha8Rng;
# use signature::{Keypair, rand_core::SeedableRng};
# use ayatori::{
#     dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
#     protocol_user_api::*,
# };
#
type S = Session<TestSessionParams<BinaryFormat>, TestProtocol>;

let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
let party_group = PartyGroup::new(&ids);

let mut rng = ChaCha8Rng::seed_from_u64(123);
let session_id = SessionId::random(&mut rng);

let sessions = signers
    .into_iter()
    .map(|signer| S::new(session_id.clone(), signer, &(), &party_group).unwrap())
    .collect::<Vec<_>>();
let results = run_sessions_sync(&mut rng, sessions).unwrap();

let value = results.reports[&ids[0]].success_ref().unwrap();
assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
```


[crate-image]: https://img.shields.io/crates/v/ayatori.svg
[crate-link]: https://crates.io/crates/ayatori
[docs-image]: https://docs.rs/ayatori/badge.svg
[docs-link]: https://docs.rs/ayatori/
[license-image]: https://img.shields.io/crates/l/ayatori
[build-image]: https://github.com/fjarri/ayatori/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/fjarri/ayatori/actions/workflows/ci.yml
[coverage-image]: https://codecov.io/gh/fjarri/ayatori/branch/master/graph/badge.svg
[coverage-link]: https://codecov.io/gh/fjarri/ayatori
