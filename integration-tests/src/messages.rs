use alloc::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use ayatori::protocol_author_api::*;

#[derive(Debug)]
pub struct TestProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message1<Id>(Id);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message2<Id>(Id, Id);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message3<Id>(Id, Id);

fn make_scalar_value<SP: SessionParameters>(args: &Args<SP>) -> Result<Message1<SP::Verifier>, UnattributableError> {
    Ok(Message1(args.my_id().clone()))
}

fn make_mapping_elem<SP: SessionParameters>(
    id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<Message2<SP::Verifier>, UnattributableError> {
    Ok(Message2(args.my_id().clone(), id.clone()))
}

fn make_mapping_elem_sans_me<SP: SessionParameters>(
    id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<Message3<SP::Verifier>, UnattributableError> {
    Ok(Message3(args.my_id().clone(), id.clone()))
}

fn gen_output<SP: SessionParameters>(args: &Args<SP>) -> Result<(), UnattributableError> {
    let xs = args.get_map::<Message1<SP::Verifier>>("x")?;
    for (id, x) in xs {
        assert_eq!(id, &x.0);
    }

    let ys = args.get_map::<Message2<SP::Verifier>>("y")?;
    for (id, y) in ys {
        assert_eq!(id, &y.0);
        assert_eq!(args.my_id(), &y.1);
    }

    let zs = args.get_map::<Message3<SP::Verifier>>("z")?;
    assert!(!zs.contains_key(args.my_id()));
    for (id, z) in zs {
        assert_eq!(id, &z.0);
        assert_eq!(args.my_id(), &z.1);
    }

    Ok(())
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for TestProtocol {
    type PrivateData = ();
    type SharedData = PartyGroup<SP::Verifier>;
    type Output = ();

    fn make_private_inputs(_private_data: &Self::PrivateData) -> PrivateInputs {
        PrivateInputs::new()
    }

    fn make_public_inputs(_shared_data: &Self::SharedData) -> PublicInputs {
        PublicInputs::new()
    }

    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.clone()
    }

    fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier> {
        shared_data.ids().cloned().collect()
    }
}

impl<SP: SessionParameters> ComposableProtocol<SP> for TestProtocol {
    type OutputNode = Node<ComputeScalar<SP>>;
    type BuildData = PartyGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new()
    }

    fn build(
        party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        let message_x = ProtocolMessage::new::<Message1<SP::Verifier>>("x");
        let message_y = ProtocolMessage::new::<Message2<SP::Verifier>>("y");
        let message_z = ProtocolMessage::new::<Message3<SP::Verifier>>("z");

        let all_parties = build_data;

        let my_x = compute_scalar("my_x", make_scalar_value, &[]);
        let x_broadcasted = broadcast(&message_x, &my_x);
        let x = receive(&message_x);
        let all_x = collect(&x, all_parties).with_dependency(&collect(&x_broadcasted, all_parties));

        let my_y = compute_mapping("my_y", make_mapping_elem, &[]);
        let y_sent = direct_message(&message_y, &my_y);
        let y = receive(&message_y);
        let all_y = collect(&y, all_parties).with_dependency(&collect(&y_sent, all_parties));

        let my_z_group = all_parties.except(party_build_data.id());
        let my_z = compute_mapping("my_z", make_mapping_elem_sans_me, &[]);
        let z_sent = direct_message(&message_z, &my_z);
        let z = receive(&message_z);
        let all_z = collect(&z, &my_z_group).with_dependency(&collect(&z_sent, &my_z_group));

        Ok(compute_scalar(
            "output",
            gen_output,
            &[("x", (&all_x).into()), ("y", (&all_y).into()), ("z", (&all_z).into())],
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use rand_chacha::ChaCha8Rng;

    use ayatori::{
        dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
        protocol_user_api::*,
        signature::{Keypair, rand_core::SeedableRng},
    };

    use super::TestProtocol;

    #[test]
    fn happy_path() {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
        let party_group = PartyGroup::new(&ids);

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng);

        let sessions = signers
            .into_iter()
            .map(|signer| {
                Session::<TestSessionParams<BinaryFormat, ChaCha8Rng>, TestProtocol>::new(
                    session_id.clone(),
                    signer,
                    &(),
                    &party_group,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let _results = run_sessions_sync(&mut rng, sessions).unwrap();
    }
}
