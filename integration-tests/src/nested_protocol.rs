use alloc::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use ayatori::protocol_author_api::*;

#[derive(Debug)]
struct Protocol2;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Protocol2Message(u64);

fn make_protocol2_value<SP: SessionParameters>(args: &Args<SP>) -> Result<Protocol2Message, UnattributableError> {
    let p2 = args.get::<u64>("p2")?;
    Ok(Protocol2Message(*p2))
}

fn make_protocol2_output<SP: SessionParameters>(args: &Args<SP>) -> Result<u64, UnattributableError> {
    let xs = args.get_map::<Protocol2Message>("x")?;
    Ok(xs.values().map(|message| message.0).sum())
}

impl<SP: SessionParameters> ComposableProtocol<SP> for Protocol2 {
    type OutputNode = Node<ComputeScalar<SP>>;
    type BuildData = ThresholdGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new().input("p2")
    }

    fn build(
        _party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        let message_x = ProtocolMessage::new::<Protocol2Message>("x");

        let all_parties = build_data;
        let p2 = inputs.get("p2")?;

        let my_x = compute_scalar("my_x", make_protocol2_value, &[("p2", p2.into())]);
        let x_broadcasted = broadcast(&message_x, &my_x, all_parties.ids());
        let x = receive(&message_x);
        let all_x = collect(&x, all_parties).with_dependency(&x_broadcasted);

        Ok(compute_scalar(
            "output",
            make_protocol2_output,
            &[("x", (&all_x).into())],
        ))
    }
}

#[derive(Debug)]
pub struct Protocol1;

#[derive(Debug, Clone)]
pub struct Protocol1SharedData<SP: SessionParameters> {
    p1: u64,
    party_group: ThresholdGroup<SP::Verifier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Protocol1Message(u64);

fn make_protocol1_value<SP: SessionParameters>(args: &Args<SP>) -> Result<Protocol1Message, UnattributableError> {
    let p1 = args.get::<u64>("p1")?;
    Ok(Protocol1Message(*p1))
}

fn make_protocol1_output<SP: SessionParameters>(args: &Args<SP>) -> Result<u64, UnattributableError> {
    let xs = args.get_map::<Protocol1Message>("x")?;
    Ok(xs.values().map(|message| message.0).sum())
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for Protocol1 {
    type PrivateData = ();
    type SharedData = Protocol1SharedData<SP>;
    type Output = u64;

    fn make_private_inputs(_private_data: &Self::PrivateData) -> PrivateInputs {
        PrivateInputs::new()
    }

    fn make_public_inputs(shared_data: &Self::SharedData) -> PublicInputs {
        PublicInputs::new().input("p1", shared_data.p1)
    }

    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.party_group.clone()
    }

    fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier> {
        shared_data.party_group.ids().clone()
    }
}

impl<SP: SessionParameters> ComposableProtocol<SP> for Protocol1 {
    type OutputNode = Node<ComputeScalar<SP>>;
    type BuildData = ThresholdGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new().input("p1")
    }

    fn build(
        party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        let message_x = ProtocolMessage::new::<Protocol1Message>("x");

        let all_parties = build_data;
        let p1 = inputs.get("p1")?;

        let my_x = compute_scalar("my_x", make_protocol1_value, &[("p1", p1.into())]);
        let x_broadcasted = broadcast(&message_x, &my_x, all_parties.ids());
        let x = receive(&message_x);
        let all_x = collect(&x, all_parties).with_dependency(&x_broadcasted);

        let p1_sum = compute_scalar("p1_sum", make_protocol1_output, &[("x", (&all_x).into())]);

        let args = ProtocolArgs::new().input("p2", &p1_sum);
        call_protocol::<SP, Protocol2>("protocol2", party_build_data, build_data, args)
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

    use super::{Protocol1, Protocol1SharedData};

    #[test]
    fn happy_path() {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
        let shared_data = Protocol1SharedData {
            p1: 1,
            party_group: ThresholdGroup::new(&ids.iter().cloned().collect()),
        };

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng).unwrap();

        let sessions = signers
            .into_iter()
            .map(|signer| {
                Session::<TestSessionParams<BinaryFormat, ChaCha8Rng>, Protocol1>::new(
                    session_id.clone(),
                    signer,
                    &(),
                    &shared_data,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let _results = run_sessions_sync(&mut rng, sessions).unwrap();
    }
}
