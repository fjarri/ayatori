use alloc::{collections::BTreeSet, vec::Vec};

use ayatori::protocol_author_api::*;

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
struct Share<SP: SessionParameters> {
    value: u64,
    threshold: usize,
    share_id: SP::Verifier,
}

impl<SP: SessionParameters> Share<SP> {
    fn new(value: u64, threshold: usize, share_id: &SP::Verifier) -> Self {
        Self {
            value,
            threshold,
            share_id: share_id.clone(),
        }
    }

    fn assemble(shares: &[Self]) -> Option<u64> {
        let share_ids = shares.iter().map(|share| &share.share_id).collect::<BTreeSet<_>>();
        if share_ids.len() < shares[0].threshold {
            return None;
        }
        Some(shares[0].value)
    }
}

#[derive(Debug)]
pub struct TestProtocol;

fn make_share<SP: SessionParameters>(id: &SP::Verifier, args: &Args<SP>) -> Result<Share<SP>, UnattributableError> {
    let value = args.get::<u64>("value")?;
    let threshold = args.get::<usize>("threshold")?;
    Ok(Share::new(*value, *threshold, id))
}

fn make_echo<SP: SessionParameters>(args: &Args<SP>) -> Result<Share<SP>, UnattributableError> {
    let share_map = args.get_map::<Share<SP>>("share")?;
    let sender = args.get::<SP::Verifier>("sender")?;
    let share = share_map.get(sender).unwrap();
    Ok((*share).clone())
}

fn gen_output<SP: SessionParameters>(args: &Args<SP>) -> Result<u64, UnattributableError> {
    let echos = args.get_map::<Share<SP>>("echos")?;
    let echos = echos.values().cloned().cloned().collect::<Vec<_>>();
    Ok(Share::assemble(&echos).unwrap())
}

#[derive(Debug, Clone)]
pub enum PrivateData {
    Sender { value: u64 },
    Receiver,
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for TestProtocol {
    type PrivateData = PrivateData;
    type SharedData = BuildData<SP>;
    type Output = u64;

    fn make_private_inputs(private_data: &Self::PrivateData) -> PrivateInputs {
        match private_data {
            PrivateData::Receiver => PrivateInputs::new(),
            PrivateData::Sender { value } => PrivateInputs::new().input("to_broadcast", *value),
        }
    }

    fn make_public_inputs(_shared_data: &Self::SharedData) -> PublicInputs {
        PublicInputs::new()
    }

    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.clone()
    }

    fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier> {
        shared_data.all_parties.clone()
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub struct BuildData<SP: SessionParameters> {
    sender: SP::Verifier,
    all_parties: BTreeSet<SP::Verifier>,
    max_faulty_parties: usize,
}

impl<SP: SessionParameters> ComposableProtocol<SP> for TestProtocol {
    type BuildData = BuildData<SP>;
    type OutputNode = Node<ComputeScalar<SP>>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new().input("to_broadcast")
    }

    fn build(
        party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        let message_share = ProtocolMessage::new::<Share<SP>>("share");
        let message_echo = ProtocolMessage::new::<Share<SP>>("echo");
        let message_ready = ProtocolMessage::new::<()>("ready");

        let to_broadcast = inputs.get("to_broadcast")?;

        let n = build_data.all_parties.len();
        let f = build_data.max_faulty_parties;
        let ids = build_data.all_parties.iter().cloned().collect::<Vec<_>>();

        let share_received_scalar = if &build_data.sender == party_build_data.id() {
            let share_threshold = n - 2 * f;
            let threshold = constant("threshold", share_threshold);
            let shares = compute_mapping(
                "shares",
                make_share,
                &[("value", (to_broadcast).into()), ("threshold", (&threshold).into())],
            );

            let share_sent = direct_message(&message_share, &shares);
            // TODO: this should be a "trigger" node since we don't care about the values
            // TODO: what should be the threshold here?
            let all_shares_sent = collect(&share_sent, &PartyGroup::new(&ids));

            let share_received = receive(&message_share);

            let sender_party = PartyGroup::new(core::slice::from_ref(&build_data.sender));
            collect(&share_received, &sender_party).with_dependency(&all_shares_sent)
        } else {
            let share_received = receive(&message_share);

            let sender_party = PartyGroup::new(core::slice::from_ref(&build_data.sender));
            collect(&share_received, &sender_party)
        };

        let sender = constant("sender", build_data.sender.clone());
        let echo = compute_scalar(
            "echo",
            make_echo,
            &[("sender", (&sender).into()), ("share", (&share_received_scalar).into())],
        );
        let echo_sent = broadcast(&message_echo, &echo);
        let echo_received = receive(&message_echo);

        // TODO: can this be relaxed? The algorithm in the paper only asks to send and echo when we received a share.
        // Can we proceed if only a few echos were sent?
        // Seems like the "0" threshold would be applicable here, but it creates problems
        // since the action of collecting does not find any values in the storage.
        // The "0" threshold basically means "we don't care if these were sent or not, just add the node to the tree"
        let all_echos_sent = collect(&echo_sent, &PartyGroup::new(&ids));

        let all_echos_received = collect_into(
            "enough_echos_for_ready",
            &echo_received,
            &PartyGroup::new_threshold(&ids, n - f),
        )
        .with_dependency(&all_echos_sent);

        let ready_received = receive(&message_ready);
        let some_ready_received = collect(&ready_received, &PartyGroup::new_threshold(&ids, f + 1));

        let ready_trigger = merge_scalars(&all_echos_received, &some_ready_received);
        let ready = constant("ready", ());
        let ready_sent = broadcast(&message_ready, &ready).with_dependency(&ready_trigger);

        let all_ready_received = collect(&ready_received, &PartyGroup::new_threshold(&ids, 2 * f + 1));
        let enough_echos_received = collect_into(
            "enough_echos_for_decode",
            &echo_received,
            &PartyGroup::new_threshold(&ids, n - 2 * f),
        );

        // TODO: same as above, collect(ready_sent) can have a 0 threshold.
        let output = compute_scalar("output", gen_output, &[("echos", (&enough_echos_received).into())])
            .with_dependency(&all_ready_received)
            .with_dependency(&collect(&ready_sent, &PartyGroup::new(&ids)));

        Ok(output)
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

    use super::{BuildData, PrivateData, TestProtocol};

    type SP = TestSessionParams<BinaryFormat, ChaCha8Rng>;

    #[test]
    fn happy_path() {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();

        let build_data = BuildData {
            all_parties: ids.iter().cloned().collect(),
            sender: ids[0],
            max_faulty_parties: 1,
        };

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng).unwrap();

        let sessions = signers
            .into_iter()
            .map(|signer| {
                let private_data = if signer.verifying_key() == ids[0] {
                    PrivateData::Sender { value: 111 }
                } else {
                    PrivateData::Receiver
                };
                Session::<SP, TestProtocol>::new(session_id.clone(), signer, &private_data, &build_data).unwrap()
            })
            .collect::<Vec<_>>();
        let results = run_sessions_sync(&mut rng, sessions).unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }
}
