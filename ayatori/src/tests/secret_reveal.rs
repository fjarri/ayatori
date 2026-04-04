use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use rand_chacha::ChaCha8Rng;
use signature::{
    Keypair,
    rand_core::{CryptoRngCore, SeedableRng},
};

use crate::{
    dev::{BinaryFormat, Replacement, TestSessionParams, TestSigner, run_sessions_sync},
    protocol_author_api::*,
    protocol_user_api::*,
};

const MODULUS: u64 = 0x7fffffff;
const GENERATOR: u64 = 7;

fn modadd(x: u64, y: u64) -> u64 {
    (x + y) % MODULUS
}

fn modsub(x: u64, y: u64) -> u64 {
    (x + MODULUS - y) % MODULUS
}

fn modpow(x: u64, exp: u64) -> u64 {
    let mut base = x;
    let mut result = 1;
    let mut exp = exp;

    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % MODULUS;
        }
        base = base * base % MODULUS;
        exp >>= 1;
    }

    result
}

#[derive(Debug)]
struct TestProtocol;

fn gen_secrets<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    args: &Args<SP>,
) -> Result<BTreeMap<SP::Verifier, u64>, UnattributableError> {
    let all_parties = args.get::<PartyGroup<SP::Verifier>>("all_parties")?;
    let mut secrets = all_parties
        .ids()
        .map(|id| (id.clone(), rng.next_u64() % MODULUS))
        .collect::<BTreeMap<_, _>>();
    let total = secrets.values().sum::<u64>() % MODULUS;
    let id = all_parties.ids().next().unwrap();
    *secrets.get_mut(id).unwrap() = modsub(secrets[id], total);
    Ok(secrets)
}

fn splay_secrets<SP: SessionParameters>(id: &SP::Verifier, args: &Args<SP>) -> Result<u64, UnattributableError> {
    let x_map = args.get::<BTreeMap<SP::Verifier, u64>>("x_map")?;
    Ok(x_map[id])
}

fn gen_dh_secret<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    _id: &SP::Verifier,
    _args: &Args<SP>,
) -> Result<u64, UnattributableError> {
    Ok(rng.next_u64() % MODULUS)
}

fn gen_public<SP: SessionParameters>(_id: &SP::Verifier, args: &Args<SP>) -> Result<u64, UnattributableError> {
    let x = args.get("x")?;
    Ok(modpow(GENERATOR, *x))
}

fn gen_dh_public<SP: SessionParameters>(_id: &SP::Verifier, args: &Args<SP>) -> Result<u64, UnattributableError> {
    let y = args.get("y")?;
    Ok(modpow(GENERATOR, *y))
}

fn encrypt_secret<SP: SessionParameters>(_id: &SP::Verifier, args: &Args<SP>) -> Result<u64, UnattributableError> {
    let x = args.get::<u64>("x")?;
    let y = args.get("y")?;
    let y_cap = args.get("Y")?;
    Ok(modadd(*x, modpow(*y_cap, *y)))
}

fn decrypt_secret<SP: SessionParameters>(_id: &SP::Verifier, args: &Args<SP>) -> Result<u64, UnattributableError> {
    let c_cap = args.get::<u64>("C")?;
    let y = args.get("y")?;
    let y_cap = args.get("Y")?;
    Ok(modsub(*c_cap, modpow(*y_cap, *y)))
}

fn verify_secret<SP: SessionParameters>(
    _id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<(), SenderAttributableErrorWithReveal<SP>> {
    let y = args.get::<u64>("y")?;
    let x_dec = args.get::<u64>("x_dec")?;
    let x_cap = args.get::<u64>("X")?;
    if *x_cap != modpow(GENERATOR, *x_dec) {
        Err(SenderAttributableErrorWithReveal::new(
            "For the decrypted x: g^x != X",
            *y,
        ))
    } else {
        Ok(())
    }
}

fn verify_evidence<SP: SessionParameters>(
    _id: &SP::Verifier,
    args: &Args<SP>,
    associated_data: &AssociatedData<SP>,
) -> Result<EvidenceVerdict, RuntimeError> {
    let y = associated_data.deserialize::<u64>()?; // our secret
    let x_cap = args.get::<u64>("X")?;
    let y_cap_remote = args.get::<u64>("Y_remote")?;
    let y_cap_local = args.get::<u64>("Y")?;

    let c_cap = args.get::<u64>("C")?;

    if modpow(GENERATOR, y) != *y_cap_local {
        return Ok(EvidenceVerdict::invalid("check 1 failed"));
    }

    if *x_cap == modpow(GENERATOR, modsub(*c_cap, modpow(*y_cap_remote, y))) {
        return Ok(EvidenceVerdict::invalid("check 2 failed"));
    }

    Ok(EvidenceVerdict::valid())
}

fn gen_output<SP: SessionParameters>(args: &Args<SP>) -> Result<BTreeMap<SP::Verifier, u64>, UnattributableError> {
    let xs = args.get_map::<u64>("x")?;
    Ok(xs.iter().map(|(k, v)| ((*k).clone(), **v)).collect())
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for TestProtocol {
    type PrivateData = ();
    type SharedData = PartyGroup<SP::Verifier>;
    type Output = BTreeMap<SP::Verifier, u64>;

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
    type BuildData = PartyGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new()
    }

    fn build(
        _party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Node<SP>, RuntimeError> {
        let message_x = ProtocolMessage::new::<u64>("X");
        let message_y = ProtocolMessage::new::<u64>("Y");
        let message_c = ProtocolMessage::new::<u64>("C");
        let all_parties = build_data;

        let all_parties_const = constant("all_parties", all_parties.clone());
        let my_x_map = compute_scalar_with_rng("x_map", gen_secrets, &[("all_parties", &all_parties_const)])?; // {x_i,[]}
        let my_x = compute_mapping("x", splay_secrets, &[("x_map", &my_x_map)])?; // x_i,[]
        let my_y = compute_mapping_with_rng("y", gen_dh_secret, &[])?; // y_i,[]

        let my_x_cap = compute_mapping("X", gen_public, &[("x", &my_x)])?; // X_i,[]
        let my_y_cap = compute_mapping("Y", gen_dh_public, &[("y", &my_y)])?; // Y_i,[]

        let x_cap_sent = send(&message_x, &my_x_cap, all_parties)?;
        let y_cap_sent = send(&message_y, &my_y_cap, all_parties)?;

        let x_cap = receive(&message_x)?; // X_j,[]
        let y_cap = receive(&message_y)?; // Y_j,[]

        let message_y_echo = ProtocolMessage::new::<u64>("Y_echo");
        let y_echo_sent = send(&message_y_echo, &y_cap, all_parties)?;
        let y_echo = receive(&message_y_echo)?; // Y_i,[]

        // for j: C_j,i = x_i,j + Y_j,i^(y_i,j)
        let my_c_cap = compute_mapping("C", encrypt_secret, &[("x", &my_x), ("y", &my_y), ("Y", &y_cap)])?;
        let c_cap_sent = send(&message_c, &my_c_cap, all_parties)?;

        let c_cap = receive(&message_c)?; // C_i,[]
        let x_decrypted = compute_mapping("x_dec", decrypt_secret, &[("C", &c_cap), ("y", &my_y), ("Y", &y_cap)])?;
        let x_verified = compute_mapping_sender_fallible_with_info(
            "x_dec_correct",
            verify_secret,
            &[
                ("y", &my_y),            // y_i,j
                ("x_dec", &x_decrypted), // x_j,i
                ("X", &x_cap),           // X_j,[] (we only need X_j,i)
            ],
            verify_evidence,
            &[
                ("X", &x_cap),        // S_j(X_j,i)
                ("C", &c_cap),        // S_j(C_i,j)
                ("Y_remote", &y_cap), // S_j(Y_j,[])
                // In a real protocol this need to be verified separately on reception
                // (that is, compared to our stored `Y`),
                // and the result made a dependency of the node that decrypts `x`.
                // But for this test it does not matter.
                ("Y", &y_echo), // S_j(Y_i,j) (echoed back to us)
            ],
        )?;

        compute_scalar("output", gen_output, &[("x", &collect(&x_decrypted, all_parties)?)])?.with_dependencies(&[
            &collect(&x_verified, all_parties)?,
            &x_cap_sent,
            &y_cap_sent,
            &y_echo_sent,
            &c_cap_sent,
        ])
    }
}

type SP = TestSessionParams<BinaryFormat>;
type S = Session<SP, TestProtocol>;

#[test]
fn happy_path() {
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

    let x1 = results.reports[&ids[0]].success_ref().unwrap();
    let x2 = results.reports[&ids[1]].success_ref().unwrap();
    let x3 = results.reports[&ids[2]].success_ref().unwrap();

    assert_eq!(modadd(modadd(x1[&ids[0]], x2[&ids[0]]), x3[&ids[0]]), 0);
    assert_eq!(modadd(modadd(x1[&ids[1]], x2[&ids[1]]), x3[&ids[1]]), 0);
    assert_eq!(modadd(modadd(x1[&ids[2]], x2[&ids[2]]), x3[&ids[2]]), 0);
}

#[test]
fn provable_error() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let party_group = PartyGroup::new(&ids);

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng);

    let sessions = signers
        .into_iter()
        .enumerate()
        .map(|(idx, signer)| {
            if idx == 0 {
                let id1 = ids[1];
                let replacement = Replacement::<SP>::compute_mapping(
                    &["C"],
                    move |orig_value: &u64, id, _args: &Args<SP>| {
                        if id == &id1 { Ok(0) } else { Ok(*orig_value) }
                    },
                )
                .unwrap();
                S::new_with_replacements(session_id.clone(), signer, &(), &party_group, &[&replacement]).unwrap()
            } else {
                S::new(session_id.clone(), signer, &(), &party_group).unwrap()
            }
        })
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    assert!(results.reports[&ids[0]].success_ref().is_some());
    assert!(results.reports[&ids[0]].provable_errors.is_empty());

    assert!(results.reports[&ids[1]].is_unfinishable());
    assert!(results.reports[&ids[1]].provable_errors.contains_key(&ids[0]));
    assert!(
        results.reports[&ids[1]].provable_errors[&ids[0]]
            .verify(&party_group)
            .is_ok()
    );

    assert!(results.reports[&ids[2]].success_ref().is_some());
    assert!(results.reports[&ids[2]].provable_errors.is_empty());
}
