use alloc::{collections::BTreeMap, vec::Vec};

use signature::rand_core::CryptoRngCore;

use crate::{
    protocol::{Protocol, SessionParameters},
    session::{Message, Session, Task},
};

pub fn run_sessions_sync<SP: SessionParameters, P: Protocol<SP>>(
    rng: &mut impl CryptoRngCore,
    sessions: Vec<Session<SP, P>>,
) -> BTreeMap<SP::Verifier, P::Output> {
    let mut sessions = sessions
        .into_iter()
        .map(|session| (session.id().clone(), session))
        .collect::<BTreeMap<_, _>>();
    let mut messages = sessions
        .keys()
        .map(|id| (id.clone(), Vec::<Message<SP>>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut results = BTreeMap::new();

    while !sessions.is_empty() {
        let mut finished = Vec::new();

        for (id, session) in sessions.iter_mut() {
            for message in messages.get_mut(id).unwrap().drain(..) {
                session.add_message(message);
            }

            match session.make_task() {
                Some(Task::Compute(task)) => {
                    let result = task.compute();
                    session.add_result(result);
                }
                Some(Task::ComputeWithRng(task)) => {
                    let result = task.compute(rng);
                    session.add_result(result);
                }
                Some(Task::Send(task)) => {
                    let (message, result) = task.compute();
                    let destination = message.destination().clone();
                    messages.get_mut(&destination).unwrap().push(message);
                    session.add_result(result);
                }
                Some(Task::Finalize(task)) => {
                    results.insert(id.clone(), task.value());
                    finished.push(id.clone());
                }
                None => {}
            }
        }

        for id in finished {
            sessions.remove(&id);
        }
    }

    results
}
