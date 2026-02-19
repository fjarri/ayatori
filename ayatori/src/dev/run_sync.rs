use alloc::{collections::BTreeMap, format, vec::Vec};

use signature::rand_core::CryptoRngCore;

use crate::{
    error::LocalError,
    protocol::{ExecutableProtocol, SessionParameters},
    session::{Message, Session, Task},
};

pub fn run_sessions_sync<SP: SessionParameters, P: ExecutableProtocol<SP>>(
    rng: &mut impl CryptoRngCore,
    sessions: Vec<Session<SP, P>>,
) -> Result<BTreeMap<SP::Verifier, P::Output>, LocalError> {
    let mut sessions = sessions
        .into_iter()
        .map(|session| (session.verifier(), session))
        .collect::<BTreeMap<_, _>>();
    let mut messages = sessions
        .keys()
        .map(|id| (id.clone(), Vec::<Message<SP>>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut results = BTreeMap::new();

    while !sessions.is_empty() {
        let mut finished = Vec::new();
        let mut task_processed = false;

        for (id, session) in &mut sessions {
            for message in messages
                .get_mut(id)
                .ok_or_else(|| LocalError::new(format!("{id:?} not found in the map of message queues")))?
                .drain(..)
            {
                let message_with_id = message.attach_id(rng);
                let task = session.preprocess_message(message_with_id);
                let result = task.execute()?;
                session.add_preprocess_result(result)?;
            }

            if let Some(task) = session.make_task()? {
                match task {
                    Task::Compute(task) => {
                        let result = task.compute()?;
                        session.add_result(result)?;
                    }
                    Task::ComputeWithRng(task) => {
                        let result = task.compute(rng)?;
                        session.add_result(result)?;
                    }
                    Task::Send(task) => {
                        let (message, result) = task.compute()?;
                        let destination = message.destination().clone();
                        messages
                            .get_mut(&destination)
                            .ok_or_else(|| LocalError::new(format!("{id:?} not found in the map of message queues")))?
                            .push(message);
                        session.add_result(result)?;
                    }
                    Task::Finalize(task) => {
                        results.insert(id.clone(), task.value()?);
                        finished.push(id.clone());
                    }
                }
                task_processed = true;
            }
        }

        if !task_processed {
            return Err(LocalError::new(
                "Sessions are stuck: there are still active rules, but no tasks are being created",
            ));
        }

        for id in finished {
            sessions.remove(&id);
        }
    }

    Ok(results)
}
