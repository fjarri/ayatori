use alloc::{collections::BTreeMap, format, vec::Vec};

use signature::rand_core::CryptoRngCore;

use crate::{
    entities::{Message, MessageId, UnattributableError},
    execution::{Session, SessionReport, Task, TaskError},
    traits::{ExecutableProtocol, SessionParameters},
};

pub fn run_sessions_sync<SP: SessionParameters, P: ExecutableProtocol<SP>>(
    rng: &mut impl CryptoRngCore,
    sessions: Vec<Session<SP, P>>,
) -> Result<ExecutionResult<SP, P>, UnattributableError> {
    let mut sessions = sessions
        .into_iter()
        .map(|session| (session.verifier().clone(), session))
        .collect::<BTreeMap<_, _>>();
    let mut messages = sessions
        .keys()
        .map(|id| (id.clone(), Vec::<Message<SP>>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut reports = BTreeMap::new();

    while !sessions.is_empty() {
        let mut finished_with_success = Vec::new();
        let mut finished_with_stall = Vec::new();
        let mut task_processed = false;

        for (id, session) in &mut sessions {
            for message in messages
                .get_mut(id)
                .ok_or_else(|| UnattributableError::runtime(format!("{id:?} not found in the map of message queues")))?
                .drain(..)
            {
                let message_id = MessageId::random(rng);
                session.add_message(&message_id, message);
            }

            if let Some(task) = session.make_task()? {
                let task_result = match task {
                    Task::Compute(task) => {
                        let result = task.compute()?;
                        session.add_result(result)
                    }
                    Task::ComputeWithRng(task) => {
                        let result = task.compute(rng)?;
                        session.add_result(result)
                    }
                    Task::Send(task) => {
                        let (message, result) = task.compute()?;
                        let destination = message.destination().clone();
                        messages
                            .get_mut(&destination)
                            .ok_or_else(|| {
                                UnattributableError::runtime(format!("{id:?} not found in the map of message queues"))
                            })?
                            .push(message);
                        session.add_result(result)
                    }
                    Task::FinalizeWithSuccess(token) => {
                        finished_with_success.push((id.clone(), token));
                        Ok(())
                    }
                    Task::FinalizeWithStall(token) => {
                        finished_with_stall.push((id.clone(), token));
                        Ok(())
                    }
                };
                task_processed = true;

                match task_result {
                    Ok(()) => {}
                    Err(TaskError::Unattributable(error)) => return Err(error),
                    Err(TaskError::InvalidMessage(error)) => {
                        return Err(UnattributableError::runtime(format!("Invalid message: {error:?}")));
                    }
                    Err(TaskError::DuplicateMessages(error)) => {
                        return Err(UnattributableError::runtime(format!("Duplicate messages: {error:?}")));
                    }
                }
            }
        }

        if !task_processed {
            return Err(UnattributableError::runtime(
                "Sessions are stuck: there are still active rules, but no tasks are being created",
            ));
        }

        for (id, token) in finished_with_success {
            let session = sessions
                .remove(&id)
                .ok_or_else(|| UnattributableError::runtime("A session for {id:?} was not found"))?;
            let report = session.finalize_with_success(token)?;
            reports.insert(id.clone(), report);
        }

        for (id, token) in finished_with_stall {
            let session = sessions
                .remove(&id)
                .ok_or_else(|| UnattributableError::runtime("A session for {id:?} was not found"))?;
            let report = session.finalize_with_stalled(token);
            reports.insert(id.clone(), report);
        }
    }

    Ok(ExecutionResult { reports })
}

#[derive(Debug)]
pub struct ExecutionResult<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    pub reports: BTreeMap<SP::Verifier, SessionReport<SP, P>>,
}
