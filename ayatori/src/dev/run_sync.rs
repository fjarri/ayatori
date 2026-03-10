use alloc::{collections::BTreeMap, format, vec::Vec};

use signature::rand_core::CryptoRngCore;

use crate::{
    error::LocalError,
    protocol::{ExecutableProtocol, SessionParameters},
    session::{Message, PreprocessingError, Session, SessionReport, Task},
};

pub fn run_sessions_sync<SP: SessionParameters, P: ExecutableProtocol<SP>>(
    rng: &mut impl CryptoRngCore,
    sessions: Vec<Session<SP, P>>,
) -> Result<ExecutionResult<SP, P>, LocalError> {
    let mut sessions = sessions
        .into_iter()
        .map(|session| (session.verifier().clone(), session))
        .collect::<BTreeMap<_, _>>();
    let mut messages = sessions
        .keys()
        .map(|id| (id.clone(), Vec::<Message<SP>>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut results = BTreeMap::new();
    let mut reports = BTreeMap::new();

    while !sessions.is_empty() {
        let mut finished_with_success = Vec::new();
        let mut finished_with_stall = Vec::new();
        let mut task_processed = false;

        for (id, session) in &mut sessions {
            for message in messages
                .get_mut(id)
                .ok_or_else(|| LocalError::new(format!("{id:?} not found in the map of message queues")))?
                .drain(..)
            {
                let message_with_id = message.attach_id(rng);
                let tasks = session.preprocess_message(message_with_id).collect::<Vec<_>>();

                for task in tasks {
                    let result = task.execute()?;
                    match session.add_preprocess_result(result) {
                        Ok(()) => {}
                        Err(PreprocessingError::Local(error)) => return Err(error),
                        // TODO (#40): record this for the final report instead of terminating straight away
                        Err(PreprocessingError::InvalidMessage(error)) => {
                            return Err(LocalError::new(format!("Invalid message: {error:?}")));
                        }
                        Err(PreprocessingError::DuplicateMessages(error)) => {
                            return Err(LocalError::new(format!("Duplicate messages: {error:?}")));
                        }
                    };
                }
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
                    Task::FinalizeWithSuccess(token) => {
                        finished_with_success.push((id.clone(), token));
                    }
                    Task::FinalizeWithStall(token) => {
                        finished_with_stall.push((id.clone(), token));
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

        for (id, token) in finished_with_success {
            let session = sessions
                .remove(&id)
                .ok_or_else(|| LocalError::new("A session for {id:?} was not found"))?;
            let (result, report) = session.finalize_with_success(token)?;
            results.insert(id.clone(), result);
            reports.insert(id.clone(), report);
        }

        for (id, _token) in finished_with_stall {
            let session = sessions
                .remove(&id)
                .ok_or_else(|| LocalError::new("A session for {id:?} was not found"))?;
            let report = session.make_report();
            reports.insert(id.clone(), report);
        }
    }

    Ok(ExecutionResult {
        outputs: results,
        reports,
    })
}

#[derive(Debug)]
pub struct ExecutionResult<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    pub outputs: BTreeMap<SP::Verifier, P::Output>,
    pub reports: BTreeMap<SP::Verifier, SessionReport<SP, P>>,
}
