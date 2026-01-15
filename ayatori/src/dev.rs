use alloc::collections::BTreeMap;

use crate::protocol::{PartyId, Protocol, Tag, Value};
use crate::session::{Session, Task};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestPartyId(u64);

impl TestPartyId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

struct Message<Id> {
    source: Id,
    tag: Tag,
    data: Value,
}

pub fn run_sessions_sync<Id: PartyId, P: Protocol<Id>>(sessions: Vec<Session<Id, P>>) -> BTreeMap<Id, P::Output> {
    let mut sessions = sessions
        .into_iter()
        .map(|session| (session.id().clone(), session))
        .collect::<BTreeMap<_, _>>();
    let mut messages = sessions
        .keys()
        .map(|id| (id.clone(), Vec::<Message<Id>>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut results = BTreeMap::new();

    while !sessions.is_empty() {
        let mut finished = Vec::new();

        for (id, session) in sessions.iter_mut() {
            for message in messages.get_mut(id).unwrap().drain(..) {
                session.add_message(&message.source, &message.tag, message.data);
            }

            match session.make_task() {
                Some(Task::Compute(task)) => {
                    let result = task.compute();
                    session.add_result(result);
                }
                Some(Task::Send(task)) => {
                    let result = task.result();
                    let tag = task.tag().clone();
                    let destination = task.destination().clone();
                    messages.get_mut(&destination).unwrap().push(Message {
                        data: task.data(),
                        tag,
                        source: id.clone(),
                    });
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
