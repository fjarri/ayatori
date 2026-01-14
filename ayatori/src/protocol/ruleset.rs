use super::node::*;
use alloc::collections::BTreeSet;
use core::any::Any;
use core::fmt::{self, Display};

use itertools::Itertools;

#[derive(Debug, Clone)]
enum Condition<Id: PartyId> {
    ValueReady { tag: Tag },
    ArrayReady { tag: Tag, group: PartyGroup<Id> },
}

#[derive(Debug)]
enum Action<Id: PartyId, P: Protocol<Id>> {
    ComputeScalar {
        store_in: Tag,
        function: WrappedFunction<Id, P>,
        args: Vec<Tag>,
    },
    Send {
        store_in: Tag,
        send_as: Tag,
        to_send: Tag,
        destination: Id,
    },
    Collect {
        store_in: Tag,
        values: Tag,
    },
}

#[derive(Debug)]
struct Rule<Id: PartyId, P: Protocol<Id>> {
    conditions: Vec<Condition<Id>>,
    action: Action<Id, P>,
}

#[derive(Debug)]
pub struct Ruleset<Id: PartyId, P: Protocol<Id>> {
    rules: Vec<Rule<Id, P>>,
}

impl<Id: PartyId, P: Protocol<Id>> Ruleset<Id, P> {
    pub fn new(output_node: Node<Id, P>) -> Self {
        let mut nodes_to_process = vec![output_node];
        let mut rules = Vec::new();

        let mut nodes_seen = BTreeSet::<usize>::new();

        while !nodes_to_process.is_empty() {
            let node = nodes_to_process.pop().unwrap();

            if nodes_seen.contains(&node.id()) {
                continue;
            }
            nodes_seen.insert(node.id());

            if let TypedNode::Receive { store_in, .. } = node.as_ref() {
                // TODO: we can collect the tags we expect to receive here
                continue;
            }

            let mut conditions = Vec::new();

            for dependency in node.as_ref().dependencies() {
                conditions.push(Condition::ValueReady {
                    tag: dependency.as_ref().store_in().clone(),
                });
                nodes_to_process.push(dependency.get_strong_ref());
            }

            match node.as_ref() {
                TypedNode::ComputeScalar { args, .. } => {
                    for arg in args.iter() {
                        conditions.push(Condition::ValueReady {
                            tag: arg.as_ref().store_in().clone(),
                        });
                        nodes_to_process.push(arg.get_strong_ref());
                    }
                }
                TypedNode::Send { data, .. } => {
                    conditions.push(Condition::ValueReady {
                        tag: data.as_ref().store_in().clone(),
                    });
                    nodes_to_process.push(data.get_strong_ref());
                }
                TypedNode::Collect { values, .. } => {
                    let group = match values.as_ref() {
                        TypedNode::Send { group, .. } => group,
                        TypedNode::Receive { group, .. } => group,
                        _ => panic!(),
                    };

                    conditions.push(Condition::ArrayReady {
                        tag: values.as_ref().store_in().clone(),
                        group: group.clone(),
                    });
                    nodes_to_process.push(values.get_strong_ref());
                }
                TypedNode::Receive { .. } => {}
            }

            let mut actions = Vec::new();

            match node.as_ref() {
                TypedNode::ComputeScalar {
                    store_in,
                    function,
                    args,
                    ..
                } => {
                    actions.push(Action::ComputeScalar {
                        store_in: store_in.clone(),
                        function: function.clone(),
                        args: args.iter().map(|arg| arg.as_ref().store_in().clone()).collect(),
                    });
                }
                TypedNode::Send {
                    store_in,
                    send_as,
                    data,
                    group,
                    ..
                } => {
                    for id in group.ids() {
                        actions.push(Action::Send {
                            store_in: store_in.clone(),
                            send_as: send_as.clone(),
                            to_send: data.as_ref().store_in().clone(),
                            destination: id.clone(),
                        });
                    }
                }
                TypedNode::Collect { store_in, values, .. } => actions.push(Action::Collect {
                    store_in: store_in.clone(),
                    values: values.as_ref().store_in().clone(),
                }),
                TypedNode::Receive { .. } => {}
            }

            for action in actions {
                rules.push(Rule {
                    conditions: conditions.clone(),
                    action,
                });
            }
        }

        Self { rules }
    }
}

impl<Id: PartyId> Display for Condition<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ValueReady { tag } => {
                write!(f, "ready({tag})")
            }
            Self::ArrayReady { tag, group } => {
                write!(f, "all_ready({tag}, {group})")
            }
        }
    }
}

impl<Id: PartyId, P: Protocol<Id>> Display for Action<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ComputeScalar {
                store_in,
                function,
                args,
            } => {
                let joined_args = args.iter().map(|arg| arg.to_string()).join(", ");
                write!(f, "{store_in} = {function}({joined_args})")
            }
            Self::Send {
                store_in,
                send_as,
                to_send,
                destination,
            } => {
                write!(f, "{store_in} = send({to_send}) as {send_as} to {destination:?}")
            }
            Self::Collect { store_in, values } => {
                write!(f, "{store_in} = collect({values})")
            }
        }
    }
}

impl<Id: PartyId, P: Protocol<Id>> Display for Rule<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if self.conditions.is_empty() {
            writeln!(f, "if True:")?;
        } else {
            let conditions = self
                .conditions
                .iter()
                .map(|condition| condition.to_string())
                .join(" AND ");
            writeln!(f, "if {conditions}:")?;
        }
        write!(f, "  {}", self.action)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Display for Ruleset<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Ruleset:")?;
        for rule in self.rules.iter() {
            writeln!(f, "{}", rule)?;
        }
        Ok(())
    }
}
