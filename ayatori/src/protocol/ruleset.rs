use super::node::{Node, PartyGroup, PartyId, Protocol, Tag, TypedNode, WrappedFunction};
use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::{vec, vec::Vec};
use core::fmt::{self, Display};

use itertools::Itertools;

#[derive(Debug, Clone)]
enum Condition<Id: PartyId> {
    ValueReady {
        tag: Tag,
    },
    // TODO: kind of weird to keep `got_ids` here, keep it separate?
    ArrayReady {
        tag: Tag,
        group: PartyGroup<Id>,
        got_ids: BTreeSet<Id>,
    },
}

#[derive(Debug)]
pub(crate) enum Action<Id: PartyId, P: Protocol<Id>> {
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
pub(crate) struct Ruleset<Id: PartyId, P: Protocol<Id>> {
    output_tag: Tag,
    rules: Vec<Rule<Id, P>>,
}

impl<Id: PartyId, P: Protocol<Id>> Ruleset<Id, P> {
    pub fn new(output_node: Node<Id, P>) -> Self {
        let output_tag = output_node.as_ref().store_in().clone();

        let mut nodes_to_process = vec![output_node];
        let mut rules = Vec::new();

        let mut nodes_seen = BTreeSet::<usize>::new();

        while let Some(node) = nodes_to_process.pop() {
            if nodes_seen.contains(&node.id()) {
                continue;
            }
            nodes_seen.insert(node.id());

            if let TypedNode::Receive { .. } = node.as_ref() {
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
                        got_ids: BTreeSet::new(),
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
                        args: args
                            .iter()
                            .map(|arg: &Node<Id, P>| arg.as_ref().store_in().clone())
                            .collect(),
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

        Self { rules, output_tag }
    }

    pub fn value_ready(&mut self, tag: &Tag, id: Option<&Id>) {
        // TODO: split in two methods, for scalars and arrays?
        for rule in self.rules.iter_mut() {
            // TODO: have a Conditions struct with a `partially_eval` or `update` method
            let mut new_conditions = Vec::new();
            for condition in rule.conditions.iter().cloned() {
                let mut condition = condition;
                match id {
                    Some(id) => match &mut condition {
                        Condition::ArrayReady {
                            tag: condition_tag,
                            group,
                            got_ids,
                        } => {
                            if condition_tag == tag {
                                got_ids.insert(id.clone());
                                if group.has_quorum(got_ids) {
                                    continue;
                                }
                            }
                        }
                        Condition::ValueReady { tag: condition_tag } => {
                            if condition_tag == tag {
                                panic!()
                            }
                        }
                    },
                    None => match &condition {
                        Condition::ArrayReady { tag: condition_tag, .. } => {
                            if condition_tag == tag {
                                panic!()
                            }
                        }
                        Condition::ValueReady { tag: condition_tag } => {
                            if condition_tag == tag {
                                continue;
                            }
                        }
                    },
                }
                new_conditions.push(condition);
            }

            rule.conditions = new_conditions;
        }
    }

    fn pop_send_action(&mut self) -> Option<Action<Id, P>> {
        self.rules
            .extract_if(.., |rule| {
                matches!(rule.action, Action::Send { .. }) && rule.conditions.is_empty()
            })
            .next()
            .map(|rule| rule.action)
    }

    fn pop_local_action(&mut self) -> Option<Action<Id, P>> {
        self.rules
            .extract_if(.., |rule| {
                !matches!(rule.action, Action::Send { .. }) && rule.conditions.is_empty()
            })
            .next()
            .map(|rule| rule.action)
    }

    pub fn pop_action(&mut self) -> Option<Action<Id, P>> {
        self.pop_local_action().or_else(|| self.pop_send_action())
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn output_tag(&self) -> &Tag {
        &self.output_tag
    }
}

impl<Id: PartyId> Display for Condition<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ValueReady { tag } => {
                write!(f, "ready({tag})")
            }
            Self::ArrayReady { tag, group, got_ids } => {
                write!(f, "all-ready({tag}, {group}) [have: {got_ids:?}]")
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
