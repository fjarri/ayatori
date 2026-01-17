use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::{format, vec, vec::Vec};
use core::fmt::{self, Display};

use itertools::Itertools;

use super::conditions::{Condition, LeafCondition};
use crate::protocol::{
    Node, PartyId, Protocol, Tag, TypedNode, WrappedArrayFunction, WrappedFunction, WrappedFunctionPrivate,
};

#[derive(Debug)]
pub(crate) enum Arg {
    Scalar(Tag),
    ArrayElem(Tag),
}

#[derive(Debug)]
pub(crate) enum Action<Id: PartyId, P: Protocol<Id>> {
    ComputeScalar {
        store_in: Tag,
        function: WrappedFunction<Id, P>,
        args: Vec<Tag>,
    },
    ComputeScalarPrivate {
        store_in: Tag,
        function: WrappedFunctionPrivate<Id, P>,
        args: Vec<Tag>,
    },
    ComputeArrayElement {
        store_in: Tag,
        index: Id,
        function: WrappedArrayFunction<Id, P>,
        args: Vec<Arg>,
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
    condition: Condition<Id>,
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
                continue;
            }

            let mut shared_condition = Condition::empty();

            for dependency in node.as_ref().dependencies() {
                shared_condition.and(LeafCondition::Value {
                    tag: dependency.as_ref().store_in().clone(),
                });
                nodes_to_process.push(dependency.get_strong_ref());
            }

            let mut actions = Vec::new();

            match node.as_ref() {
                TypedNode::ComputeScalar {
                    store_in,
                    function,
                    args,
                    ..
                } => {
                    let mut specific_condition = Condition::empty();
                    for arg in args.iter() {
                        specific_condition.and(LeafCondition::Value {
                            tag: arg.as_ref().store_in().clone(),
                        });
                        nodes_to_process.push(arg.get_strong_ref());
                    }
                    actions.push((
                        Action::ComputeScalar {
                            store_in: store_in.clone(),
                            function: function.clone(),
                            args: args
                                .iter()
                                .map(|arg: &Node<Id, P>| arg.as_ref().store_in().clone())
                                .collect(),
                        },
                        specific_condition,
                    ));
                }
                TypedNode::ComputeScalarPrivate {
                    store_in,
                    function,
                    args,
                    ..
                } => {
                    let mut specific_condition = Condition::empty();
                    for arg in args.iter() {
                        specific_condition.and(LeafCondition::Value {
                            tag: arg.as_ref().store_in().clone(),
                        });
                        nodes_to_process.push(arg.get_strong_ref());
                    }
                    actions.push((
                        Action::ComputeScalarPrivate {
                            store_in: store_in.clone(),
                            function: function.clone(),
                            args: args
                                .iter()
                                .map(|arg: &Node<Id, P>| arg.as_ref().store_in().clone())
                                .collect(),
                        },
                        specific_condition,
                    ));
                }
                TypedNode::ComputeArray {
                    store_in,
                    function,
                    args,
                    group,
                    ..
                } => {
                    for id in group.ids() {
                        let mut specific_condition = Condition::empty();
                        for arg in args.iter() {
                            if arg.as_ref().group().is_some() {
                                specific_condition.and(LeafCondition::ArrayElement {
                                    tag: arg.as_ref().store_in().clone(),
                                    id: id.clone(),
                                });
                            } else {
                                specific_condition.and(LeafCondition::Value {
                                    tag: arg.as_ref().store_in().clone(),
                                });
                            }
                        }

                        actions.push((
                            Action::ComputeArrayElement {
                                store_in: store_in.clone(),
                                function: function.clone(),
                                index: id.clone(),
                                args: args
                                    .iter()
                                    .map(|arg: &Node<Id, P>| {
                                        let tag = arg.as_ref().store_in().clone();
                                        if arg.as_ref().group().is_some() {
                                            Arg::ArrayElem(tag)
                                        } else {
                                            Arg::Scalar(tag)
                                        }
                                    })
                                    .collect(),
                            },
                            specific_condition,
                        ));
                    }
                }
                TypedNode::Send {
                    store_in,
                    send_as,
                    data,
                    group,
                    ..
                } => {
                    let mut specific_condition = Condition::empty();
                    specific_condition.and(LeafCondition::Value {
                        tag: data.as_ref().store_in().clone(),
                    });
                    nodes_to_process.push(data.get_strong_ref());
                    for id in group.ids() {
                        actions.push((
                            Action::Send {
                                store_in: store_in.clone(),
                                send_as: send_as.clone(),
                                to_send: data.as_ref().store_in().clone(),
                                destination: id.clone(),
                            },
                            specific_condition.clone(),
                        ));
                    }
                }
                TypedNode::Collect { store_in, values, .. } => {
                    let mut specific_condition = Condition::empty();
                    let group = values.as_ref().group().unwrap();
                    specific_condition.and(LeafCondition::Array {
                        tag: values.as_ref().store_in().clone(),
                        group: group.clone(),
                        got_ids: BTreeSet::new(),
                    });
                    nodes_to_process.push(values.get_strong_ref());

                    actions.push((
                        Action::Collect {
                            store_in: store_in.clone(),
                            values: values.as_ref().store_in().clone(),
                        },
                        specific_condition,
                    ))
                }
                TypedNode::Receive { .. } => {}
            }

            for (action, specific_condition) in actions {
                let mut condition = shared_condition.clone();
                condition.and_condition(specific_condition);
                rules.push(Rule { condition, action });
            }
        }

        Self { rules, output_tag }
    }

    pub fn update_with_value_ready(&mut self, tag: &Tag) {
        for rule in self.rules.iter_mut() {
            rule.condition.update_with_value_ready(tag);
        }
    }

    pub fn update_with_array_element_ready(&mut self, tag: &Tag, id: &Id) {
        for rule in self.rules.iter_mut() {
            rule.condition.update_with_array_element_ready(tag, id);
        }
    }

    fn pop_send_action(&mut self) -> Option<Action<Id, P>> {
        self.rules
            .extract_if(.., |rule| {
                matches!(rule.action, Action::Send { .. }) && rule.condition.is_empty()
            })
            .next()
            .map(|rule| rule.action)
    }

    fn pop_local_action(&mut self) -> Option<Action<Id, P>> {
        self.rules
            .extract_if(.., |rule| {
                !matches!(rule.action, Action::Send { .. }) && rule.condition.is_empty()
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
            Self::ComputeScalarPrivate {
                store_in,
                function,
                args,
            } => {
                let joined_args = args.iter().map(|arg| arg.to_string()).join(", ");
                write!(f, "{store_in} = {function}(RNG, {joined_args})")
            }
            Self::ComputeArrayElement {
                store_in,
                index,
                function,
                args,
            } => {
                let joined_args = args
                    .iter()
                    .map(|arg| match arg {
                        Arg::Scalar(tag) => tag.to_string(),
                        Arg::ArrayElem(tag) => format!("{tag}[{index:?}]"),
                    })
                    .join(", ");
                write!(f, "{store_in}[{index:?}] = {function}({index:?}, {joined_args})")
            }
            Self::Send {
                store_in,
                send_as,
                to_send,
                destination,
            } => {
                write!(
                    f,
                    "{store_in}[{destination:?}] = send({to_send}) as {send_as} to {destination:?}"
                )
            }
            Self::Collect { store_in, values } => {
                write!(f, "{store_in} = collect({values})")
            }
        }
    }
}

impl<Id: PartyId, P: Protocol<Id>> Display for Rule<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "if {}:", self.condition)?;
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
