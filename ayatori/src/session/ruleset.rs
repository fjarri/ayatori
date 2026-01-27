use alloc::{collections::BTreeSet, format, string::ToString, vec, vec::Vec};
use core::fmt::{self, Display};

use itertools::Itertools;

use super::conditions::{Condition, LeafCondition};
use crate::protocol::{ArrayFunction, Node, NodeKind, Protocol, ScalarFunction, SessionParameters, Tag};

#[derive(Debug)]
pub(crate) enum Arg {
    Scalar(Tag),
    ArrayElem(Tag),
}

#[derive(Debug)]
pub(crate) enum Action<SP: SessionParameters, P: Protocol<SP>> {
    ComputeScalar {
        store_in: Tag,
        function: ScalarFunction<SP, P>,
        args: Vec<Tag>,
    },
    ComputeArrayElement {
        store_in: Tag,
        index: SP::Verifier,
        function: ArrayFunction<SP, P>,
        args: Vec<Arg>,
    },
    Send {
        store_in: Tag,
        to_send: Tag,
        destination: SP::Verifier,
        index: Option<SP::Verifier>,
    },
    Collect {
        store_in: Tag,
        values: Tag,
    },
}

#[derive(Debug)]
struct Rule<SP: SessionParameters, P: Protocol<SP>> {
    condition: Condition<SP::Verifier>,
    action: Action<SP, P>,
}

#[derive(Debug)]
pub(crate) struct Ruleset<SP: SessionParameters, P: Protocol<SP>> {
    output_tag: Tag,
    rules: Vec<Rule<SP, P>>,
}

impl<SP: SessionParameters, P: Protocol<SP>> Ruleset<SP, P> {
    pub fn new(output_node: Node<SP, P>) -> Self {
        let output_tag = output_node.as_ref().store_in().clone();

        let mut nodes_to_process = vec![output_node];
        let mut rules = Vec::new();

        let mut nodes_seen = BTreeSet::<usize>::new();

        while let Some(node) = nodes_to_process.pop() {
            if nodes_seen.contains(&node.id()) {
                continue;
            }
            nodes_seen.insert(node.id());

            if let NodeKind::Receive { .. } = node.as_ref().kind() {
                continue;
            }

            let mut shared_condition = Condition::empty();

            for dependency in node.as_ref().dependencies() {
                match dependency.as_ref().group() {
                    Some(_group) => {
                        panic!("Not supported");
                    }
                    None => {
                        shared_condition.and(LeafCondition::Value {
                            tag: dependency.as_ref().store_in().clone(),
                        });
                    }
                }
                nodes_to_process.push(dependency.get_strong_ref());
            }

            let mut actions = Vec::new();

            match node.as_ref().kind() {
                NodeKind::ComputeScalar { function, args } => {
                    let mut specific_condition = Condition::empty();
                    for arg in args.iter() {
                        specific_condition.and(LeafCondition::Value {
                            tag: arg.as_ref().store_in().clone(),
                        });
                        nodes_to_process.push(arg.get_strong_ref());
                    }
                    actions.push((
                        Action::ComputeScalar {
                            store_in: node.as_ref().store_in().clone(),
                            function: function.clone(),
                            args: args
                                .iter()
                                .map(|arg: &Node<SP, P>| arg.as_ref().store_in().clone())
                                .collect(),
                        },
                        specific_condition,
                    ));
                }
                NodeKind::ComputeArray {
                    function,
                    args,
                    group,
                    #[allow(unused)]
                    returns_nothing,
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
                            nodes_to_process.push(arg.get_strong_ref());
                        }

                        actions.push((
                            Action::ComputeArrayElement {
                                store_in: node.as_ref().store_in().clone(),
                                function: function.clone(),
                                index: id.clone(),
                                args: args
                                    .iter()
                                    .map(|arg: &Node<SP, P>| {
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
                NodeKind::DirectMessage { data, group } => {
                    nodes_to_process.push(data.get_strong_ref());
                    for id in group.ids() {
                        let mut specific_condition = Condition::empty();
                        specific_condition.and(LeafCondition::ArrayElement {
                            tag: data.as_ref().store_in().clone(),
                            id: id.clone(),
                        });
                        actions.push((
                            Action::Send {
                                store_in: node.as_ref().store_in().clone(),
                                to_send: data.as_ref().store_in().clone(),
                                destination: id.clone(),
                                index: Some(id.clone()),
                            },
                            specific_condition,
                        ));
                    }
                }
                NodeKind::Collect { values, group } => {
                    let mut specific_condition = Condition::empty();
                    specific_condition.and(LeafCondition::Array {
                        tag: values.as_ref().store_in().clone(),
                        group: group.clone(),
                        got_ids: BTreeSet::new(),
                    });
                    nodes_to_process.push(values.get_strong_ref());

                    actions.push((
                        Action::Collect {
                            store_in: node.as_ref().store_in().clone(),
                            values: values.as_ref().store_in().clone(),
                        },
                        specific_condition,
                    ))
                }
                NodeKind::Receive { .. } => {}
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

    pub fn update_with_array_element_ready(&mut self, tag: &Tag, id: &SP::Verifier) {
        for rule in self.rules.iter_mut() {
            rule.condition.update_with_array_element_ready(tag, id);
        }
    }

    fn pop_send_action(&mut self) -> Option<Action<SP, P>> {
        self.rules
            .extract_if(.., |rule| {
                matches!(rule.action, Action::Send { .. }) && rule.condition.is_empty()
            })
            .next()
            .map(|rule| rule.action)
    }

    fn pop_local_action(&mut self) -> Option<Action<SP, P>> {
        self.rules
            .extract_if(.., |rule| {
                !matches!(rule.action, Action::Send { .. }) && rule.condition.is_empty()
            })
            .next()
            .map(|rule| rule.action)
    }

    pub fn pop_action(&mut self) -> Option<Action<SP, P>> {
        self.pop_local_action().or_else(|| self.pop_send_action())
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn output_tag(&self) -> &Tag {
        &self.output_tag
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for Action<SP, P> {
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
                to_send,
                destination,
                index,
            } => {
                if let Some(index) = index {
                    write!(
                        f,
                        "{store_in}[{destination:?}] = send({to_send}[{index:?}]) to {destination:?})"
                    )
                } else {
                    write!(f, "{store_in}[{destination:?}] = send({to_send}) to {destination:?}")
                }
            }
            Self::Collect { store_in, values } => {
                write!(f, "{store_in} = collect({values})")
            }
        }
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for Rule<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "if {}:", self.condition)?;
        write!(f, "  {}", self.action)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for Ruleset<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Ruleset:")?;
        for rule in self.rules.iter() {
            writeln!(f, "{}", rule)?;
        }
        Ok(())
    }
}
