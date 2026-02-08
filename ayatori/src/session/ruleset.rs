use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};

use itertools::Itertools;

use super::conditions::{Condition, LeafCondition};
use crate::{
    error::LocalError,
    protocol::{ArrayFunction, Node, NodeKind, ScalarFunction, SessionParameters, Tag, serialize_function},
};

#[derive(Debug)]
pub(crate) enum Arg {
    Scalar(Tag),
    ArrayElem(Tag),
}

#[derive_where::derive_where(Debug)]
pub(crate) enum Action<SP: SessionParameters> {
    ComputeScalar {
        store_in: Tag,
        function: ScalarFunction<SP>,
        args: BTreeMap<String, Tag>,
    },
    ComputeArrayElement {
        store_in: Tag,
        index: SP::Verifier,
        function: ArrayFunction<SP>,
        args: BTreeMap<String, Arg>,
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
struct Rule<SP: SessionParameters> {
    condition: Condition<SP::Verifier>,
    action: Action<SP>,
}

#[derive(Debug)]
pub(crate) struct Ruleset<SP: SessionParameters> {
    output_tag: Tag,
    rules: Vec<Rule<SP>>,
}

impl<SP: SessionParameters> Ruleset<SP> {
    pub fn new(output_node: Node<SP>) -> Result<Self, LocalError> {
        let output_tag = output_node.store_in().clone();

        let mut rules = Vec::new();

        for node in output_node.flattened(None) {
            if let NodeKind::Receive { .. } = node.kind() {
                continue;
            }

            let mut shared_condition = Condition::empty();

            for dependency in node.dependencies() {
                match dependency.group() {
                    Some(_group) => {
                        return Err(LocalError::new("Only scalar nodes are allowed as dependencies"));
                    }
                    None => {
                        shared_condition.and(LeafCondition::Value {
                            tag: dependency.store_in().clone(),
                        });
                    }
                }
            }

            let mut actions = Vec::new();

            match node.kind() {
                NodeKind::ComputeScalar { function, args } => {
                    let mut specific_condition = Condition::empty();
                    for arg in args.values() {
                        specific_condition.and(LeafCondition::Value {
                            tag: arg.store_in().clone(),
                        });
                    }
                    actions.push((
                        Action::ComputeScalar {
                            store_in: node.store_in().clone(),
                            function: function.clone(),
                            args: args
                                .iter()
                                .map(|(name, arg)| (name.clone(), arg.store_in().clone()))
                                .collect(),
                        },
                        specific_condition,
                    ));
                }
                NodeKind::ComputeArray { function, args, group } => {
                    for id in group.ids() {
                        let mut specific_condition = Condition::empty();
                        for arg in args.values() {
                            if arg.group().is_some() {
                                specific_condition.and(LeafCondition::ArrayElement {
                                    tag: arg.store_in().clone(),
                                    id: id.clone(),
                                });
                            } else {
                                specific_condition.and(LeafCondition::Value {
                                    tag: arg.store_in().clone(),
                                });
                            }
                        }

                        actions.push((
                            Action::ComputeArrayElement {
                                store_in: node.store_in().clone(),
                                function: function.clone(),
                                index: id.clone(),
                                args: args
                                    .iter()
                                    .map(|(name, arg)| {
                                        let tag = arg.store_in().clone();
                                        let arg = if arg.group().is_some() {
                                            Arg::ArrayElem(tag)
                                        } else {
                                            Arg::Scalar(tag)
                                        };
                                        (name.clone(), arg)
                                    })
                                    .collect(),
                            },
                            specific_condition,
                        ));
                    }
                }
                NodeKind::Serialize { data, group, adapter } => {
                    for id in group.ids() {
                        let mut specific_condition = Condition::empty();
                        if data.group().is_some() {
                            specific_condition.and(LeafCondition::ArrayElement {
                                tag: data.store_in().clone(),
                                id: id.clone(),
                            });
                        } else {
                            specific_condition.and(LeafCondition::Value {
                                tag: data.store_in().clone(),
                            });
                        }

                        let arg_name = "_value";
                        let function = serialize_function(arg_name, node.store_in(), adapter);
                        let data_tag = data.store_in().clone();
                        let arg = if data.group().is_some() {
                            Arg::ArrayElem(data_tag)
                        } else {
                            Arg::Scalar(data_tag)
                        };

                        actions.push((
                            Action::ComputeArrayElement {
                                store_in: node.store_in().clone(),
                                function,
                                index: id.clone(),
                                args: [(arg_name.into(), arg)].into(),
                            },
                            specific_condition,
                        ));
                    }
                }
                NodeKind::DirectMessage { data, group } => {
                    for id in group.ids() {
                        let mut specific_condition = Condition::empty();
                        specific_condition.and(LeafCondition::ArrayElement {
                            tag: data.store_in().clone(),
                            id: id.clone(),
                        });
                        actions.push((
                            Action::Send {
                                store_in: node.store_in().clone(),
                                to_send: data.store_in().clone(),
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
                        tag: values.store_in().clone(),
                        group: group.clone(),
                        got_ids: BTreeSet::new(),
                    });

                    actions.push((
                        Action::Collect {
                            store_in: node.store_in().clone(),
                            values: values.store_in().clone(),
                        },
                        specific_condition,
                    ));
                }
                NodeKind::Receive { .. } => {}
            }

            for (action, specific_condition) in actions {
                let mut condition = shared_condition.clone();
                condition.and_condition(specific_condition);
                rules.push(Rule { condition, action });
            }
        }

        Ok(Self { output_tag, rules })
    }

    pub fn update_with_value_ready(&mut self, tag: &Tag) {
        for rule in &mut self.rules {
            rule.condition.update_with_value_ready(tag);
        }
    }

    pub fn update_with_array_element_ready(&mut self, tag: &Tag, id: &SP::Verifier) {
        for rule in &mut self.rules {
            rule.condition.update_with_array_element_ready(tag, id);
        }
    }

    fn pop_send_action(&mut self) -> Option<Action<SP>> {
        self.rules
            .extract_if(.., |rule| {
                matches!(rule.action, Action::Send { .. }) && rule.condition.is_empty()
            })
            .next()
            .map(|rule| rule.action)
    }

    fn pop_local_action(&mut self) -> Option<Action<SP>> {
        self.rules
            .extract_if(.., |rule| {
                !matches!(rule.action, Action::Send { .. }) && rule.condition.is_empty()
            })
            .next()
            .map(|rule| rule.action)
    }

    pub fn pop_action(&mut self) -> Option<Action<SP>> {
        self.pop_local_action().or_else(|| self.pop_send_action())
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn output_tag(&self) -> &Tag {
        &self.output_tag
    }
}

impl<SP: SessionParameters> Display for Action<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ComputeScalar {
                store_in,
                function,
                args,
            } => {
                let joined_args = args.iter().map(|(name, arg)| format!("{}={}", name, arg)).join(", ");
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
                    .map(|(name, arg)| {
                        let arg_str = match arg {
                            Arg::Scalar(tag) => tag.to_string(),
                            Arg::ArrayElem(tag) => format!("{tag}[{index:?}]"),
                        };
                        format!("{}={}", name, arg_str)
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

impl<SP: SessionParameters> Display for Rule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "if {}:", self.condition)?;
        write!(f, "  {}", self.action)
    }
}

impl<SP: SessionParameters> Display for Ruleset<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Ruleset:")?;
        for rule in &self.rules {
            writeln!(f, "{rule}")?;
        }
        Ok(())
    }
}
