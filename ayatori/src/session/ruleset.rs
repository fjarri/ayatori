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
    protocol::{ArrayFunction, FullName, Node, NodeKind, Reproducibility, ScalarFunction, SessionParameters, Tag},
};

#[derive(Debug)]
pub(crate) enum Arg {
    Scalar(Tag),
    ArrayElem(Tag),
}

#[derive(Debug, Clone)]
pub(crate) enum OnError {
    CollectEvidence(BTreeSet<FullName>),
    Escalate,
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
        on_error: OnError,
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

impl<SP: SessionParameters> Action<SP> {
    pub fn store_in(&self) -> &Tag {
        // TODO: should this just be a field?
        match self {
            Self::ComputeScalar { store_in, .. }
            | Self::ComputeArrayElement { store_in, .. }
            | Self::Send { store_in, .. }
            | Self::Collect { store_in, .. } => store_in,
        }
    }
}

#[derive(Debug)]
struct Rule<SP: SessionParameters> {
    condition: Condition<SP::Verifier>,
    action: Action<SP>,
}

fn get_on_error<SP: SessionParameters>(node: &Node<SP>, private_inputs: &BTreeSet<String>) -> OnError {
    match node.reproducibility() {
        Reproducibility::Available { arguments, messages } => {
            if !arguments.is_disjoint(private_inputs) {
                return OnError::Escalate;
            }
            OnError::CollectEvidence(messages)
        }
        Reproducibility::NotAvailable => OnError::Escalate,
    }
}

fn make_compute_array_action<SP: SessionParameters>(
    store_in: &Tag,
    id: &SP::Verifier,
    function: &ArrayFunction<SP>,
    args: &BTreeMap<String, Node<SP>>,
    on_error: &OnError,
) -> (Action<SP>, Condition<SP::Verifier>) {
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

    let arg_tags = args
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
        .collect();

    let action = Action::ComputeArrayElement {
        store_in: store_in.clone(),
        function: function.clone(),
        index: id.clone(),
        args: arg_tags,
        on_error: on_error.clone(),
    };

    (action, specific_condition)
}

#[derive(Debug)]
enum State {
    InProgress,
    ReachedOutput,
    StalledAt(Tag),
}

#[derive(Debug)]
pub(crate) enum ActionGroup<SP: SessionParameters> {
    Action(Action<SP>),
    ReturnOutput(Tag),
    Terminate(Tag),
}

#[derive(Debug)]
pub(crate) struct Ruleset<SP: SessionParameters> {
    output_tag: Tag,
    rules: Vec<Rule<SP>>,
    expected_messages: BTreeMap<FullName, BTreeSet<SP::Verifier>>,
    state: State,
    banned_parties: BTreeSet<SP::Verifier>,
}

impl<SP: SessionParameters> Ruleset<SP> {
    pub fn new(output_node: &Node<SP>, private_inputs: &BTreeSet<String>) -> Result<Self, LocalError> {
        let output_tag = output_node.store_in().clone();

        let mut rules = Vec::new();
        let mut expected_messages = BTreeMap::new();

        let mut arguments = Vec::new();

        for node in output_node.flattened() {
            let mut shared_condition = Condition::empty();

            for dependency in node.dependencies() {
                match dependency.group() {
                    Some(_group) => {
                        // TODO: should be checked at node graph creation stage
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
                NodeKind::ScalarArgument {
                    store_in: _store_in,
                    name,
                } => {
                    // TODO: check that the remaining argument nodes correspond to arguments provided.
                    arguments.push(name.clone());
                }
                NodeKind::ComputeScalar {
                    store_in,
                    function,
                    args,
                } => {
                    let mut specific_condition = Condition::empty();
                    for arg in args.values() {
                        specific_condition.and(LeafCondition::Value {
                            tag: arg.store_in().clone(),
                        });
                    }
                    actions.push((
                        Action::ComputeScalar {
                            store_in: store_in.clone(),
                            function: function.clone(),
                            args: args
                                .iter()
                                .map(|(name, arg)| (name.clone(), arg.store_in().clone()))
                                .collect(),
                        },
                        specific_condition,
                    ));
                }
                NodeKind::ComputeArray {
                    store_in,
                    function,
                    args,
                    group,
                } => {
                    let on_error = get_on_error(&node, private_inputs);
                    for id in group.ids() {
                        actions.push(make_compute_array_action(store_in, id, function, args, &on_error));
                    }
                }
                NodeKind::DirectMessage { store_in, data, group } => {
                    for id in group.ids() {
                        let mut specific_condition = Condition::empty();
                        specific_condition.and(LeafCondition::ArrayElement {
                            tag: data.store_in().clone(),
                            id: id.clone(),
                        });
                        actions.push((
                            Action::Send {
                                store_in: store_in.clone(),
                                to_send: data.store_in().clone(),
                                destination: id.clone(),
                                index: Some(id.clone()),
                            },
                            specific_condition,
                        ));
                    }
                }
                NodeKind::Collect {
                    store_in,
                    values,
                    group,
                } => {
                    let mut specific_condition = Condition::empty();
                    specific_condition.and(LeafCondition::Array {
                        tag: values.store_in().clone(),
                        group: group.clone(),
                        got_ids: BTreeSet::new(),
                    });

                    actions.push((
                        Action::Collect {
                            store_in: store_in.clone(),
                            values: values.store_in().clone(),
                        },
                        specific_condition,
                    ));
                }
                NodeKind::Receive {
                    store_in: _store_in,
                    group,
                    message_name,
                    serde_adapter: _serde_adapter,
                } => {
                    expected_messages.insert(message_name.clone(), group.ids().cloned().collect());
                }
            }

            for (action, specific_condition) in actions {
                let mut condition = shared_condition.clone();
                condition.and_condition(specific_condition);
                rules.push(Rule { condition, action });
            }
        }

        let mut result = Self {
            output_tag,
            rules,
            expected_messages,
            state: State::InProgress,
            banned_parties: BTreeSet::new(),
        };

        for name in arguments {
            result.update_with_value_ready(&Tag::computed(&name));
        }

        Ok(result)
    }

    pub fn update_with_banned_party(&mut self, id: &SP::Verifier) {
        self.banned_parties.insert(id.clone());
        for rule in &mut self.rules {
            if !rule.condition.is_satisfiable(&self.banned_parties) {
                // TODO (#21): it is possible that the output is reached by other branches,
                // so we are not always stalled.
                self.state = State::StalledAt(rule.action.store_in().clone());
                return;
            }
        }
    }

    pub fn update_with_value_ready(&mut self, tag: &Tag) {
        for rule in &mut self.rules {
            rule.condition.update_with_value_ready(tag);
        }
        if tag == &self.output_tag {
            self.state = State::ReachedOutput;
        }
    }

    pub fn update_with_array_element_ready(&mut self, tag: &Tag, id: &SP::Verifier) {
        for rule in &mut self.rules {
            rule.condition.update_with_array_element_ready(tag, id);
        }
    }

    fn pop_send_action(&mut self) -> Option<ActionGroup<SP>> {
        self.rules
            .extract_if(.., |rule| {
                matches!(rule.action, Action::Send { .. }) && rule.condition.is_empty()
            })
            .next()
            .map(|rule| rule.action)
            .map(ActionGroup::Action)
    }

    fn pop_local_action(&mut self) -> Option<ActionGroup<SP>> {
        self.rules
            .extract_if(.., |rule| {
                !matches!(rule.action, Action::Send { .. }) && rule.condition.is_empty()
            })
            .next()
            .map(|rule| rule.action)
            .map(ActionGroup::Action)
    }

    pub fn pop_action(&mut self) -> Result<Option<ActionGroup<SP>>, LocalError> {
        if matches!(self.state, State::InProgress) && self.rules.is_empty() {
            return Err(LocalError::new(
                "No rules to apply, and the output value has not been set",
            ));
        }

        // TODO: we need to not expose Action to the outside. This way we can flatten ActionGroup.
        Ok(match &self.state {
            // Regular operation: first pop all locally computable actions
            // to have as many values ready to send as possible.
            State::InProgress => self.pop_local_action().or_else(|| self.pop_send_action()),
            // If we are ready to terminate, pop all send action first so that we don't stall other nodes,
            // then return the terminating action.
            State::ReachedOutput => self
                .pop_send_action()
                .or_else(|| Some(ActionGroup::ReturnOutput(self.output_tag.clone()))),
            State::StalledAt(tag) => {
                let tag = tag.clone();
                self.pop_send_action()
                    .or_else(move || Some(ActionGroup::Terminate(tag)))
            }
        })
    }

    pub fn expected_messages(&self) -> &BTreeMap<FullName, BTreeSet<SP::Verifier>> {
        &self.expected_messages
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
                on_error,
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
                write!(f, "{store_in}[{index:?}] = {function}({index:?}, {joined_args})")?;
                write!(f, "\n  on_error: {on_error:?}",)
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
