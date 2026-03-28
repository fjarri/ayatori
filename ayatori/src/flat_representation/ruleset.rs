use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};

use itertools::Itertools;

use super::conditions::{ElementCondition, QuorumCondition, ScalarCondition};
use crate::{
    entities::{
        AnyTag, AnyTagRef, DeserializeFunction, FullName, MappingFunction, MappingTag, ScalarFunction, ScalarTag,
        SerdeAdapter, SerializeAndSignFunction,
    },
    errors::LocalError,
    graph_representation::{Node, NodeKind, Reproducibility},
    traits::SessionParameters,
};

#[derive_where::derive_where(Debug)]
struct ScalarRule<SP: SessionParameters> {
    dependencies_condition: ScalarCondition,
    scalar_condition: ScalarCondition,
    store_in: ScalarTag,
    function: ScalarFunction<SP>,
    args: BTreeMap<String, ScalarTag>,
}

#[derive_where::derive_where(Debug)]
struct CollectRule<SP: SessionParameters> {
    dependencies_condition: ScalarCondition,
    quorum_condition: QuorumCondition<SP::Verifier>,
    store_in: ScalarTag,
    values: MappingTag,
}

#[derive_where::derive_where(Debug)]
struct MappingRule<SP: SessionParameters> {
    dependencies_condition: ScalarCondition,
    scalar_condition: ScalarCondition,
    element_conditions: BTreeMap<SP::Verifier, ElementCondition>,
    kind: MappingRuleKind<SP>,
}

#[derive_where::derive_where(Debug, Clone)]
enum MappingRuleKind<SP: SessionParameters> {
    Compute {
        store_in: MappingTag,
        function: MappingFunction<SP>,
        args: BTreeMap<String, AnyTag>,
        on_error: OnError,
    },
    SerializeAndSign {
        store_in: MappingTag,
        function: SerializeAndSignFunction<SP>,
        data: AnyTag,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    Deserialize {
        store_in: MappingTag,
        function: DeserializeFunction<SP>,
        data: MappingTag,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        on_error: OnError,
    },
    Send {
        store_in: MappingTag,
        to_send: MappingTag,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum OnError {
    CollectEvidence(BTreeSet<FullName>),
    Escalate,
}

#[derive_where::derive_where(Debug)]
pub(crate) enum Action<SP: SessionParameters> {
    ComputeScalar {
        store_in: ScalarTag,
        function: ScalarFunction<SP>,
        args: BTreeMap<String, ScalarTag>,
    },
    ComputeMappingElement {
        store_in: MappingTag,
        index: SP::Verifier,
        function: MappingFunction<SP>,
        args: BTreeMap<String, AnyTag>,
        on_error: OnError,
    },
    ComputeSerializeAndSignElement {
        store_in: MappingTag,
        index: SP::Verifier,
        function: SerializeAndSignFunction<SP>,
        data: AnyTag,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    ComputeDeserializeElement {
        store_in: MappingTag,
        index: SP::Verifier,
        function: DeserializeFunction<SP>,
        data: MappingTag,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        on_error: OnError,
    },
    Send {
        store_in: MappingTag,
        to_send: MappingTag,
        destination: SP::Verifier,
    },
    Collect {
        store_in: ScalarTag,
        values: MappingTag,
        indices: BTreeSet<SP::Verifier>,
    },
    ReturnOutput(ScalarTag),
    Terminate(ScalarTag),
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

fn propagate_groups<SP: SessionParameters>(
    root: &Node<SP>,
) -> Result<BTreeMap<MappingTag, BTreeSet<SP::Verifier>>, LocalError> {
    let mut result: BTreeMap<MappingTag, BTreeSet<SP::Verifier>> = BTreeMap::new();

    for node in root.flattened_pre_order() {
        match node.kind() {
            NodeKind::ScalarArgument { .. } => {}
            NodeKind::ComputeScalar { .. } => {}
            NodeKind::ComputeMapping { store_in, args, .. } => {
                let ids = result
                    .get(store_in)
                    .cloned()
                    .ok_or_else(|| LocalError::new("Assumption: the node must have been already processed"))?;
                for arg in args.values() {
                    if let AnyTagRef::Mapping(tag) = arg.store_in() {
                        result.entry(tag.clone()).or_insert(BTreeSet::new()).extend(ids.clone());
                    }
                }
            }
            NodeKind::SerializeAndSign { store_in, data, .. } => {
                let ids = result
                    .get(store_in)
                    .cloned()
                    .ok_or_else(|| LocalError::new("Assumption: the node must have been already processed"))?;
                if let AnyTagRef::Mapping(tag) = data.store_in() {
                    result.entry(tag.clone()).or_insert(BTreeSet::new()).extend(ids);
                }
            }
            NodeKind::Deserialize { store_in, data, .. } => {
                let ids = result
                    .get(store_in)
                    .cloned()
                    .ok_or_else(|| LocalError::new("Assumption: the node must have been already processed"))?;
                let tag = data
                    .store_in()
                    .mapping()
                    .cloned()
                    .ok_or_else(|| LocalError::new("Assumption: Deserialize's argument is a mapping node"))?;
                result.entry(tag).or_insert(BTreeSet::new()).extend(ids);
            }
            NodeKind::DirectMessage { store_in, data, .. } => {
                let ids = result
                    .get(store_in)
                    .cloned()
                    .ok_or_else(|| LocalError::new("Assumption: the node must have been already processed"))?;
                let tag = data
                    .store_in()
                    .mapping()
                    .cloned()
                    .ok_or_else(|| LocalError::new("Assumption: DirectMessage's argument is a mapping node"))?;
                result.entry(tag).or_insert(BTreeSet::new()).extend(ids);
            }

            NodeKind::Collect { values, group, .. } => {
                let tag = values
                    .store_in()
                    .mapping()
                    .cloned()
                    .ok_or_else(|| LocalError::new("Assumption: Collect's argument is a mapping node"))?;
                result
                    .entry(tag)
                    .or_insert(BTreeSet::new())
                    .extend(group.ids().cloned());
            }
            NodeKind::Receive { .. } => {}
        }
    }

    Ok(result)
}

#[derive(Debug)]
enum State {
    InProgress,
    ReachedOutput,
    StalledAt(ScalarTag),
}

#[derive(Debug)]
pub(crate) struct Ruleset<SP: SessionParameters> {
    output_tag: ScalarTag,
    scalar_rules: Vec<ScalarRule<SP>>,
    collect_rules: Vec<CollectRule<SP>>,
    mapping_rules: Vec<MappingRule<SP>>,
    expected_messages: BTreeMap<FullName, BTreeSet<SP::Verifier>>,
    arguments: BTreeMap<String, ScalarTag>,
    state: State,
}

impl<SP: SessionParameters> Ruleset<SP> {
    pub fn new(output_node: &Node<SP>, private_inputs: &BTreeSet<String>) -> Result<Self, LocalError> {
        let output_tag = output_node
            .store_in()
            .scalar()
            .cloned()
            .ok_or_else(|| LocalError::new("The output node must be a scalar node"))?;

        let propagated_ids = propagate_groups(output_node)?;

        let mut scalar_rules = Vec::new();
        let mut collect_rules = Vec::new();
        let mut mapping_rules = Vec::new();
        let mut expected_messages = BTreeMap::new();

        let mut arguments = BTreeMap::new();

        for node in output_node.flattened_post_order() {
            let mut dependencies_condition = ScalarCondition::empty();

            for dependency in node.dependencies() {
                let tag = dependency
                    .store_in()
                    .scalar()
                    .ok_or_else(|| LocalError::new("Assumption: Only scalar nodes are allowed as dependencies"))?;
                dependencies_condition = dependencies_condition.and(tag);
            }

            match node.kind() {
                NodeKind::ScalarArgument { store_in, name } => {
                    arguments.insert(name.clone(), store_in.clone());
                }
                NodeKind::ComputeScalar {
                    store_in,
                    function,
                    args,
                } => {
                    let mut arg_tags = BTreeMap::new();
                    let mut scalar_condition = ScalarCondition::empty();
                    for (name, arg) in args {
                        let tag = arg.store_in().scalar().ok_or_else(|| {
                            LocalError::new(
                                "Assumption: Only scalar nodes are allowed as arguments to scalar functions",
                            )
                        })?;
                        scalar_condition = scalar_condition.and(tag);
                        arg_tags.insert(name.clone(), tag.clone());
                    }
                    scalar_rules.push(ScalarRule {
                        dependencies_condition,
                        scalar_condition,
                        store_in: store_in.clone(),
                        function: function.clone(),
                        args: arg_tags,
                    });
                }
                NodeKind::ComputeMapping {
                    store_in,
                    function,
                    args,
                } => {
                    let on_error = get_on_error(&node, private_inputs);
                    let possible_ids = propagated_ids.get(store_in).ok_or_else(|| {
                        LocalError::new("Assumption: the required IDs were propagated to all nodes in the tree")
                    })?;

                    let mut scalar_condition = ScalarCondition::empty();
                    let mut element_condition = ElementCondition::empty();
                    for arg in args.values() {
                        match arg.store_in() {
                            AnyTagRef::Mapping(tag) => element_condition = element_condition.and(tag),
                            AnyTagRef::Scalar(tag) => scalar_condition = scalar_condition.and(tag),
                        };
                    }

                    let element_conditions = possible_ids
                        .iter()
                        .cloned()
                        .map(|id| (id, element_condition.clone()))
                        .collect();

                    let arg_tags = args
                        .iter()
                        .map(|(name, arg)| {
                            let arg = arg.store_in().to_owned();
                            (name.clone(), arg)
                        })
                        .collect();

                    mapping_rules.push(MappingRule {
                        dependencies_condition,
                        scalar_condition,
                        element_conditions,
                        kind: MappingRuleKind::Compute {
                            store_in: store_in.clone(),
                            function: function.clone(),
                            args: arg_tags,
                            on_error: on_error.clone(),
                        },
                    })
                }
                NodeKind::SerializeAndSign {
                    store_in,
                    function,
                    data,
                    message_name,
                    serde_adapter,
                } => {
                    let possible_ids = propagated_ids.get(store_in).ok_or_else(|| {
                        LocalError::new("Assumption: the required IDs were propagated to all nodes in the tree")
                    })?;

                    let tag = data.store_in();

                    let mut scalar_condition = ScalarCondition::empty();
                    let mut element_condition = ElementCondition::empty();

                    match tag {
                        AnyTagRef::Scalar(tag) => scalar_condition = scalar_condition.and(tag),
                        AnyTagRef::Mapping(tag) => element_condition = element_condition.and(tag),
                    }

                    let element_conditions = possible_ids
                        .iter()
                        .cloned()
                        .map(|id| (id, element_condition.clone()))
                        .collect();

                    mapping_rules.push(MappingRule {
                        dependencies_condition,
                        scalar_condition,
                        element_conditions,
                        kind: MappingRuleKind::SerializeAndSign {
                            store_in: store_in.clone(),
                            function: function.clone(),
                            data: tag.to_owned(),
                            message_name: message_name.clone(),
                            serde_adapter: serde_adapter.clone(),
                        },
                    })
                }
                NodeKind::Deserialize {
                    store_in,
                    function,
                    data,
                    serde_adapter,
                } => {
                    let on_error = get_on_error(&node, private_inputs);

                    let possible_ids = propagated_ids.get(store_in).ok_or_else(|| {
                        LocalError::new("Assumption: the required IDs were propagated to all nodes in the tree")
                    })?;

                    let tag = data
                        .store_in()
                        .mapping()
                        .ok_or_else(|| LocalError::new("Assumption: Deserialize is expected to take mapping data"))?;

                    let element_condition = ElementCondition::empty().and(tag);
                    let element_conditions = possible_ids
                        .iter()
                        .cloned()
                        .map(|id| (id, element_condition.clone()))
                        .collect();

                    mapping_rules.push(MappingRule {
                        dependencies_condition,
                        scalar_condition: ScalarCondition::empty(),
                        element_conditions,
                        kind: MappingRuleKind::Deserialize {
                            store_in: store_in.clone(),
                            function: function.clone(),
                            data: tag.clone(),
                            serde_adapter: serde_adapter.clone(),
                            on_error,
                        },
                    })
                }
                NodeKind::DirectMessage { store_in, data } => {
                    let possible_ids = propagated_ids.get(store_in).ok_or_else(|| {
                        LocalError::new("Assumption: the required IDs were propagated to all nodes in the tree")
                    })?;

                    let tag = data.store_in().mapping().ok_or_else(|| {
                        LocalError::new("Assumption: DirectMessage node is expected to send mapping data")
                    })?;
                    let element_condition = ElementCondition::empty().and(tag);
                    let element_conditions = possible_ids
                        .iter()
                        .cloned()
                        .map(|id| (id, element_condition.clone()))
                        .collect();
                    mapping_rules.push(MappingRule {
                        dependencies_condition,
                        scalar_condition: ScalarCondition::empty(),
                        element_conditions,
                        kind: MappingRuleKind::Send {
                            store_in: store_in.clone(),
                            to_send: tag.clone(),
                        },
                    });
                }
                NodeKind::Collect {
                    store_in,
                    values,
                    group,
                } => {
                    let tag = values.store_in().mapping().ok_or_else(|| {
                        LocalError::new("Assumption: Collect node is expected to collect mapping data")
                    })?;
                    let quorum_condition = QuorumCondition::new(tag, group);
                    collect_rules.push(CollectRule {
                        dependencies_condition,
                        quorum_condition,
                        store_in: store_in.clone(),
                        values: tag.clone(),
                    });
                }
                NodeKind::Receive { store_in, message_name } => {
                    let possible_ids = propagated_ids.get(store_in).ok_or_else(|| {
                        LocalError::new("Assumption: the required IDs were propagated to all nodes in the tree")
                    })?;
                    expected_messages.insert(message_name.clone(), possible_ids.clone());
                }
            };
        }

        Ok(Self {
            output_tag,
            scalar_rules,
            collect_rules,
            mapping_rules,
            expected_messages,
            arguments,
            state: State::InProgress,
        })
    }

    pub fn update_with_banned_party(&mut self, id: &SP::Verifier) {
        for rule in &mut self.collect_rules {
            rule.quorum_condition.update_with_banned_party(id);
            if !rule.quorum_condition.is_satisfiable() {
                self.state = State::StalledAt(rule.store_in.clone());
            }
        }
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        if tag == &self.output_tag {
            self.state = State::ReachedOutput;
        }

        for rule in &mut self.scalar_rules {
            rule.dependencies_condition.update_with_scalar_ready(tag);
            rule.scalar_condition.update_with_scalar_ready(tag);
        }

        for rule in &mut self.collect_rules {
            rule.dependencies_condition.update_with_scalar_ready(tag);
        }

        for rule in &mut self.mapping_rules {
            rule.dependencies_condition.update_with_scalar_ready(tag);
            rule.scalar_condition.update_with_scalar_ready(tag);
        }
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &SP::Verifier) {
        for rule in &mut self.collect_rules {
            rule.quorum_condition.update_with_element_ready(tag, id);
        }

        for rule in &mut self.mapping_rules {
            if let Some(condition) = rule.element_conditions.get_mut(id) {
                condition.update_with_scalar_ready(tag);
            }
        }
    }

    fn pop_scalar_action(&mut self) -> Option<Action<SP>> {
        self.scalar_rules
            .extract_if(.., |rule| {
                rule.dependencies_condition.is_satisfied() && rule.scalar_condition.is_satisfied()
            })
            .next()
            .map(|rule| Action::ComputeScalar {
                store_in: rule.store_in,
                function: rule.function,
                args: rule.args,
            })
    }

    fn pop_collect_action(&mut self) -> Option<Action<SP>> {
        self.collect_rules
            .extract_if(.., |rule| {
                rule.dependencies_condition.is_satisfied() && rule.quorum_condition.is_satisfied()
            })
            .next()
            .map(|rule| Action::Collect {
                store_in: rule.store_in,
                values: rule.values,
                indices: rule.quorum_condition.available_ids(),
            })
    }

    fn pop_mapping_action(
        &mut self,
        predicate: impl Fn(&SP::Verifier, &MappingRuleKind<SP>) -> Option<Action<SP>>,
    ) -> Option<Action<SP>> {
        let mut result = None;
        let mut rule_idx_to_delete = None;

        for (idx, rule) in &mut self.mapping_rules.iter_mut().enumerate() {
            if !rule.dependencies_condition.is_satisfied() || !rule.scalar_condition.is_satisfied() {
                continue;
            }

            let maybe_id = rule
                .element_conditions
                .iter()
                .find(|(_id, condition)| condition.is_satisfied())
                .map(|(id, _condition)| id.clone());

            if let Some(id) = maybe_id {
                let maybe_action = predicate(&id, &rule.kind);
                if let Some(action) = maybe_action {
                    rule.element_conditions.remove(&id);
                    if rule.element_conditions.is_empty() {
                        rule_idx_to_delete = Some(idx);
                    }
                    result = Some(action);
                    break;
                }
            }
        }

        if let Some(idx) = rule_idx_to_delete {
            self.mapping_rules.remove(idx);
        }

        result
    }

    fn pop_send_action(&mut self) -> Option<Action<SP>> {
        self.pop_mapping_action(|id, kind| {
            if let MappingRuleKind::Send { store_in, to_send } = kind {
                Some(Action::Send {
                    store_in: store_in.clone(),
                    to_send: to_send.clone(),
                    destination: id.clone(),
                })
            } else {
                None
            }
        })
    }

    fn pop_regular_mapping_action(&mut self) -> Option<Action<SP>> {
        self.pop_mapping_action(|id, kind| match kind {
            MappingRuleKind::Send { .. } => None,
            MappingRuleKind::Compute {
                store_in,
                function,
                args,
                on_error,
            } => Some(Action::ComputeMappingElement {
                store_in: store_in.clone(),
                index: id.clone(),
                function: function.clone(),
                args: args.clone(),
                on_error: on_error.clone(),
            }),
            MappingRuleKind::SerializeAndSign {
                store_in,
                function,
                data,
                message_name,
                serde_adapter,
            } => Some(Action::ComputeSerializeAndSignElement {
                store_in: store_in.clone(),
                index: id.clone(),
                function: function.clone(),
                data: data.clone(),
                message_name: message_name.clone(),
                serde_adapter: serde_adapter.clone(),
            }),
            MappingRuleKind::Deserialize {
                store_in,
                function,
                data,
                serde_adapter,
                on_error,
            } => Some(Action::ComputeDeserializeElement {
                store_in: store_in.clone(),
                index: id.clone(),
                function: function.clone(),
                data: data.clone(),
                serde_adapter: serde_adapter.clone(),
                on_error: on_error.clone(),
            }),
        })
    }

    pub fn pop_action(&mut self) -> Result<Option<Action<SP>>, LocalError> {
        if matches!(self.state, State::InProgress) && self.collect_rules.is_empty() && self.scalar_rules.is_empty() {
            return Err(LocalError::new(
                "No rules to apply, and the output value has not been set",
            ));
        }

        Ok(match &self.state {
            // Regular operation: first pop all locally computable actions
            // to have as many values ready to send as possible.
            State::InProgress => self
                .pop_scalar_action()
                .or_else(|| self.pop_collect_action())
                .or_else(|| self.pop_regular_mapping_action())
                .or_else(|| self.pop_send_action()),
            // If we are ready to terminate, pop all send actions first so that we don't stall other nodes,
            // then return the terminating action.
            State::ReachedOutput => self
                .pop_send_action()
                .or_else(|| Some(Action::ReturnOutput(self.output_tag.clone()))),
            State::StalledAt(tag) => {
                let tag = tag.clone();
                self.pop_send_action().or_else(move || Some(Action::Terminate(tag)))
            }
        })
    }

    pub fn expected_messages(&self) -> &BTreeMap<FullName, BTreeSet<SP::Verifier>> {
        &self.expected_messages
    }

    pub fn arguments(&self) -> &BTreeMap<String, ScalarTag> {
        &self.arguments
    }
}

impl<SP: SessionParameters> Display for ScalarRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        if !self.scalar_condition.is_satisfied() {
            writeln!(f, "if {}", self.scalar_condition)?;
        }
        writeln!(
            f,
            "{} = {}({})",
            self.store_in,
            self.function,
            self.args.values().map(ToString::to_string).join(", ")
        )
    }
}

impl<SP: SessionParameters> Display for CollectRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        if !self.quorum_condition.is_satisfied() {
            writeln!(f, "if {}", self.quorum_condition)?;
        }
        writeln!(f, "{} = collect({})", self.store_in, self.values)
    }
}

impl<SP: SessionParameters> Display for MappingRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        if !self.scalar_condition.is_satisfied() {
            writeln!(f, "if {}", self.scalar_condition)?;
        }
        for (id, condition) in self.element_conditions.iter() {
            writeln!(f, "if element-ready({:?}, {})", id, condition)?;
        }
        writeln!(f, "  {}", self.kind)
    }
}

impl<SP: SessionParameters> Display for MappingRuleKind<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Compute {
                store_in,
                function,
                args,
                ..
            } => writeln!(
                f,
                "{store_in} = {function}({})",
                args.values().map(ToString::to_string).join(", ")
            ),
            Self::SerializeAndSign {
                store_in,
                function,
                data,
                ..
            } => writeln!(f, "{store_in} = {function}({data})"),
            Self::Deserialize {
                store_in,
                function,
                data,
                ..
            } => writeln!(f, "{store_in} = {function}({data})"),
            Self::Send { store_in, to_send } => writeln!(f, "{store_in} = send({to_send})"),
        }
    }
}

impl<SP: SessionParameters> Display for Ruleset<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Ruleset:")?;
        for rule in &self.scalar_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.mapping_rules {
            writeln!(f, "{rule}")?;
        }
        Ok(())
    }
}
