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
struct ComputeScalarRule<SP: SessionParameters> {
    dependencies: ScalarCondition,
    condition: ScalarCondition,
    store_in: ScalarTag,
    function: ScalarFunction<SP>,
    args: BTreeMap<String, ScalarTag>,
}

#[derive_where::derive_where(Debug)]
struct ComputeMappingRule<SP: SessionParameters> {
    dependencies: ScalarCondition,
    scalar_condition: ScalarCondition,
    element_conditions: BTreeMap<SP::Verifier, ElementCondition>,
    store_in: MappingTag,
    function: MappingFunction<SP>,
    args: BTreeMap<String, AnyTag>,
    on_error: OnError,
}

#[derive_where::derive_where(Debug)]
struct ComputeSerializeAndSignRule<SP: SessionParameters> {
    dependencies: ScalarCondition,
    scalar_condition: ScalarCondition,
    element_conditions: BTreeMap<SP::Verifier, ElementCondition>,
    store_in: MappingTag,
    function: SerializeAndSignFunction<SP>,
    data: AnyTag,
    message_name: FullName,
    serde_adapter: SerdeAdapter<SP::WireFormat>,
}

#[derive_where::derive_where(Debug)]
struct ComputeDeserializeRule<SP: SessionParameters> {
    dependencies: ScalarCondition,
    element_conditions: BTreeMap<SP::Verifier, ElementCondition>,
    store_in: MappingTag,
    function: DeserializeFunction<SP>,
    data: MappingTag,
    message_name: FullName,
    serde_adapter: SerdeAdapter<SP::WireFormat>,
    on_error: OnError,
}

#[derive_where::derive_where(Debug)]
struct SendRule<SP: SessionParameters> {
    dependencies: ScalarCondition,
    element_conditions: BTreeMap<SP::Verifier, ElementCondition>,
    store_in: MappingTag,
    to_send: MappingTag,
}

#[derive_where::derive_where(Debug)]
struct CollectRule<SP: SessionParameters> {
    dependencies: ScalarCondition,
    condition: QuorumCondition<SP::Verifier>,
    store_in: ScalarTag,
    values: MappingTag,
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
        message_name: FullName,
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

#[derive(Debug)]
enum State {
    InProgress,
    ReachedOutput,
    StalledAt(ScalarTag),
}

#[derive(Debug)]
pub(crate) struct Ruleset<SP: SessionParameters> {
    output_tag: ScalarTag,
    compute_scalar_rules: Vec<ComputeScalarRule<SP>>,
    compute_mapping_rules: Vec<ComputeMappingRule<SP>>,
    compute_serialize_and_sign_rules: Vec<ComputeSerializeAndSignRule<SP>>,
    compute_deserialize_rules: Vec<ComputeDeserializeRule<SP>>,
    send_rules: Vec<SendRule<SP>>,
    collect_rules: Vec<CollectRule<SP>>,
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

        let mut compute_scalar_rules = Vec::new();
        let mut compute_mapping_rules = Vec::new();
        let mut compute_serialize_and_sign_rules = Vec::new();
        let mut compute_deserialize_rules = Vec::new();
        let mut send_rules = Vec::new();
        let mut collect_rules = Vec::new();
        let mut expected_messages = BTreeMap::new();

        let mut arguments = BTreeMap::new();

        for node in output_node.flattened() {
            let mut dependencies = ScalarCondition::empty();

            for dependency in node.dependencies() {
                let tag = dependency
                    .store_in()
                    .scalar()
                    .ok_or_else(|| LocalError::new("Assumption: Only scalar nodes are allowed as dependencies"))?;
                dependencies = dependencies.and(tag);
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
                    let mut condition = ScalarCondition::empty();
                    for (name, arg) in args {
                        let tag = arg.store_in().scalar().ok_or_else(|| {
                            LocalError::new(
                                "Assumption: Only scalar nodes are allowed as arguments to scalar functions",
                            )
                        })?;
                        condition = condition.and(tag);
                        arg_tags.insert(name.clone(), tag.clone());
                    }
                    compute_scalar_rules.push(ComputeScalarRule {
                        dependencies,
                        condition,
                        store_in: store_in.clone(),
                        function: function.clone(),
                        args: arg_tags,
                    });
                }
                NodeKind::ComputeMapping {
                    store_in,
                    function,
                    args,
                    group,
                } => {
                    let on_error = get_on_error(&node, private_inputs);

                    let possible_ids = group.ids().cloned().collect::<BTreeSet<_>>();
                    let mut scalar_condition = ScalarCondition::empty();
                    let mut element_condition = ElementCondition::empty();
                    for arg in args.values() {
                        match arg.store_in() {
                            // TODO (#68): we're assuming here that `arg.group()` is a superset of `group`.
                            // Review this when fixing #68.
                            AnyTagRef::Mapping(tag) => element_condition = element_condition.and(tag),
                            AnyTagRef::Scalar(tag) => scalar_condition = scalar_condition.and(tag),
                        };
                    }

                    let element_conditions = possible_ids
                        .into_iter()
                        .map(|id| (id, element_condition.clone()))
                        .collect();

                    let arg_tags = args
                        .iter()
                        .map(|(name, arg)| {
                            let arg = arg.store_in().to_owned();
                            (name.clone(), arg)
                        })
                        .collect();

                    compute_mapping_rules.push(ComputeMappingRule {
                        dependencies,
                        scalar_condition,
                        element_conditions,
                        store_in: store_in.clone(),
                        function: function.clone(),
                        args: arg_tags,
                        on_error: on_error.clone(),
                    })
                }
                NodeKind::SerializeAndSign {
                    store_in,
                    function,
                    data,
                    group,
                    message_name,
                    serde_adapter,
                } => {
                    let possible_ids = group.ids().cloned().collect::<BTreeSet<_>>();

                    let tag = data.store_in();

                    let mut scalar_condition = ScalarCondition::empty();
                    let mut element_condition = ElementCondition::empty();

                    match tag {
                        AnyTagRef::Scalar(tag) => scalar_condition = scalar_condition.and(tag),
                        AnyTagRef::Mapping(tag) => element_condition = element_condition.and(tag),
                    }

                    let element_conditions = possible_ids
                        .into_iter()
                        .map(|id| (id, element_condition.clone()))
                        .collect();

                    compute_serialize_and_sign_rules.push(ComputeSerializeAndSignRule {
                        dependencies,
                        scalar_condition,
                        element_conditions,
                        store_in: store_in.clone(),
                        function: function.clone(),
                        data: tag.to_owned(),
                        message_name: message_name.clone(),
                        serde_adapter: serde_adapter.clone(),
                    })
                }
                NodeKind::Deserialize {
                    store_in,
                    function,
                    data,
                    group,
                    message_name,
                    serde_adapter,
                } => {
                    let on_error = get_on_error(&node, private_inputs);

                    let possible_ids = group.ids().cloned().collect::<BTreeSet<_>>();

                    let tag = data
                        .store_in()
                        .mapping()
                        .ok_or_else(|| LocalError::new("Assumption: Deserialize is expected to take mapping data"))?;

                    let element_condition = ElementCondition::empty().and(tag);
                    let element_conditions = possible_ids
                        .into_iter()
                        .map(|id| (id, element_condition.clone()))
                        .collect();

                    compute_deserialize_rules.push(ComputeDeserializeRule {
                        dependencies,
                        element_conditions,
                        store_in: store_in.clone(),
                        function: function.clone(),
                        data: tag.clone(),
                        message_name: message_name.clone(),
                        serde_adapter: serde_adapter.clone(),
                        on_error,
                    })
                }
                NodeKind::DirectMessage { store_in, data, group } => {
                    let possible_ids = group.ids().cloned().collect::<BTreeSet<_>>();

                    let tag = data.store_in().mapping().ok_or_else(|| {
                        LocalError::new("Assumption: DirectMessage node is expected to send mapping data")
                    })?;
                    let element_condition = ElementCondition::empty().and(tag);
                    let element_conditions = possible_ids
                        .into_iter()
                        .map(|id| (id, element_condition.clone()))
                        .collect();
                    send_rules.push(SendRule {
                        dependencies,
                        element_conditions,
                        store_in: store_in.clone(),
                        to_send: tag.clone(),
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
                    let condition = QuorumCondition::new(tag, group);
                    collect_rules.push(CollectRule {
                        dependencies,
                        condition,
                        store_in: store_in.clone(),
                        values: tag.clone(),
                    });
                }
                NodeKind::Receive {
                    store_in: _store_in,
                    group,
                    message_name,
                    serde_adapter: _serde_adapter,
                } => {
                    expected_messages.insert(message_name.clone(), group.ids().cloned().collect());
                }
            };
        }

        Ok(Self {
            output_tag,
            compute_scalar_rules,
            compute_mapping_rules,
            compute_serialize_and_sign_rules,
            compute_deserialize_rules,
            send_rules,
            collect_rules,
            expected_messages,
            arguments,
            state: State::InProgress,
        })
    }

    pub fn update_with_banned_party(&mut self, id: &SP::Verifier) {
        for rule in &mut self.collect_rules {
            rule.condition.update_with_banned_party(id);
        }

        for rule in &self.collect_rules {
            if !rule.condition.is_satisfiable() {
                self.state = State::StalledAt(rule.store_in.clone());
            }
        }
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        if tag == &self.output_tag {
            self.state = State::ReachedOutput;
        }

        for rule in &mut self.compute_scalar_rules {
            rule.dependencies.update_with_scalar_ready(tag);
            rule.condition.update_with_scalar_ready(tag);
        }

        for rule in &mut self.compute_mapping_rules {
            rule.dependencies.update_with_scalar_ready(tag);
            rule.scalar_condition.update_with_scalar_ready(tag);
        }

        for rule in &mut self.compute_serialize_and_sign_rules {
            rule.dependencies.update_with_scalar_ready(tag);
            rule.scalar_condition.update_with_scalar_ready(tag);
        }

        for rule in &mut self.compute_deserialize_rules {
            rule.dependencies.update_with_scalar_ready(tag);
        }

        for rule in &mut self.send_rules {
            rule.dependencies.update_with_scalar_ready(tag);
        }

        for rule in &mut self.collect_rules {
            rule.dependencies.update_with_scalar_ready(tag);
        }
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &SP::Verifier) {
        for rule in &mut self.compute_mapping_rules {
            if let Some(condition) = rule.element_conditions.get_mut(id) {
                condition.update_with_scalar_ready(tag)
            }
        }

        for rule in &mut self.compute_serialize_and_sign_rules {
            if let Some(condition) = rule.element_conditions.get_mut(id) {
                condition.update_with_scalar_ready(tag)
            }
        }

        for rule in &mut self.compute_deserialize_rules {
            if let Some(condition) = rule.element_conditions.get_mut(id) {
                condition.update_with_scalar_ready(tag)
            }
        }

        for rule in &mut self.send_rules {
            if let Some(condition) = rule.element_conditions.get_mut(id) {
                condition.update_with_scalar_ready(tag)
            }
        }

        for rule in &mut self.collect_rules {
            rule.condition.update_with_element_ready(tag, id);
        }
    }

    fn pop_send_action(&mut self) -> Option<Action<SP>> {
        let mut action = None;

        for rule in &mut self.send_rules {
            if !rule.dependencies.is_satisfied() {
                continue;
            }

            action = rule
                .element_conditions
                .extract_if(.., |_id, condition| condition.is_satisfied())
                .next()
                .map(|(id, _condition)| Action::Send {
                    store_in: rule.store_in.clone(),
                    to_send: rule.to_send.clone(),
                    destination: id,
                });

            if action.is_some() {
                break;
            }
        }

        // TODO (#68): this may need to be removed after #68 is fixed, because compute-mapping rules
        // won't track the IDs for which they were completed.
        // If not, it needs to be optimized to not look through the whole list,
        // but only at the rule which produced the action.
        if action.is_some() {
            self.send_rules.retain(|rule| !rule.element_conditions.is_empty());
        }

        action
    }

    fn pop_compute_scalar_action(&mut self) -> Option<Action<SP>> {
        self.compute_scalar_rules
            .extract_if(.., |rule| {
                rule.dependencies.is_satisfied() && rule.condition.is_satisfied()
            })
            .next()
            .map(|rule| Action::ComputeScalar {
                store_in: rule.store_in,
                function: rule.function,
                args: rule.args,
            })
    }

    fn pop_compute_element_action(&mut self) -> Option<Action<SP>> {
        let mut action = None;
        for rule in &mut self.compute_mapping_rules {
            if !rule.dependencies.is_satisfied() || !rule.scalar_condition.is_satisfied() {
                continue;
            }

            action = rule
                .element_conditions
                .extract_if(.., |_id, condition| condition.is_satisfied())
                .next()
                .map(|(id, _condition)| Action::ComputeMappingElement {
                    store_in: rule.store_in.clone(),
                    index: id,
                    function: rule.function.clone(),
                    args: rule.args.clone(),
                    on_error: rule.on_error.clone(),
                });

            if action.is_some() {
                break;
            }
        }

        // TODO (#68): this may need to be removed after #68 is fixed, because compute-mapping rules
        // won't track the IDs for which they were completed.
        // If not, it needs to be optimized to not look through the whole list,
        // but only at the rule which produced the action.
        if action.is_some() {
            self.compute_mapping_rules
                .retain(|rule| !rule.element_conditions.is_empty());
        }

        action
    }

    fn pop_serialize_and_sign_action(&mut self) -> Option<Action<SP>> {
        let mut action = None;
        for rule in &mut self.compute_serialize_and_sign_rules {
            if !rule.dependencies.is_satisfied() || !rule.scalar_condition.is_satisfied() {
                continue;
            }

            action = rule
                .element_conditions
                .extract_if(.., |_id, condition| condition.is_satisfied())
                .next()
                .map(|(id, _condition)| Action::ComputeSerializeAndSignElement {
                    store_in: rule.store_in.clone(),
                    index: id,
                    function: rule.function.clone(),
                    data: rule.data.clone(),
                    message_name: rule.message_name.clone(),
                    serde_adapter: rule.serde_adapter.clone(),
                });

            if action.is_some() {
                break;
            }
        }

        // TODO (#68): this may need to be removed after #68 is fixed, because compute-mapping rules
        // won't track the IDs for which they were completed.
        // If not, it needs to be optimized to not look through the whole list,
        // but only at the rule which produced the action.
        if action.is_some() {
            self.compute_serialize_and_sign_rules
                .retain(|rule| !rule.element_conditions.is_empty());
        }

        action
    }

    fn pop_deserialize_action(&mut self) -> Option<Action<SP>> {
        let mut action = None;
        for rule in &mut self.compute_deserialize_rules {
            if !rule.dependencies.is_satisfied() {
                continue;
            }

            action = rule
                .element_conditions
                .extract_if(.., |_id, condition| condition.is_satisfied())
                .next()
                .map(|(id, _condition)| Action::ComputeDeserializeElement {
                    store_in: rule.store_in.clone(),
                    index: id,
                    function: rule.function.clone(),
                    data: rule.data.clone(),
                    message_name: rule.message_name.clone(),
                    serde_adapter: rule.serde_adapter.clone(),
                    on_error: rule.on_error.clone(),
                });

            if action.is_some() {
                break;
            }
        }

        // TODO (#68): this may need to be removed after #68 is fixed, because compute-mapping rules
        // won't track the IDs for which they were completed.
        // If not, it needs to be optimized to not look through the whole list,
        // but only at the rule which produced the action.
        if action.is_some() {
            self.compute_deserialize_rules
                .retain(|rule| !rule.element_conditions.is_empty());
        }

        action
    }

    fn pop_collect_action(&mut self) -> Option<Action<SP>> {
        self.collect_rules
            .extract_if(.., |rule| {
                rule.dependencies.is_satisfied() && rule.condition.is_satisfied()
            })
            .next()
            .map(|rule| Action::Collect {
                store_in: rule.store_in,
                values: rule.values,
                indices: rule.condition.available_ids(),
            })
    }

    pub fn pop_action(&mut self) -> Result<Option<Action<SP>>, LocalError> {
        if matches!(self.state, State::InProgress)
            && self.compute_scalar_rules.is_empty()
            && self.collect_rules.is_empty()
        {
            return Err(LocalError::new(
                "No rules to apply, and the output value has not been set",
            ));
        }

        Ok(match &self.state {
            // Regular operation: first pop all locally computable actions
            // to have as many values ready to send as possible.
            State::InProgress => self
                .pop_compute_scalar_action()
                .or_else(|| self.pop_compute_element_action())
                .or_else(|| self.pop_serialize_and_sign_action())
                .or_else(|| self.pop_deserialize_action())
                .or_else(|| self.pop_collect_action())
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

impl<SP: SessionParameters> Display for ComputeScalarRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies.is_satisfied() {
            writeln!(f, "if {}", self.dependencies)?;
        }
        if !self.condition.is_satisfied() {
            writeln!(f, "if {}", self.condition)?;
        }
        writeln!(
            f,
            "  {} = {}({})",
            self.store_in,
            self.function,
            self.args.values().map(ToString::to_string).join(", ")
        )
    }
}

impl<SP: SessionParameters> Display for ComputeMappingRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies.is_satisfied() {
            writeln!(f, "if {}", self.dependencies)?;
        }
        if !self.scalar_condition.is_satisfied() {
            writeln!(f, "if {}", self.scalar_condition)?;
        }
        for (id, condition) in self.element_conditions.iter() {
            writeln!(f, "if element-ready({:?}, {})", id, condition)?;
        }
        writeln!(
            f,
            "  {} = {}({})",
            self.store_in,
            self.function,
            self.args.values().map(ToString::to_string).join(", ")
        )
    }
}

impl<SP: SessionParameters> Display for ComputeSerializeAndSignRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies.is_satisfied() {
            writeln!(f, "if {}", self.dependencies)?;
        }
        if !self.scalar_condition.is_satisfied() {
            writeln!(f, "if {}", self.scalar_condition)?;
        }
        for (id, condition) in self.element_conditions.iter() {
            writeln!(f, "if element-ready({:?}, {})", id, condition)?;
        }
        writeln!(f, "  {} = {}({})", self.store_in, self.function, self.data)
    }
}

impl<SP: SessionParameters> Display for ComputeDeserializeRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies.is_satisfied() {
            writeln!(f, "if {}", self.dependencies)?;
        }
        for (id, condition) in self.element_conditions.iter() {
            writeln!(f, "if element-ready({:?}, {})", id, condition)?;
        }
        writeln!(f, "  {} = {}({})", self.store_in, self.function, self.data)
    }
}

impl<SP: SessionParameters> Display for SendRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies.is_satisfied() {
            writeln!(f, "if {}", self.dependencies)?;
        }
        for (id, condition) in self.element_conditions.iter() {
            writeln!(f, "if element-ready({:?}, {})", id, condition)?;
        }
        writeln!(f, "  {} = send({})", self.store_in, self.to_send)
    }
}

impl<SP: SessionParameters> Display for CollectRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies.is_satisfied() {
            writeln!(f, "if {}", self.dependencies)?;
        }
        writeln!(f, "if {}", self.condition)?;
        writeln!(f, "  {} = collect({})", self.store_in, self.values)
    }
}

impl<SP: SessionParameters> Display for Ruleset<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Ruleset:")?;
        for rule in &self.compute_scalar_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.compute_mapping_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.compute_serialize_and_sign_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.compute_deserialize_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.collect_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.send_rules {
            writeln!(f, "{rule}")?;
        }
        Ok(())
    }
}
