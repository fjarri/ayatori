use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};

use itertools::Itertools;

use super::conditions::{
    ElementCondition, ElementConditionWithState, QuorumCondition, QuorumConditionWithState, ScalarCondition,
    ScalarConditionWithState,
};
use crate::{
    entities::{
        AnyTag, AnyTagRef, CollectedTag, ComputedMappingTag, ComputedScalarTag, DeserializeFunction, FullName,
        LocalSignedTag, MappingFunction, MappingTag, MappingTagRef, MergedScalarTag, ReceivedTag, RemoteSignedTag,
        RuntimeError, ScalarArgumentTag, ScalarFunction, ScalarTag, SentTag, SerdeAdapter, SerializeAndSignFunction,
    },
    graph_representation::{AnyNode, ComputeMappingKind, GeneralizedNode, OutputNode, Reproducibility},
    traits::SessionParameters,
};

#[derive_where::derive_where(Debug)]
struct ScalarRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    scalar_condition: ScalarConditionWithState,
    kind: ScalarRuleKind<SP>,
}

#[derive_where::derive_where(Debug, Clone)]
enum ScalarRuleKind<SP: SessionParameters> {
    Compute {
        store_in: ComputedScalarTag,
        function: ScalarFunction<SP>,
        args: BTreeMap<String, ScalarTag>,
    },
    Merge {
        store_in: MergedScalarTag,
        left: ScalarTag,
        right: ScalarTag,
    },
}

#[derive_where::derive_where(Debug)]
struct CollectRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    quorum_condition: QuorumConditionWithState<SP::Verifier>,
    store_in: CollectedTag,
    values: MappingTag,
}

#[derive_where::derive_where(Debug)]
struct MappingRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    scalar_condition: ScalarConditionWithState,
    element_condition: ElementConditionWithState<SP::Verifier>,
    kind: MappingRuleKind<SP>,
}

#[derive_where::derive_where(Debug, Clone)]
enum MappingRuleKind<SP: SessionParameters> {
    Compute {
        store_in: ComputedMappingTag,
        function: MappingFunction<SP>,
        args: BTreeMap<String, AnyTag>,
        on_error: OnError,
    },
    SerializeAndSign {
        store_in: LocalSignedTag,
        function: SerializeAndSignFunction<SP>,
        data: AnyTag,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    Deserialize {
        store_in: ReceivedTag,
        function: DeserializeFunction<SP>,
        data: RemoteSignedTag,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        on_error: OnError,
    },
}

#[derive_where::derive_where(Debug)]
struct SendRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    scalar_condition: ScalarConditionWithState,
    element_condition: ElementConditionWithState<SP::Verifier>,
    store_in: SentTag,
    to_send: LocalSignedTag,
}

#[derive(Debug, Clone)]
pub(crate) enum OnError {
    CollectEvidence(BTreeSet<FullName>),
    Escalate,
}

#[derive_where::derive_where(Debug)]
pub(crate) enum Action<SP: SessionParameters> {
    ComputeScalar {
        store_in: ComputedScalarTag,
        function: ScalarFunction<SP>,
        args: BTreeMap<String, ScalarTag>,
    },
    ComputeMappingElement {
        store_in: ComputedMappingTag,
        index: SP::Verifier,
        function: MappingFunction<SP>,
        args: BTreeMap<String, AnyTag>,
        on_error: OnError,
    },
    ComputeSerializeAndSignElement {
        store_in: LocalSignedTag,
        index: SP::Verifier,
        function: SerializeAndSignFunction<SP>,
        data: AnyTag,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    ComputeDeserializeElement {
        store_in: ReceivedTag,
        index: SP::Verifier,
        function: DeserializeFunction<SP>,
        data: RemoteSignedTag,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        on_error: OnError,
    },
    DirectMessage {
        store_in: SentTag,
        to_send: LocalSignedTag,
        destination: SP::Verifier,
    },
    Collect {
        store_in: CollectedTag,
        values: MappingTag,
        indices: BTreeSet<SP::Verifier>,
    },
    MergeScalar {
        store_in: MergedScalarTag,
        left: ScalarTag,
        right: ScalarTag,
    },
}

fn get_on_error<SP: SessionParameters, T>(node: &T, private_inputs: &BTreeSet<String>) -> OnError
where
    T: Into<AnyNode<SP>> + GeneralizedNode,
{
    let any_node: AnyNode<SP> = node.get_strong_ref().into();
    match any_node.reproducibility() {
        Reproducibility::Available { arguments, messages } => {
            if !arguments.is_disjoint(private_inputs) {
                return OnError::Escalate;
            }
            OnError::CollectEvidence(messages)
        }
        Reproducibility::NotAvailable => OnError::Escalate,
    }
}

/// Contains the specific IDs for which every mapping-type node needs to be calculated for,
/// based on collect-type nodes that consume it.
struct PropagatedGroups<SP: SessionParameters>(BTreeMap<MappingTag, BTreeSet<SP::Verifier>>);

impl<SP: SessionParameters> PropagatedGroups<SP> {
    fn empty() -> Self {
        Self(BTreeMap::new())
    }

    fn insert(&mut self, tag: MappingTagRef<'_>, ids: BTreeSet<SP::Verifier>) {
        self.0.entry(tag.to_owned()).or_default().extend(ids);
    }

    fn get(&self, tag: MappingTagRef<'_>) -> Result<&BTreeSet<SP::Verifier>, RuntimeError> {
        self.0
            .get(&tag.to_owned())
            .ok_or_else(|| RuntimeError::expect("The required IDs were propagated to this node"))
    }

    fn new(root: &AnyNode<SP>) -> Result<Self, RuntimeError> {
        let mut result = Self::empty();

        for node in root.flattened_roots_first() {
            match node {
                AnyNode::ScalarArgument(_)
                | AnyNode::MergeScalars(_)
                | AnyNode::ComputeScalar(_)
                | AnyNode::Receive(_) => {}
                AnyNode::ComputeMapping(node) => {
                    let ids = result.get(MappingTagRef::Computed(&node.as_ref().store_in))?.clone();
                    for arg in node.as_ref().args.values() {
                        if let AnyTagRef::Mapping(tag) = arg.store_in() {
                            result.insert(tag, ids.clone());
                        }
                    }

                    match &node.as_ref().kind {
                        ComputeMappingKind::Simple { .. } | ComputeMappingKind::ThirdPartyAttributable { .. } => {}
                        ComputeMappingKind::WithReveal { verification_args, .. } => {
                            for arg in verification_args.values() {
                                if let AnyTagRef::Mapping(tag) = arg.store_in() {
                                    result.insert(tag, ids.clone());
                                }
                            }
                        }
                    }
                }
                AnyNode::SerializeAndSign(node) => {
                    let ids = result.get(MappingTagRef::LocalSigned(&node.as_ref().store_in))?.clone();
                    if let AnyTagRef::Mapping(tag) = node.as_ref().data.store_in() {
                        result.insert(tag, ids);
                    }
                }
                AnyNode::DeserializeAndCheck(node) => {
                    let ids = result.get(MappingTagRef::Received(&node.as_ref().store_in))?.clone();
                    result.insert(MappingTagRef::RemoteSigned(&node.as_ref().data.as_ref().store_in), ids);
                }
                AnyNode::DirectMessage(node) => {
                    let ids = result.get(MappingTagRef::Sent(&node.as_ref().store_in))?.clone();
                    result.insert(MappingTagRef::LocalSigned(&node.as_ref().data.as_ref().store_in), ids);
                }
                AnyNode::Collect(node) => {
                    result.insert(
                        node.as_ref().values.store_in(),
                        node.as_ref().group.ids().cloned().collect(),
                    );
                }
            }
        }

        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RulesetState {
    InProgress,
    ReachedOutput,
    StalledAt(CollectedTag),
}

#[derive(Debug)]
pub(crate) struct Ruleset<SP: SessionParameters> {
    output_tag: ComputedScalarTag,
    scalar_rules: Vec<ScalarRule<SP>>,
    collect_rules: Vec<CollectRule<SP>>,
    mapping_rules: Vec<MappingRule<SP>>,
    send_rules: Vec<SendRule<SP>>,
    expected_messages: BTreeMap<FullName, BTreeSet<SP::Verifier>>,
    arguments: BTreeMap<String, ScalarArgumentTag>,
    state: RulesetState,
}

impl<SP: SessionParameters> Ruleset<SP> {
    pub fn new(output_node: &OutputNode<SP>, private_inputs: &BTreeSet<String>) -> Result<Self, RuntimeError> {
        let output_tag = output_node.store_in();

        let propagated_groups = PropagatedGroups::new(&AnyNode::from(output_node.get_strong_ref()))?;

        let mut scalar_rules = Vec::new();
        let mut collect_rules = Vec::new();
        let mut mapping_rules = Vec::new();
        let mut send_rules = Vec::new();
        let mut expected_messages = BTreeMap::new();

        let mut arguments = BTreeMap::new();

        // Nodes can be iterated in any order here, but we do leaves first to make the sequence of rules more logical
        // in case someone has to look at it during debugging.
        for node in AnyNode::from(output_node.get_strong_ref()).flattened_leaves_first() {
            let dependencies_condition =
                ScalarConditionWithState::new(ScalarCondition::from_dependencies(node.dependencies()));
            match node {
                AnyNode::ScalarArgument(node) => {
                    let node = node.as_ref();
                    arguments.insert(node.name.clone(), node.store_in.clone());
                }
                AnyNode::ComputeScalar(node) => {
                    let node = node.as_ref();
                    let scalar_condition = ScalarCondition::from_compute_scalar(node);

                    let arg_tags = node
                        .args
                        .iter()
                        .map(|(name, arg)| {
                            let arg = arg.store_in().to_owned();
                            (name.clone(), arg)
                        })
                        .collect();

                    scalar_rules.push(ScalarRule {
                        dependencies_condition,
                        scalar_condition: ScalarConditionWithState::new(scalar_condition),
                        kind: ScalarRuleKind::Compute {
                            store_in: node.store_in.clone(),
                            function: node.function.clone(),
                            args: arg_tags,
                        },
                    });
                }
                AnyNode::ComputeMapping(node) => {
                    let on_error = get_on_error(&node, private_inputs);
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(MappingTagRef::Computed(&node.store_in))?;

                    let scalar_condition = ScalarCondition::from_compute_mapping(node);
                    let element_condition = ElementCondition::from_compute_mapping(node);

                    let function = match &node.kind {
                        ComputeMappingKind::Simple { function } => MappingFunction::from(function.clone()),
                        ComputeMappingKind::WithReveal { function, .. } => {
                            MappingFunction::SenderAttributableWithReveal(function.clone())
                        }
                        ComputeMappingKind::ThirdPartyAttributable { function, .. } => {
                            MappingFunction::ThirdPartyAttributable(function.clone())
                        }
                    };

                    let arg_tags = node
                        .args
                        .iter()
                        .map(|(name, arg)| {
                            let arg = arg.store_in().to_owned();
                            (name.clone(), arg)
                        })
                        .collect();

                    mapping_rules.push(MappingRule {
                        dependencies_condition,
                        scalar_condition: ScalarConditionWithState::new(scalar_condition),
                        element_condition: ElementConditionWithState::new(element_condition, possible_ids),
                        kind: MappingRuleKind::Compute {
                            store_in: node.store_in.clone(),
                            function,
                            args: arg_tags,
                            on_error: on_error.clone(),
                        },
                    });
                }
                AnyNode::SerializeAndSign(node) => {
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(MappingTagRef::LocalSigned(&node.store_in))?;

                    let scalar_condition = ScalarCondition::from_serialize_and_sign(node);
                    let element_condition = ElementCondition::from_serialize_and_sign(node);

                    mapping_rules.push(MappingRule {
                        dependencies_condition,
                        scalar_condition: ScalarConditionWithState::new(scalar_condition),
                        element_condition: ElementConditionWithState::new(element_condition, possible_ids),
                        kind: MappingRuleKind::SerializeAndSign {
                            store_in: node.store_in.clone(),
                            function: node.function.clone(),
                            data: node.data.store_in().to_owned(),
                            message_name: node.message_name.clone(),
                            serde_adapter: node.serde_adapter.clone(),
                        },
                    });
                }
                AnyNode::DeserializeAndCheck(node) => {
                    let on_error = get_on_error(&node, private_inputs);
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(MappingTagRef::Received(&node.store_in))?;

                    let element_condition = ElementCondition::from_deserialize_and_check(node);

                    mapping_rules.push(MappingRule {
                        dependencies_condition,
                        scalar_condition: ScalarConditionWithState::new(ScalarCondition::empty()),
                        element_condition: ElementConditionWithState::new(element_condition, possible_ids),
                        kind: MappingRuleKind::Deserialize {
                            store_in: node.store_in.clone(),
                            function: node.function.clone(),
                            data: node.data.as_ref().store_in.clone(),
                            message_name: node.message_name.clone(),
                            serde_adapter: node.serde_adapter.clone(),
                            on_error,
                        },
                    });
                }
                AnyNode::DirectMessage(node) => {
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(MappingTagRef::Sent(&node.store_in))?;

                    let element_condition = ElementCondition::from_direct_message(node);

                    send_rules.push(SendRule {
                        dependencies_condition,
                        scalar_condition: ScalarConditionWithState::new(ScalarCondition::empty()),
                        element_condition: ElementConditionWithState::new(element_condition, possible_ids),
                        store_in: node.store_in.clone(),
                        to_send: node.data.as_ref().store_in.clone(),
                    });
                }
                AnyNode::Collect(node) => {
                    let node = node.as_ref();
                    let quorum_condition = QuorumCondition::from_collect(node);
                    collect_rules.push(CollectRule {
                        dependencies_condition,
                        quorum_condition: QuorumConditionWithState::new(quorum_condition),
                        store_in: node.store_in.clone(),
                        values: node.values.store_in().to_owned(),
                    });
                }
                AnyNode::Receive(node) => {
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(MappingTagRef::RemoteSigned(&node.store_in))?;
                    expected_messages.insert(node.message_name.clone(), possible_ids.clone());
                }
                AnyNode::MergeScalars(node) => {
                    let node = node.as_ref();
                    let scalar_condition = ScalarCondition::from_merged_scalar(node);
                    scalar_rules.push(ScalarRule {
                        dependencies_condition,
                        scalar_condition: ScalarConditionWithState::new(scalar_condition),
                        kind: ScalarRuleKind::Merge {
                            store_in: node.store_in.clone(),
                            left: node.left.store_in().to_owned(),
                            right: node.right.store_in().to_owned(),
                        },
                    });
                }
            }
        }

        Ok(Self {
            output_tag: output_tag.clone(),
            scalar_rules,
            collect_rules,
            mapping_rules,
            send_rules,
            expected_messages,
            arguments,
            state: RulesetState::InProgress,
        })
    }

    pub fn update_with_banned_party(&mut self, id: &SP::Verifier) {
        for rule in &mut self.collect_rules {
            rule.quorum_condition.update_with_banned_party(id);
            if !rule.quorum_condition.is_satisfiable() {
                self.state = RulesetState::StalledAt(rule.store_in.clone());
            }
        }
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        if let ScalarTag::Computed(computed_tag) = tag
            && computed_tag == &self.output_tag
        {
            self.state = RulesetState::ReachedOutput;
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

        for rule in &mut self.send_rules {
            rule.dependencies_condition.update_with_scalar_ready(tag);
            rule.scalar_condition.update_with_scalar_ready(tag);
        }
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &SP::Verifier) {
        for rule in &mut self.collect_rules {
            rule.quorum_condition.update_with_element_ready(tag, id);
        }

        for rule in &mut self.mapping_rules {
            rule.element_condition.update_with_element_ready(tag, id);
        }

        for rule in &mut self.send_rules {
            rule.element_condition.update_with_element_ready(tag, id);
        }
    }

    fn pop_scalar_action(&mut self) -> Option<Action<SP>> {
        self.scalar_rules
            .extract_if(.., |rule| {
                rule.dependencies_condition.is_satisfied() && rule.scalar_condition.is_satisfied()
            })
            .next()
            .map(|rule| match rule.kind {
                ScalarRuleKind::Compute {
                    store_in,
                    function,
                    args,
                } => Action::ComputeScalar {
                    store_in,
                    function,
                    args,
                },
                ScalarRuleKind::Merge { store_in, left, right } => Action::MergeScalar { store_in, left, right },
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

    fn pop_send_action(&mut self) -> Option<Action<SP>> {
        for rule in &mut self.send_rules.iter_mut() {
            if !rule.dependencies_condition.is_satisfied() || !rule.scalar_condition.is_satisfied() {
                continue;
            }

            if let Some(id) = rule.element_condition.pop_satisfied() {
                return Some(Action::DirectMessage {
                    store_in: rule.store_in.clone(),
                    to_send: rule.to_send.clone(),
                    destination: id,
                });
            }
        }

        None
    }

    fn pop_mapping_action(&mut self) -> Option<Action<SP>> {
        for rule in &mut self.mapping_rules.iter_mut() {
            if !rule.dependencies_condition.is_satisfied() || !rule.scalar_condition.is_satisfied() {
                continue;
            }

            if let Some(id) = rule.element_condition.pop_satisfied() {
                return Some(match &rule.kind {
                    MappingRuleKind::Compute {
                        store_in,
                        function,
                        args,
                        on_error,
                    } => Action::ComputeMappingElement {
                        store_in: store_in.clone(),
                        index: id.clone(),
                        function: function.clone(),
                        args: args.clone(),
                        on_error: on_error.clone(),
                    },
                    MappingRuleKind::SerializeAndSign {
                        store_in,
                        function,
                        data,
                        message_name,
                        serde_adapter,
                    } => Action::ComputeSerializeAndSignElement {
                        store_in: store_in.clone(),
                        index: id.clone(),
                        function: function.clone(),
                        data: data.clone(),
                        message_name: message_name.clone(),
                        serde_adapter: serde_adapter.clone(),
                    },
                    MappingRuleKind::Deserialize {
                        store_in,
                        function,
                        data,
                        message_name,
                        serde_adapter,
                        on_error,
                    } => Action::ComputeDeserializeElement {
                        store_in: store_in.clone(),
                        index: id.clone(),
                        function: function.clone(),
                        data: data.clone(),
                        message_name: message_name.clone(),
                        serde_adapter: serde_adapter.clone(),
                        on_error: on_error.clone(),
                    },
                });
            }
        }

        None
    }

    pub fn pop_action(&mut self) -> Result<Option<Action<SP>>, RuntimeError> {
        if matches!(self.state, RulesetState::InProgress)
            && self.collect_rules.is_empty()
            && self.scalar_rules.is_empty()
        {
            return Err(RuntimeError::new(
                "No rules to apply, and the output value has not been set",
            ));
        }

        Ok(self
            .pop_scalar_action()
            .or_else(|| self.pop_collect_action())
            .or_else(|| self.pop_mapping_action())
            .or_else(|| self.pop_send_action()))
    }

    pub fn expected_messages(&self) -> &BTreeMap<FullName, BTreeSet<SP::Verifier>> {
        &self.expected_messages
    }

    pub fn arguments(&self) -> &BTreeMap<String, ScalarArgumentTag> {
        &self.arguments
    }

    pub fn state(&self) -> &RulesetState {
        &self.state
    }

    pub fn output_tag(&self) -> &ComputedScalarTag {
        &self.output_tag
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
        match &self.kind {
            ScalarRuleKind::Compute {
                store_in,
                function,
                args,
            } => writeln!(
                f,
                "  {store_in} = {function}({})",
                args.values().map(ToString::to_string).join(", ")
            ),
            ScalarRuleKind::Merge { store_in, left, right } => writeln!(f, "  {store_in} = {left} | {right}"),
        }
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
        writeln!(f, "  {} = collect({})", self.store_in, self.values)
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
        writeln!(f, "if {})", self.element_condition)?;
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
        }
    }
}

impl<SP: SessionParameters> Display for SendRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        if !self.scalar_condition.is_satisfied() {
            writeln!(f, "if {}", self.scalar_condition)?;
        }
        writeln!(f, "if {})", self.element_condition)?;
        writeln!(f, "  {} = direct_message({})", self.store_in, self.to_send)
    }
}

impl<SP: SessionParameters> Display for Ruleset<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Mapping rules:")?;
        for rule in &self.mapping_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.send_rules {
            writeln!(f, "{rule}")?;
        }

        writeln!(f, "Scalar rules:")?;
        for rule in &self.scalar_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.collect_rules {
            writeln!(f, "{rule}")?;
        }
        Ok(())
    }
}
