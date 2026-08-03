use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::fmt::{self, Display};

use super::{
    actions::Action,
    rules::{CollectRule, MappingRule, OnError, ScalarRule, SendBCRule, SendDMRule},
};
use crate::{
    entities::{AnyTagRef, ComputedScalarTag, MappingTag, RuntimeError, ScalarArgumentTag, ScalarTag},
    graph_representation::{AnyNode, GeneralizedNode, OutputNode, Reproducibility},
    traits::SessionParameters,
};

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

    fn insert(&mut self, tag: impl Into<MappingTag>, ids: &BTreeSet<SP::Verifier>) {
        self.0.entry(tag.into()).or_default().extend(ids.iter().cloned());
    }

    fn get(&self, tag: &(impl Display + Clone + Into<MappingTag>)) -> Result<&BTreeSet<SP::Verifier>, RuntimeError> {
        // Unfortunately `get()` requires something which the key can be `Borrow`ed as,
        // and it's impossible to implement a custom reference type without `unsafe` transmutations.
        // So we have to clone the tag here.
        let mapping_tag = tag.clone().into();
        // This is an internal method which we only call in the places where by construction it cannot fail
        // (in `Self::new()`, because of the order in which we process nodes;
        // in `Ruleset::new()`, because we call it for the nodes of the tree that was used to create `Self`).
        self.0.get(&mapping_tag).ok_or_else(|| {
            RuntimeError::new(format!(
                "Expected the node {tag} to be present in the propagated groups"
            ))
        })
    }

    fn new(root: &AnyNode<SP>) -> Result<Self, RuntimeError> {
        let mut result = Self::empty();

        for node in root.flattened_roots_first() {
            match &node {
                // Driver node (Collect) - collected values need to be calculated for each ID from the group.
                AnyNode::Collect(node) => {
                    let ids = node.as_ref().group.ids();
                    let tag = node.as_ref().values.store_in().to_owned();
                    result.insert(tag, ids);
                }
                // Driver node (SendAll) - sent values need to be calculated for each ID from the destinations.
                AnyNode::SendAll(node) => {
                    let ids = &node.as_ref().destinations;
                    let tag = MappingTag::from(node.as_ref().values.as_ref().store_in.clone());
                    result.insert(tag, ids);
                }
                // Driven nodes: if it's a mapping node, take the set of IDs it needs to be calculated for,
                // and propagate it to the arguments.
                AnyNode::ScalarArgument(_)
                | AnyNode::MergeScalars(_)
                | AnyNode::ComputeScalar(_)
                | AnyNode::SerializeAndSignBC(_)
                | AnyNode::SendBC(_)
                | AnyNode::Receive(_)
                | AnyNode::ComputeMapping(_)
                | AnyNode::SerializeAndSignDM(_)
                | AnyNode::DeserializeAndCheck(_)
                | AnyNode::SendDM(_) => {
                    if let AnyTagRef::Mapping(tag) = node.store_in() {
                        let ids = result.get(&tag.to_owned())?.clone();
                        for arg in node.all_args() {
                            if let AnyTagRef::Mapping(tag) = arg.store_in() {
                                result.insert(tag.to_owned(), &ids);
                            }
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RulesetStateChange {
    NotChanged,
    ReachedOutput,
    ImpossibleToCollect(Vec<ScalarTag>),
}

#[derive_where::derive_where(Debug)]
pub(crate) struct Ruleset<SP: SessionParameters> {
    output_tag: ComputedScalarTag,
    scalar_rules: Vec<ScalarRule<SP>>,
    collect_rules: Vec<CollectRule<SP>>,
    mapping_rules: Vec<MappingRule<SP>>,
    send_bc_rules: Vec<SendBCRule<SP>>,
    send_dm_rules: Vec<SendDMRule<SP>>,
    arguments: BTreeMap<String, ScalarArgumentTag>,
}

impl<SP: SessionParameters> Ruleset<SP> {
    pub fn new(output_node: &OutputNode<SP>, private_inputs: &BTreeSet<String>) -> Result<Self, RuntimeError> {
        let output_tag = output_node.store_in();

        let propagated_groups = PropagatedGroups::new(&AnyNode::from(output_node.get_strong_ref()))?;

        let mut scalar_rules = Vec::new();
        let mut collect_rules = Vec::new();
        let mut mapping_rules = Vec::new();
        let mut send_bc_rules = Vec::new();
        let mut send_dm_rules = Vec::new();
        let mut expected_messages = BTreeMap::new();

        let mut arguments = BTreeMap::new();

        // Nodes can be iterated in any order here, but we do leaves first to make the sequence of rules more logical
        // in case someone has to look at it during debugging.
        for node in AnyNode::from(output_node.get_strong_ref()).flattened_leaves_first() {
            match node {
                AnyNode::ScalarArgument(node) => {
                    let node = node.as_ref();
                    arguments.insert(node.name.clone(), node.store_in.clone());
                }
                AnyNode::ComputeScalar(node) => {
                    scalar_rules.push(ScalarRule::new_compute(node.as_ref()));
                }
                AnyNode::ComputeMapping(node) => {
                    let on_error = get_on_error(&node, private_inputs);
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(&node.store_in)?;
                    mapping_rules.push(MappingRule::new_compute(node, possible_ids, on_error));
                }
                AnyNode::SerializeAndSignBC(node) => {
                    scalar_rules.push(ScalarRule::new_serialize_and_sign(node.as_ref()));
                }
                AnyNode::SerializeAndSignDM(node) => {
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(&node.store_in)?;
                    mapping_rules.push(MappingRule::new_serialize_and_sign(node, possible_ids));
                }
                AnyNode::DeserializeAndCheck(node) => {
                    let on_error = get_on_error(&node, private_inputs);
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(&node.store_in)?;

                    // We expect the expected senders to be present because they are added by the `Receive` node,
                    // which is an argument to this node, so it would have been processed previously.
                    let expected_senders = expected_messages.get(&node.message_name).cloned().ok_or_else(|| {
                        RuntimeError::new(format!("Expected senders for `{}` to be available", node.message_name))
                    })?;

                    mapping_rules.push(MappingRule::new_deserialize(
                        node,
                        expected_senders,
                        possible_ids,
                        on_error,
                    ));
                }
                AnyNode::SendBC(node) => {
                    send_bc_rules.push(SendBCRule::new(node.as_ref()));
                }
                AnyNode::SendDM(node) => {
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(&node.store_in)?;
                    send_dm_rules.push(SendDMRule::new(node, possible_ids));
                }
                AnyNode::Collect(node) => {
                    collect_rules.push(CollectRule::new(node.as_ref()));
                }
                AnyNode::SendAll(node) => {
                    collect_rules.push(CollectRule::new_send_all(node.as_ref()));
                }
                AnyNode::Receive(node) => {
                    let node = node.as_ref();
                    let possible_ids = propagated_groups.get(&node.store_in)?;
                    expected_messages.insert(node.message_name.clone(), possible_ids.clone());
                }
                AnyNode::MergeScalars(node) => {
                    scalar_rules.push(ScalarRule::new_merge(node.as_ref()));
                }
            }
        }

        Ok(Self {
            output_tag: output_tag.clone(),
            scalar_rules,
            collect_rules,
            mapping_rules,
            send_bc_rules,
            send_dm_rules,
            arguments,
        })
    }

    #[must_use]
    pub fn update_with_banned_party(&mut self, id: &SP::Verifier) -> RulesetStateChange {
        let mut impossible_collects = Vec::new();
        for rule in &mut self.collect_rules {
            rule.update_with_banned_party(id);
            if !rule.is_satisfiable() {
                impossible_collects.push(rule.store_in().clone());
            }
        }

        if impossible_collects.is_empty() {
            RulesetStateChange::NotChanged
        } else {
            RulesetStateChange::ImpossibleToCollect(impossible_collects)
        }
    }

    #[must_use]
    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) -> RulesetStateChange {
        for rule in &mut self.scalar_rules {
            rule.update_with_scalar_ready(tag);
        }

        for rule in &mut self.collect_rules {
            rule.update_with_scalar_ready(tag);
        }

        for rule in &mut self.mapping_rules {
            rule.update_with_scalar_ready(tag);
        }

        for rule in &mut self.send_bc_rules {
            rule.update_with_scalar_ready(tag);
        }

        for rule in &mut self.send_dm_rules {
            rule.update_with_scalar_ready(tag);
        }

        if let ScalarTag::Computed(computed_tag) = tag
            && computed_tag == &self.output_tag
        {
            RulesetStateChange::ReachedOutput
        } else {
            RulesetStateChange::NotChanged
        }
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &SP::Verifier) {
        for rule in &mut self.collect_rules {
            rule.update_with_element_ready(tag, id);
        }

        for rule in &mut self.mapping_rules {
            rule.update_with_element_ready(tag, id);
        }

        for rule in &mut self.send_dm_rules {
            rule.update_with_element_ready(tag, id);
        }
    }

    fn pop_scalar_action(&mut self) -> Option<Action<SP>> {
        self.scalar_rules
            .extract_if(.., |rule| rule.is_satisfied())
            .next()
            .map(ScalarRule::into_action)
    }

    fn pop_collect_action(&mut self) -> Option<Action<SP>> {
        self.collect_rules
            .extract_if(.., |rule| rule.is_satisfied())
            .next()
            .map(CollectRule::into_action)
    }

    fn pop_bc_send_action(&mut self) -> Option<Action<SP>> {
        self.send_bc_rules
            .extract_if(.., |rule| rule.is_satisfied())
            .next()
            .map(SendBCRule::into_action)
    }

    fn pop_dm_send_action(&mut self) -> Option<Action<SP>> {
        for rule in &mut self.send_dm_rules.iter_mut() {
            if let Some(id) = rule.pop_satisfied() {
                return Some(rule.make_action(id));
            }
        }

        None
    }

    fn pop_mapping_action(&mut self) -> Option<Action<SP>> {
        for rule in &mut self.mapping_rules.iter_mut() {
            if let Some(id) = rule.pop_satisfied() {
                return Some(rule.make_action(id));
            }
        }

        None
    }

    pub fn pop_action(&mut self) -> Option<Action<SP>> {
        self.pop_scalar_action()
            .or_else(|| self.pop_collect_action())
            .or_else(|| self.pop_mapping_action())
            .or_else(|| self.pop_bc_send_action())
            .or_else(|| self.pop_dm_send_action())
    }

    pub fn arguments(&self) -> &BTreeMap<String, ScalarArgumentTag> {
        &self.arguments
    }

    pub fn output_tag(&self) -> &ComputedScalarTag {
        &self.output_tag
    }
}

impl<SP: SessionParameters> Display for Ruleset<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Mapping rules:")?;
        for rule in &self.mapping_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.send_dm_rules {
            writeln!(f, "{rule}")?;
        }

        writeln!(f, "Scalar rules:")?;
        for rule in &self.scalar_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.send_bc_rules {
            writeln!(f, "{rule}")?;
        }
        for rule in &self.collect_rules {
            writeln!(f, "{rule}")?;
        }
        Ok(())
    }
}
