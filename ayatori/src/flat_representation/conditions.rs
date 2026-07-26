use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::ToString,
    vec::Vec,
};
use core::fmt::{self, Display};

use itertools::Itertools;

use crate::{
    entities::{AnyTagRef, MappingTag, PartyGroup, ScalarTag, ThresholdGroup},
    graph_representation::{
        Collect, ComputeMapping, ComputeMappingKind, ComputeScalar, Dependency, DeserializeAndCheck, MergeScalars,
        SendAll, SendBC, SendDM, SerializeAndSignBC, SerializeAndSignDM,
    },
    traits::{PartyId, SessionParameters},
};

#[derive(Debug, Clone)]
pub(crate) struct Either {
    left: ScalarTag,
    right: ScalarTag,
}

#[derive(Debug, Clone)]
pub(crate) enum ScalarCondition {
    And(BTreeSet<ScalarTag>),
    // For now we only need no more than 1 condtion (to be used in merge nodes).
    // This can be expaned to a vector if necessary.
    Or(Option<Either>),
}

impl ScalarCondition {
    pub fn from_compute_scalar<SP: SessionParameters>(node: &ComputeScalar<SP>) -> Self {
        let mut all_of = BTreeSet::new();
        for arg in node.args.values() {
            all_of.insert(arg.store_in().to_owned());
        }
        Self::And(all_of)
    }

    pub fn from_broadcast_message<SP: SessionParameters>(node: &SendBC<SP>) -> Self {
        Self::And(BTreeSet::from([ScalarTag::LocalSigned(
            node.data.as_ref().store_in.clone(),
        )]))
    }

    pub fn from_merged_scalar<SP: SessionParameters>(node: &MergeScalars<SP>) -> Self {
        Self::Or(Some(Either {
            left: node.left.store_in().to_owned(),
            right: node.right.store_in().to_owned(),
        }))
    }

    pub fn empty() -> Self {
        Self::And(BTreeSet::new())
    }

    pub fn from_compute_mapping<SP: SessionParameters>(node: &ComputeMapping<SP>) -> Self {
        let mut all_of = BTreeSet::new();
        for arg in node.args.values() {
            if let AnyTagRef::Scalar(tag) = arg.store_in() {
                all_of.insert(tag.to_owned());
            }
        }
        match &node.kind {
            ComputeMappingKind::Simple { .. } | ComputeMappingKind::ThirdPartyAttributable { .. } => {}
            ComputeMappingKind::WithReveal { verification_args, .. } => {
                for arg in verification_args.values() {
                    if let AnyTagRef::Scalar(tag) = arg.store_in() {
                        all_of.insert(tag.to_owned());
                    }
                }
            }
        }
        Self::And(all_of)
    }

    pub fn from_serialize_and_sign_bc<SP: SessionParameters>(node: &SerializeAndSignBC<SP>) -> Self {
        Self::And(BTreeSet::from([node.data.store_in().to_owned()]))
    }

    pub fn from_serialize_and_sign_dm<SP: SessionParameters>(node: &SerializeAndSignDM<SP>) -> Self {
        if let AnyTagRef::Scalar(tag) = node.data.store_in() {
            Self::And(BTreeSet::from([tag.to_owned()]))
        } else {
            Self::And(BTreeSet::new())
        }
    }

    pub fn from_dependencies<SP: SessionParameters>(nodes: &[Dependency<SP>]) -> Self {
        let mut all_of = BTreeSet::new();
        for arg in nodes {
            all_of.insert(arg.store_in().to_owned());
        }
        Self::And(all_of)
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::And(all_of) => all_of.is_empty(),
            Self::Or(maybe_either) => maybe_either.is_none(),
        }
    }
}

impl Display for ScalarCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::And(all_of) => write!(f, "ready({})", all_of.iter().map(ToString::to_string).join(" && ")),
            Self::Or(Some(either)) => write!(f, "ready({} || {})", either.left, either.right),
            Self::Or(None) => write!(f, "ready()"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ElementCondition {
    all_of: BTreeSet<MappingTag>,
}

impl ElementCondition {
    pub fn from_compute_mapping<SP: SessionParameters>(node: &ComputeMapping<SP>) -> Self {
        let mut all_of = BTreeSet::new();
        for arg in node.args.values() {
            if let AnyTagRef::Mapping(tag) = arg.store_in() {
                all_of.insert(tag.to_owned());
            }
        }
        match &node.kind {
            ComputeMappingKind::Simple { .. } | ComputeMappingKind::ThirdPartyAttributable { .. } => {}
            ComputeMappingKind::WithReveal { verification_args, .. } => {
                for arg in verification_args.values() {
                    if let AnyTagRef::Mapping(tag) = arg.store_in() {
                        all_of.insert(tag.to_owned());
                    }
                }
            }
        }
        Self { all_of }
    }

    pub fn from_serialize_and_sign<SP: SessionParameters>(node: &SerializeAndSignDM<SP>) -> Self {
        if let AnyTagRef::Mapping(tag) = node.data.store_in() {
            Self {
                all_of: BTreeSet::from([tag.to_owned()]),
            }
        } else {
            Self {
                all_of: BTreeSet::new(),
            }
        }
    }

    pub fn from_deserialize_and_check<SP: SessionParameters>(node: &DeserializeAndCheck<SP>) -> Self {
        Self {
            all_of: BTreeSet::from([MappingTag::RemoteSigned(node.data.as_ref().store_in.clone())]),
        }
    }

    pub fn from_direct_message<SP: SessionParameters>(node: &SendDM<SP>) -> Self {
        Self {
            all_of: BTreeSet::from([MappingTag::LocalSigned(node.data.as_ref().store_in.clone())]),
        }
    }
}

#[derive(Debug)]
pub(crate) struct QuorumCondition<Id: PartyId> {
    tag: MappingTag,
    group: Box<dyn PartyGroup<Id>>,
}

impl<Id: PartyId> QuorumCondition<Id> {
    pub fn from_collect<SP: SessionParameters<Verifier = Id>>(node: &Collect<SP>) -> Self {
        Self {
            tag: node.values.store_in().to_owned(),
            group: node.group.clone_box(),
        }
    }

    pub fn from_send_all<SP: SessionParameters<Verifier = Id>>(node: &SendAll<SP>) -> Self {
        Self {
            tag: MappingTag::Sent(node.values.as_ref().store_in.clone()),
            group: Box::new(ThresholdGroup::new(
                &node.destinations.iter().cloned().collect::<Vec<_>>(),
            )),
        }
    }

    pub fn is_satisfiable(&self, banned_ids: &BTreeSet<Id>) -> bool {
        self.group.is_quorum_possible(banned_ids)
    }

    pub fn is_satisfied(&self, got_ids: &BTreeSet<Id>) -> bool {
        self.group.has_quorum(got_ids)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ScalarConditionWithState {
    current_condition: ScalarCondition,
}

impl ScalarConditionWithState {
    pub fn new(condition: ScalarCondition) -> Self {
        Self {
            current_condition: condition,
        }
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        match &mut self.current_condition {
            ScalarCondition::And(all_of) => {
                all_of.remove(tag);
            }
            ScalarCondition::Or(maybe_either) => {
                if let Some(either) = maybe_either
                    && (&either.left == tag || &either.right == tag)
                {
                    *maybe_either = None;
                }
            }
        }
    }

    pub fn is_satisfied(&self) -> bool {
        self.current_condition.is_empty()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ElementConditionWithState<Id: PartyId> {
    original_condition: ElementCondition,
    current_conditions: BTreeMap<Id, BTreeSet<MappingTag>>,
    triggered_for: BTreeSet<Id>,
}

impl<Id: PartyId> ElementConditionWithState<Id> {
    pub fn new(condition: ElementCondition, possible_ids: &BTreeSet<Id>) -> Self {
        let current_conditions = possible_ids
            .iter()
            .map(|id| (id.clone(), condition.all_of.clone()))
            .collect();
        Self {
            original_condition: condition,
            current_conditions,
            triggered_for: BTreeSet::new(),
        }
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &Id) {
        self.current_conditions.get_mut(id).map(|tags| tags.remove(tag));
    }

    pub fn pop_satisfied(&mut self) -> Option<Id> {
        let id = self
            .current_conditions
            .iter()
            .find(|(_id, tags)| tags.is_empty())
            .map(|(id, _tags)| id.clone());

        if let Some(id) = id {
            self.current_conditions.remove(&id);
            self.triggered_for.insert(id.clone());
            Some(id)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub(crate) struct QuorumConditionWithState<Id: PartyId> {
    original_condition: QuorumCondition<Id>,
    got_ids: BTreeSet<Id>,
    banned_ids: BTreeSet<Id>,
}

impl<Id: PartyId> QuorumConditionWithState<Id> {
    pub fn new(condition: QuorumCondition<Id>) -> Self {
        Self {
            original_condition: condition,
            got_ids: BTreeSet::new(),
            banned_ids: BTreeSet::new(),
        }
    }

    pub fn update_with_banned_party(&mut self, id: &Id) {
        self.got_ids.remove(id);
        self.banned_ids.insert(id.clone());
    }

    pub fn is_satisfiable(&self) -> bool {
        self.original_condition.is_satisfiable(&self.banned_ids)
    }

    pub fn is_satisfied(&self) -> bool {
        self.original_condition.is_satisfied(&self.got_ids)
    }

    pub fn available_ids(self) -> BTreeSet<Id> {
        self.got_ids
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &Id) {
        if &self.original_condition.tag == tag {
            self.got_ids.insert(id.clone());
        }
    }
}

impl Display for ScalarConditionWithState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.current_condition)
    }
}

impl<Id: PartyId> Display for ElementConditionWithState<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "element-ready({}) (triggered: {})",
            self.original_condition.all_of.iter().join(", "),
            self.triggered_for.len()
        )
    }
}

impl<Id: PartyId> Display for QuorumConditionWithState<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "quorum({}, {}/{} (-{}))",
            self.original_condition.tag,
            self.got_ids.len(),
            self.original_condition.group.ids().len(),
            self.banned_ids.len()
        )
    }
}
