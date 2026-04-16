use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::fmt::{self, Display};

use itertools::Itertools;

use crate::{
    entities::{MappingTag, MappingTagRef, PartyGroup, ScalarTag, ScalarTagRef},
    traits::PartyId,
};

#[derive(Debug, Clone)]
pub(crate) struct ScalarCondition {
    all_of: BTreeSet<ScalarTag>,
}

impl ScalarCondition {
    pub fn empty() -> Self {
        Self {
            all_of: BTreeSet::new(),
        }
    }

    pub fn and(self, tag: ScalarTagRef<'_>) -> Self {
        let mut result = self;
        result.all_of.insert(tag.to_owned());
        result
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ElementCondition {
    all_of: BTreeSet<MappingTag>,
}

impl ElementCondition {
    pub fn empty() -> Self {
        Self {
            all_of: BTreeSet::new(),
        }
    }

    pub fn and(self, tag: MappingTagRef<'_>) -> Self {
        let mut result = self;
        result.all_of.insert(tag.to_owned());
        result
    }
}

#[derive(Debug, Clone)]
pub(crate) struct QuorumCondition<Id: PartyId> {
    tag: MappingTag,
    group: PartyGroup<Id>,
}

impl<Id: PartyId> QuorumCondition<Id> {
    pub fn new(tag: MappingTagRef<'_>, group: &PartyGroup<Id>) -> Self {
        Self {
            tag: tag.to_owned(),
            group: group.clone(),
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
    current_condition: BTreeSet<ScalarTag>,
}

impl ScalarConditionWithState {
    pub fn new(condition: ScalarCondition) -> Self {
        Self {
            current_condition: condition.all_of,
        }
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        self.current_condition.remove(tag);
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
        Self {
            original_condition: condition.clone(),
            current_conditions: possible_ids
                .iter()
                .map(|id| (id.clone(), condition.all_of.clone()))
                .collect(),
            triggered_for: BTreeSet::new(),
        }
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &Id) {
        // TODO: check if `id` is in `triggered_for` already?
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

#[derive(Debug, Clone)]
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
        write!(f, "ready({})", self.current_condition.iter().join(", "))
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
            self.original_condition.group.ids().collect::<Vec<_>>().len(),
            self.banned_ids.len()
        )
    }
}
