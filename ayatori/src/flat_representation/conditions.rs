use alloc::{collections::BTreeSet, vec::Vec};
use core::fmt::{self, Display};

use itertools::Itertools;

use crate::{
    entities::{MappingTag, PartyGroup, ScalarTag},
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

    pub fn is_satisfied(&self) -> bool {
        self.all_of.is_empty()
    }

    pub fn and(self, tag: &ScalarTag) -> Self {
        let mut result = self;
        result.all_of.insert(tag.clone());
        result
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        self.all_of.remove(tag);
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

    pub fn is_satisfied(&self) -> bool {
        self.all_of.is_empty()
    }

    pub fn and(self, tag: &MappingTag) -> Self {
        let mut result = self;
        result.all_of.insert(tag.clone());
        result
    }

    pub fn update_with_scalar_ready(&mut self, tag: &MappingTag) {
        self.all_of.remove(tag);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct QuorumCondition<Id: PartyId> {
    tag: MappingTag,
    group: PartyGroup<Id>,
    got_ids: BTreeSet<Id>,
    banned_ids: BTreeSet<Id>,
}

impl<Id: PartyId> QuorumCondition<Id> {
    pub fn new(tag: &MappingTag, group: &PartyGroup<Id>) -> Self {
        Self {
            tag: tag.clone(),
            group: group.clone(),
            got_ids: BTreeSet::new(),
            banned_ids: BTreeSet::new(),
        }
    }

    pub fn update_with_banned_party(&mut self, id: &Id) {
        self.got_ids.remove(id);
        self.banned_ids.insert(id.clone());
    }

    pub fn is_satisfiable(&self) -> bool {
        self.group.is_quorum_possible(&self.banned_ids)
    }

    pub fn is_satisfied(&self) -> bool {
        self.group.has_quorum(&self.got_ids)
    }

    pub fn available_ids(self) -> BTreeSet<Id> {
        self.got_ids
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &Id) {
        if &self.tag == tag {
            self.got_ids.insert(id.clone());
        }
    }
}

impl Display for ScalarCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "ready({})", self.all_of.iter().join(", "))
    }
}

impl Display for ElementCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "ready({})", self.all_of.iter().join(", "))
    }
}

impl<Id: PartyId> Display for QuorumCondition<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "quorum({}, {}/{} (-{}))",
            self.tag,
            self.got_ids.len(),
            self.group.ids().collect::<Vec<_>>().len(),
            self.banned_ids.len()
        )
    }
}
