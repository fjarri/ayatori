use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::{self, Display};

use itertools::Itertools;

use crate::protocol::{PartyGroup, PartyId, Tag};

#[derive(Debug, Clone)]
pub(crate) enum LeafCondition<Id: PartyId> {
    Value {
        tag: Tag,
    },
    ArrayElement {
        tag: Tag,
        id: Id,
    },
    Array {
        tag: Tag,
        group: PartyGroup<Id>,
        got_ids: BTreeSet<Id>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct Condition<Id: PartyId> {
    all_of: Vec<LeafCondition<Id>>,
}

impl<Id: PartyId> Condition<Id> {
    pub fn empty() -> Self {
        Self { all_of: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.all_of.is_empty()
    }

    pub fn and(&mut self, leaf: LeafCondition<Id>) {
        self.all_of.push(leaf);
    }

    pub fn and_condition(&mut self, condition: Condition<Id>) {
        self.all_of.extend(condition.all_of);
    }

    pub fn update_with_value_ready(&mut self, tag: &Tag) {
        self.all_of.retain_mut(|leaf| match leaf {
            LeafCondition::Array { tag: condition_tag, .. } => {
                if condition_tag == tag {
                    panic!()
                }
                true
            }
            LeafCondition::ArrayElement { tag: condition_tag, .. } => {
                if condition_tag == tag {
                    panic!()
                }
                true
            }
            LeafCondition::Value { tag: condition_tag } => condition_tag != tag,
        });
    }

    pub fn update_with_array_element_ready(&mut self, tag: &Tag, id: &Id) {
        self.all_of.retain_mut(|leaf| match leaf {
            LeafCondition::Array {
                tag: condition_tag,
                group,
                got_ids,
            } => {
                if condition_tag == tag {
                    got_ids.insert(id.clone());
                    !group.has_quorum(got_ids)
                } else {
                    true
                }
            }
            LeafCondition::ArrayElement {
                tag: condition_tag,
                id: condition_id,
            } => !(condition_tag == tag && condition_id == id),
            LeafCondition::Value { tag: condition_tag } => {
                if condition_tag == tag {
                    panic!()
                }
                true
            }
        });
    }
}

impl<Id: PartyId> Display for LeafCondition<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Value { tag } => {
                write!(f, "ready({tag})")
            }
            Self::ArrayElement { tag, id } => {
                write!(f, "ready({tag}, {id:?})")
            }
            Self::Array { tag, group, got_ids } => {
                write!(f, "all-ready({tag}, {group}) [have: {got_ids:?}]")
            }
        }
    }
}

impl<Id: PartyId> Display for Condition<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if self.all_of.is_empty() {
            write!(f, "True")
        } else {
            write!(f, "{}", self.all_of.iter().map(|leaf| leaf.to_string()).join(" AND "))
        }
    }
}
