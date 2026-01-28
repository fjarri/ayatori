use alloc::{collections::BTreeSet, format};
use core::fmt::{self, Debug, Display};

use itertools::Itertools;

use super::traits::PartyId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyGroup<Id: PartyId> {
    ids: BTreeSet<Id>,
}

impl<Id: PartyId> PartyGroup<Id> {
    pub fn new(ids: &[Id]) -> Self {
        Self {
            ids: ids.iter().cloned().collect(),
        }
    }

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.ids.iter()
    }

    pub fn has_quorum(&self, ids: &BTreeSet<Id>) -> bool {
        &self.ids == ids
    }

    #[must_use]
    pub fn except(&self, id: &Id) -> Self {
        let mut ids = self.ids.clone();
        ids.remove(id);
        Self { ids }
    }
}

impl<Id: PartyId> Display for PartyGroup<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let ids = self.ids.iter().map(|id| format!("{id:?}")).join(", ");
        write!(f, "{{{ids}}}")
    }
}
