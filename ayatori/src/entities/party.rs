use alloc::{collections::BTreeSet, format};
use core::fmt::{self, Debug, Display};

use itertools::Itertools;

use crate::traits::PartyId;

/// A group of parties that, in the context of a protocol, are required to provide certain information
/// (could be all of the parties, or some threshold subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyGroup<Id: PartyId> {
    ids: BTreeSet<Id>,
}

impl<Id: PartyId> PartyGroup<Id> {
    /// Creates a new group from party IDs.
    ///
    /// Repeating IDs are ignored.
    pub fn new(ids: &[Id]) -> Self {
        Self {
            ids: ids.iter().cloned().collect(),
        }
    }

    /// Returns all IDs in this group.
    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.ids.iter()
    }

    /// Returns `true` if the information from `ids` is enough to move on in the protocol.
    #[must_use]
    pub fn has_quorum(&self, ids: &BTreeSet<Id>) -> bool {
        &self.ids == ids
    }

    /// Returns `true` if it is not possible for [`Self::has_quorum`] to return `true`
    /// if `banned_ids` are guaranteed not to be present in `ids`.
    #[must_use]
    pub fn is_quorum_possible(&self, banned_ids: &BTreeSet<Id>) -> bool {
        self.has_quorum(&self.ids.difference(banned_ids).cloned().collect::<BTreeSet<_>>())
    }

    /// Returns `self` with `id` excluded from the group.
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
