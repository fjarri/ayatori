use alloc::{boxed::Box, collections::BTreeSet, format};
use core::fmt::{self, Debug, Display};

use itertools::Itertools;

use crate::traits::PartyId;

/// A group of parties that, in the context of a protocol, are required to provide certain information
/// (could be all of the parties, or some threshold subset).
pub trait PartyGroup<Id: PartyId>: Debug + Send + Sync {
    /// Returns all IDs in this group.
    fn ids(&self) -> &BTreeSet<Id>;

    /// Returns `true` if the information from `ids` is enough to move on in the protocol.
    fn has_quorum(&self, ids: &BTreeSet<Id>) -> bool;

    /// Returns `true` if it is not possible for [`Self::has_quorum`] to return `true`
    /// if `without_ids` are guaranteed not to be present in `ids`.
    fn is_quorum_possible(&self, without_ids: &BTreeSet<Id>) -> bool;

    /// Clones this object into a `Box`.
    fn clone_box(&self) -> Box<dyn PartyGroup<Id>>;
}

/// A party group with quorum achievable with any subset of parties with the size over a given threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdGroup<Id: PartyId> {
    ids: BTreeSet<Id>,
    threshold: usize,
}

impl<Id: PartyId> ThresholdGroup<Id> {
    /// Creates a new group from party IDs.
    ///
    /// Repeating IDs are ignored.
    // TODO: take a BTreeSet instead?
    pub fn new(ids: &[Id]) -> Self {
        let ids = ids.iter().cloned().collect::<BTreeSet<_>>();
        let threshold = ids.len();
        Self { ids, threshold }
    }

    /// Creates a new group from party IDs with a custom quorum threshold.
    ///
    /// Repeating IDs are ignored.
    pub fn new_threshold(ids: &[Id], threshold: usize) -> Self {
        Self {
            ids: ids.iter().cloned().collect(),
            threshold,
        }
    }

    /// Returns the quorum threshold.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

impl<Id: PartyId> PartyGroup<Id> for ThresholdGroup<Id> {
    fn ids(&self) -> &BTreeSet<Id> {
        &self.ids
    }

    fn has_quorum(&self, ids: &BTreeSet<Id>) -> bool {
        ids.intersection(&self.ids).count() >= self.threshold
    }

    fn is_quorum_possible(&self, without_ids: &BTreeSet<Id>) -> bool {
        self.ids.difference(without_ids).count() >= self.threshold
    }

    fn clone_box(&self) -> Box<dyn PartyGroup<Id>> {
        Box::new(self.clone())
    }
}

impl<Id: PartyId> Display for ThresholdGroup<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let ids = self.ids.iter().map(|id| format!("{id:?}")).join(", ");
        write!(f, "{{{ids}}}")
    }
}
