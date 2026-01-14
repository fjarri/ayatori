use crate::protocol::PartyId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestPartyId(u64);

impl TestPartyId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}
