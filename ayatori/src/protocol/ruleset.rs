use super::node::*;
use core::any::Any;

#[derive(Debug, Clone)]
enum Condition {
    ValueReady { tag: Tag },
}

#[derive(Debug)]
enum Action<Id: PartyId, P: Protocol<Id>> {
    ComputeScalar {
        store_in: Tag,
        function: WrappedFunction<Id, P>,
        args: Vec<Tag>,
    },
}

#[derive(Debug)]
struct Rule<Id: PartyId, P: Protocol<Id>> {
    conditions: Vec<Condition>,
    action: Action<Id, P>,
}

#[derive(Debug)]
pub struct Ruleset<Id: PartyId, P: Protocol<Id>> {
    rules: Vec<Rule<Id, P>>,
}

impl<Id: PartyId, P: Protocol<Id>> Ruleset<Id, P> {
    pub fn new(output_node: ComputeScalarNode<Id, P>) -> Self {
        todo!()
    }
}
