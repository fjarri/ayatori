use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
};
use core::fmt::{self, Display};

use itertools::Itertools;

use super::{
    actions::{
        Action, CollectAction, ComputeDeserializeElementAction, ComputeMappingElementAction, ComputeScalarAction,
        ComputeSerializeAndSignElementAction, ComputeSerializeAndSignScalarAction, MergeScalarsAction, SendBCAction,
        SendDMAction,
    },
    conditions::{
        ElementCondition, ElementConditionWithState, QuorumCondition, QuorumConditionWithState, ScalarCondition,
        ScalarConditionWithState,
    },
};
use crate::{
    entities::{
        AnyTag, ComputedMappingTag, ComputedScalarTag, DeserializeFunction, FullName, LocalSignedBCTag,
        LocalSignedDMTag, MappingFunction, MappingTag, MergedScalarTag, ReceivedTag, RemoteSignedTag, ScalarFunction,
        ScalarTag, SentBCTag, SentDMTag, SerdeAdapter, SerializeAndSignBCFunction, SerializeAndSignDMFunction,
    },
    graph_representation::{
        Collect, ComputeMapping, ComputeScalar, DeserializeAndCheck, MergeScalars, SendAll, SendBC, SendDM,
        SerializeAndSignBC, SerializeAndSignDM,
    },
    traits::SessionParameters,
};

#[derive(Debug, Clone)]
pub(crate) enum OnError {
    CollectEvidence(BTreeSet<FullName>),
    Escalate,
}

#[derive_where::derive_where(Debug)]
pub(super) struct ScalarRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    scalar_condition: ScalarConditionWithState,
    kind: ScalarRuleKind<SP>,
}

#[derive_where::derive_where(Debug)]
pub(super) enum ScalarRuleKind<SP: SessionParameters> {
    Compute {
        store_in: ComputedScalarTag,
        function: ScalarFunction<SP>,
        args: BTreeMap<String, ScalarTag>,
    },
    SerializeAndSign {
        store_in: LocalSignedBCTag,
        function: SerializeAndSignBCFunction<SP>,
        data: ScalarTag,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    Merge {
        store_in: MergedScalarTag,
        left: ScalarTag,
        right: ScalarTag,
    },
}

impl<SP: SessionParameters> ScalarRule<SP> {
    pub fn new_compute(node: &ComputeScalar<SP>) -> Self {
        let scalar_condition = ScalarConditionWithState::new(ScalarCondition::from_compute_scalar(node));
        let dependencies_condition =
            ScalarConditionWithState::new(ScalarCondition::from_dependencies(&node.dependencies));

        let arg_tags = node
            .args
            .iter()
            .map(|(name, arg)| {
                let arg = arg.store_in().to_owned();
                (name.clone(), arg)
            })
            .collect();

        Self {
            dependencies_condition,
            scalar_condition,
            kind: ScalarRuleKind::Compute {
                store_in: node.store_in.clone(),
                function: node.function(),
                args: arg_tags,
            },
        }
    }

    pub fn new_serialize_and_sign(node: &SerializeAndSignBC<SP>) -> Self {
        let scalar_condition = ScalarConditionWithState::new(ScalarCondition::from_serialize_and_sign_bc(node));
        let dependencies_condition = ScalarConditionWithState::new(ScalarCondition::empty());
        Self {
            dependencies_condition,
            scalar_condition,
            kind: ScalarRuleKind::SerializeAndSign {
                store_in: node.store_in.clone(),
                function: node.function.clone(),
                data: node.data.store_in().to_owned(),
                message_name: node.message_name.clone(),
                serde_adapter: node.serde_adapter.clone(),
            },
        }
    }

    pub fn new_merge(node: &MergeScalars<SP>) -> Self {
        let dependencies_condition = ScalarConditionWithState::new(ScalarCondition::empty());
        let scalar_condition = ScalarConditionWithState::new(ScalarCondition::from_merged_scalar(node));
        Self {
            dependencies_condition,
            scalar_condition,
            kind: ScalarRuleKind::Merge {
                store_in: node.store_in.clone(),
                left: node.left.store_in().to_owned(),
                right: node.right.store_in().to_owned(),
            },
        }
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        self.scalar_condition.update_with_scalar_ready(tag);
        self.dependencies_condition.update_with_scalar_ready(tag);
    }

    pub fn is_satisfied(&self) -> bool {
        self.dependencies_condition.is_satisfied() && self.scalar_condition.is_satisfied()
    }

    pub fn into_action(self) -> Action<SP> {
        match self.kind {
            ScalarRuleKind::Compute {
                store_in,
                function,
                args,
            } => Action::ComputeScalar(ComputeScalarAction {
                store_in,
                function,
                args,
            }),
            ScalarRuleKind::SerializeAndSign {
                store_in,
                function,
                data,
                message_name,
                serde_adapter,
            } => Action::ComputeSerializeAndSignScalar(ComputeSerializeAndSignScalarAction {
                store_in,
                function,
                data,
                message_name,
                serde_adapter,
            }),
            ScalarRuleKind::Merge { store_in, left, right } => {
                Action::MergeScalar(MergeScalarsAction { store_in, left, right })
            }
        }
    }
}

#[derive_where::derive_where(Debug)]
pub(super) struct CollectRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    quorum_condition: QuorumConditionWithState<SP::Verifier>,
    store_in: ScalarTag,
    values: MappingTag,
}

impl<SP: SessionParameters> CollectRule<SP> {
    pub fn new(node: &Collect<SP>) -> Self {
        let dependencies_condition =
            ScalarConditionWithState::new(ScalarCondition::from_dependencies(&node.dependencies));
        let quorum_condition = QuorumConditionWithState::new(QuorumCondition::from_collect(node));
        Self {
            dependencies_condition,
            quorum_condition,
            store_in: node.store_in.clone().into(),
            values: node.values.store_in().to_owned(),
        }
    }

    pub fn new_send_all(node: &SendAll<SP>) -> Self {
        let dependencies_condition = ScalarConditionWithState::new(ScalarCondition::empty());
        let quorum_condition = QuorumConditionWithState::new(QuorumCondition::from_send_all(node));
        Self {
            dependencies_condition,
            quorum_condition,
            store_in: node.store_in.clone().into(),
            values: node.values.as_ref().store_in.clone().into(),
        }
    }

    pub fn store_in(&self) -> &ScalarTag {
        &self.store_in
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        self.dependencies_condition.update_with_scalar_ready(tag);
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &SP::Verifier) {
        self.quorum_condition.update_with_element_ready(tag, id);
    }

    pub fn update_with_banned_party(&mut self, id: &SP::Verifier) {
        self.quorum_condition.update_with_banned_party(id);
    }

    pub fn is_satisfied(&self) -> bool {
        self.dependencies_condition.is_satisfied() && self.quorum_condition.is_satisfied()
    }

    pub fn is_satisfiable(&self) -> bool {
        self.quorum_condition.is_satisfiable()
    }

    pub fn into_action(self) -> Action<SP> {
        Action::Collect(CollectAction {
            store_in: self.store_in,
            values: self.values,
            sources: self.quorum_condition.available_ids(),
        })
    }
}

#[derive_where::derive_where(Debug)]
pub(super) struct MappingRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    scalar_condition: ScalarConditionWithState,
    element_condition: ElementConditionWithState<SP::Verifier>,
    kind: MappingRuleKind<SP>,
}

#[derive_where::derive_where(Debug)]
pub(super) enum MappingRuleKind<SP: SessionParameters> {
    Compute {
        store_in: ComputedMappingTag,
        function: MappingFunction<SP>,
        args: BTreeMap<String, AnyTag>,
        on_error: OnError,
    },
    SerializeAndSign {
        store_in: LocalSignedDMTag,
        function: SerializeAndSignDMFunction<SP>,
        data: AnyTag,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    Deserialize {
        store_in: ReceivedTag,
        function: DeserializeFunction<SP>,
        data: RemoteSignedTag,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        expected_senders: BTreeSet<SP::Verifier>,
        on_error: OnError,
    },
}

impl<SP: SessionParameters> MappingRule<SP> {
    pub fn new_compute(node: &ComputeMapping<SP>, possible_ids: &BTreeSet<SP::Verifier>, on_error: OnError) -> Self {
        let dependencies_condition =
            ScalarConditionWithState::new(ScalarCondition::from_dependencies(&node.dependencies));
        let scalar_condition = ScalarConditionWithState::new(ScalarCondition::from_compute_mapping(node));
        let element_condition =
            ElementConditionWithState::new(ElementCondition::from_compute_mapping(node), possible_ids);

        let arg_tags = node
            .args
            .iter()
            .map(|(name, arg)| {
                let arg = arg.store_in().to_owned();
                (name.clone(), arg)
            })
            .collect();

        Self {
            dependencies_condition,
            scalar_condition,
            element_condition,
            kind: MappingRuleKind::Compute {
                store_in: node.store_in.clone(),
                function: node.function(),
                args: arg_tags,
                on_error,
            },
        }
    }

    pub fn new_serialize_and_sign(node: &SerializeAndSignDM<SP>, possible_ids: &BTreeSet<SP::Verifier>) -> Self {
        let dependencies_condition = ScalarConditionWithState::new(ScalarCondition::empty());
        let scalar_condition = ScalarConditionWithState::new(ScalarCondition::from_serialize_and_sign_dm(node));
        let element_condition =
            ElementConditionWithState::new(ElementCondition::from_serialize_and_sign(node), possible_ids);
        Self {
            dependencies_condition,
            scalar_condition,
            element_condition,
            kind: MappingRuleKind::SerializeAndSign {
                store_in: node.store_in.clone(),
                function: node.function.clone(),
                data: node.data.store_in().to_owned(),
                message_name: node.message_name.clone(),
                serde_adapter: node.serde_adapter.clone(),
            },
        }
    }

    pub fn new_deserialize(
        node: &DeserializeAndCheck<SP>,
        expected_senders: BTreeSet<SP::Verifier>,
        possible_ids: &BTreeSet<SP::Verifier>,
        on_error: OnError,
    ) -> Self {
        let dependencies_condition = ScalarConditionWithState::new(ScalarCondition::empty());
        let scalar_condition = ScalarConditionWithState::new(ScalarCondition::empty());
        let element_condition =
            ElementConditionWithState::new(ElementCondition::from_deserialize_and_check(node), possible_ids);
        Self {
            dependencies_condition,
            scalar_condition,
            element_condition,
            kind: MappingRuleKind::Deserialize {
                store_in: node.store_in.clone(),
                function: node.function.clone(),
                data: node.data.as_ref().store_in.clone(),
                serde_adapter: node.serde_adapter.clone(),
                expected_senders,
                on_error,
            },
        }
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        self.scalar_condition.update_with_scalar_ready(tag);
        self.dependencies_condition.update_with_scalar_ready(tag);
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &SP::Verifier) {
        self.element_condition.update_with_element_ready(tag, id);
    }

    pub fn pop_satisfied(&mut self) -> Option<SP::Verifier> {
        if !self.dependencies_condition.is_satisfied() || !self.scalar_condition.is_satisfied() {
            return None;
        }

        self.element_condition.pop_satisfied()
    }

    pub fn make_action(&self, id: SP::Verifier) -> Action<SP> {
        match &self.kind {
            MappingRuleKind::Compute {
                store_in,
                function,
                args,
                on_error,
            } => Action::ComputeMappingElement(ComputeMappingElementAction {
                store_in: store_in.clone(),
                index: id,
                function: function.clone(),
                args: args.clone(),
                on_error: on_error.clone(),
            }),
            MappingRuleKind::SerializeAndSign {
                store_in,
                function,
                data,
                message_name,
                serde_adapter,
            } => Action::ComputeSerializeAndSignElement(ComputeSerializeAndSignElementAction {
                store_in: store_in.clone(),
                index: id,
                function: function.clone(),
                data: data.clone(),
                message_name: message_name.clone(),
                serde_adapter: serde_adapter.clone(),
            }),
            MappingRuleKind::Deserialize {
                store_in,
                function,
                data,
                serde_adapter,
                expected_senders,
                on_error,
            } => Action::ComputeDeserializeElement(ComputeDeserializeElementAction {
                store_in: store_in.clone(),
                index: id,
                function: function.clone(),
                data: data.clone(),
                serde_adapter: serde_adapter.clone(),
                expected_senders: expected_senders.clone(),
                on_error: on_error.clone(),
            }),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub(super) struct SendBCRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    scalar_condition: ScalarConditionWithState,
    store_in: SentBCTag,
    to_send: LocalSignedBCTag,
    destinations: BTreeSet<SP::Verifier>,
}

impl<SP: SessionParameters> SendBCRule<SP> {
    pub fn new(node: &SendBC<SP>) -> Self {
        let dependencies_condition =
            ScalarConditionWithState::new(ScalarCondition::from_dependencies(&node.dependencies));
        let scalar_condition = ScalarConditionWithState::new(ScalarCondition::from_broadcast_message(node));
        Self {
            dependencies_condition,
            scalar_condition,
            store_in: node.store_in.clone(),
            to_send: node.data.as_ref().store_in.clone(),
            destinations: node.destinations.clone(),
        }
    }

    pub fn is_satisfied(&self) -> bool {
        self.dependencies_condition.is_satisfied() && self.scalar_condition.is_satisfied()
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        self.scalar_condition.update_with_scalar_ready(tag);
        self.dependencies_condition.update_with_scalar_ready(tag);
    }

    pub fn into_action(self) -> Action<SP> {
        Action::SendBC(SendBCAction {
            store_in: self.store_in,
            to_send: self.to_send,
            destinations: self.destinations,
        })
    }
}

#[derive_where::derive_where(Debug)]
pub(super) struct SendDMRule<SP: SessionParameters> {
    dependencies_condition: ScalarConditionWithState,
    element_condition: ElementConditionWithState<SP::Verifier>,
    store_in: SentDMTag,
    to_send: LocalSignedDMTag,
}

impl<SP: SessionParameters> SendDMRule<SP> {
    pub fn new(node: &SendDM<SP>, possible_ids: &BTreeSet<SP::Verifier>) -> Self {
        let dependencies_condition =
            ScalarConditionWithState::new(ScalarCondition::from_dependencies(&node.dependencies));
        let element_condition =
            ElementConditionWithState::new(ElementCondition::from_direct_message(node), possible_ids);
        Self {
            dependencies_condition,
            element_condition,
            store_in: node.store_in.clone(),
            to_send: node.data.as_ref().store_in.clone(),
        }
    }

    pub fn update_with_scalar_ready(&mut self, tag: &ScalarTag) {
        self.dependencies_condition.update_with_scalar_ready(tag);
    }

    pub fn update_with_element_ready(&mut self, tag: &MappingTag, id: &SP::Verifier) {
        self.element_condition.update_with_element_ready(tag, id);
    }

    pub fn pop_satisfied(&mut self) -> Option<SP::Verifier> {
        if !self.dependencies_condition.is_satisfied() {
            return None;
        }

        self.element_condition.pop_satisfied()
    }

    pub fn make_action(&self, id: SP::Verifier) -> Action<SP> {
        Action::SendDM(SendDMAction {
            store_in: self.store_in.clone(),
            to_send: self.to_send.clone(),
            destination: id,
        })
    }
}

impl<SP: SessionParameters> Display for ScalarRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        if !self.scalar_condition.is_satisfied() {
            writeln!(f, "if {}", self.scalar_condition)?;
        }
        match &self.kind {
            ScalarRuleKind::Compute {
                store_in,
                function,
                args,
            } => writeln!(
                f,
                "  {store_in} = {function}({})",
                args.values().map(ToString::to_string).join(", ")
            ),
            ScalarRuleKind::SerializeAndSign {
                store_in,
                function,
                data,
                ..
            } => writeln!(f, "{store_in} = {function}({data})"),
            ScalarRuleKind::Merge { store_in, left, right } => writeln!(f, "  {store_in} = {left} | {right}"),
        }
    }
}

impl<SP: SessionParameters> Display for CollectRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        if !self.quorum_condition.is_satisfied() {
            writeln!(f, "if {}", self.quorum_condition)?;
        }
        writeln!(f, "  {} = collect({})", self.store_in, self.values)
    }
}

impl<SP: SessionParameters> Display for MappingRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        if !self.scalar_condition.is_satisfied() {
            writeln!(f, "if {}", self.scalar_condition)?;
        }
        writeln!(f, "if {})", self.element_condition)?;
        writeln!(f, "  {}", self.kind)
    }
}

impl<SP: SessionParameters> Display for MappingRuleKind<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Compute {
                store_in,
                function,
                args,
                ..
            } => writeln!(
                f,
                "{store_in} = {function}({})",
                args.values().map(ToString::to_string).join(", ")
            ),
            Self::SerializeAndSign {
                store_in,
                function,
                data,
                ..
            } => writeln!(f, "{store_in} = {function}({data})"),
            Self::Deserialize {
                store_in,
                function,
                data,
                ..
            } => writeln!(f, "{store_in} = {function}({data})"),
        }
    }
}

impl<SP: SessionParameters> Display for SendBCRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        if !self.scalar_condition.is_satisfied() {
            writeln!(f, "if {}", self.scalar_condition)?;
        }
        writeln!(f, "  {} = broadcast_message({})", self.store_in, self.to_send)
    }
}

impl<SP: SessionParameters> Display for SendDMRule<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if !self.dependencies_condition.is_satisfied() {
            writeln!(f, "if {}", self.dependencies_condition)?;
        }
        writeln!(f, "if {})", self.element_condition)?;
        writeln!(f, "  {} = direct_message({})", self.store_in, self.to_send)
    }
}
