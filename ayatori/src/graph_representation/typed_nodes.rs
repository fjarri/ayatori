use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt::{self, Display};

use itertools::Itertools;

use super::{
    any_node::AnyNode,
    unions::{CollectArg, ComputeMappingArg, ComputeScalarArg, Dependency, SerializeAndSignArg, UnionCastError},
};
use crate::{
    entities::{
        CollectedTag, ComputedMappingTag, ComputedScalarTag, DeserializeFunction, EvidenceVerificationFunction,
        FullName, LocalSignedTag, PartyGroup, ReceivedTag, RemoteSignedTag, RuntimeError, ScalarArgumentTag,
        ScalarFunction, SenderAttributableWithRevealMappingFunction, SentTag, SerdeAdapter, SerializeAndSignFunction,
        SimpleMappingFunction, ThirdPartyAttributableMappingFunction, ThirdPartyAttributableVerificationFunction,
    },
    traits::SessionParameters,
};

pub(crate) type NodeId = usize;

pub(crate) trait SpecificNode: Sized {
    type Inner;
    fn as_arc(&self) -> &Arc<Self::Inner>;
    fn from_arc(arc: Arc<Self::Inner>) -> Self;

    fn new(inner: Self::Inner) -> Self {
        Self::from_arc(Arc::new(inner))
    }

    fn as_ref(&self) -> &Self::Inner {
        self.as_arc()
    }
}

pub(crate) trait GeneralizedNode {
    fn id(&self) -> NodeId;
    fn get_strong_ref(&self) -> Self;
}

impl<T: SpecificNode> GeneralizedNode for T {
    fn id(&self) -> NodeId {
        // Using the pointer adderss of `Arc` to uniquely identify nodes. A little hacky.
        Arc::as_ptr(self.as_arc()) as NodeId
    }

    fn get_strong_ref(&self) -> Self {
        Self::from_arc(self.as_arc().clone())
    }
}

#[derive_where::derive_where(Debug)]
pub struct ComputeScalarNode<SP: SessionParameters>(Arc<ComputeScalar<SP>>);

#[derive_where::derive_where(Debug)]
pub(crate) struct ComputeScalar<SP: SessionParameters> {
    pub(crate) store_in: ComputedScalarTag,
    pub(crate) function: ScalarFunction<SP>,
    pub(crate) args: BTreeMap<String, ComputeScalarArg<SP>>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> SpecificNode for ComputeScalarNode<SP> {
    type Inner = ComputeScalar<SP>;
    fn as_arc(&self) -> &Arc<Self::Inner> {
        &self.0
    }
    fn from_arc(arc: Arc<Self::Inner>) -> Self {
        Self(arc)
    }
}

impl<SP: SessionParameters> ComputeScalarNode<SP> {
    // TODO: add `unwrap_or_shallow_clone()`
    pub(crate) fn shallow_clone(&self) -> ComputeScalar<SP> {
        ComputeScalar {
            store_in: self.0.store_in.clone(),
            function: self.0.function.clone(),
            args: args_to_owned(&self.0.args),
            dependencies: node_slice_to_owned(&self.0.dependencies),
        }
    }

    // TODO: do any of these methods belong in a trait?

    // TODO: should this be a method on ComputeScalar instead?
    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self.shallow_clone();
        node.args = args_with_replacements(&node.args, replacements)?;
        node.dependencies = vec_with_replacements(&node.dependencies, replacements)?;
        Ok(Self::new(node))
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let mut node = self.shallow_clone();
        node.store_in = node.store_in.with_added_prefix(prefix);
        Self::new(node)
    }

    pub fn with_dependency(&self, dependency: impl Into<Dependency<SP>>) -> Self {
        let dependency = dependency.into();
        let mut node = self.shallow_clone();
        node.dependencies.push(dependency);
        Self::new(node)
    }

    // TODO: inefficient, we don't really need to copy dependencies
    pub(crate) fn without_dependencies(&self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        Self::new(node)
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for ComputeScalarNode<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub struct CollectNode<SP: SessionParameters>(Arc<Collect<SP>>);

#[derive_where::derive_where(Debug)]
pub(crate) struct Collect<SP: SessionParameters> {
    pub(crate) store_in: CollectedTag,
    pub(crate) values: CollectArg<SP>,
    pub(crate) group: PartyGroup<SP::Verifier>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> SpecificNode for CollectNode<SP> {
    type Inner = Collect<SP>;
    fn as_arc(&self) -> &Arc<Self::Inner> {
        &self.0
    }
    fn from_arc(arc: Arc<Self::Inner>) -> Self {
        Self(arc)
    }
}

impl<SP: SessionParameters> CollectNode<SP> {
    pub(crate) fn shallow_clone(&self) -> Collect<SP> {
        Collect {
            store_in: self.0.store_in.clone(),
            values: self.0.values.get_strong_ref(),
            group: self.0.group.clone(),
            dependencies: node_slice_to_owned(&self.0.dependencies),
        }
    }

    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self.shallow_clone();
        node.values = node_with_replacements(&self.0.values, replacements)?;
        node.dependencies = vec_with_replacements(&node.dependencies, replacements)?;
        Ok(Self::new(node))
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let mut node = self.shallow_clone();
        node.store_in = node.store_in.with_added_prefix(prefix);
        Self::new(node)
    }

    pub fn with_dependency(&self, dependency: impl Into<Dependency<SP>>) -> Self {
        let dependency = dependency.into();
        let mut node = self.shallow_clone();
        node.dependencies.push(dependency);
        Self::new(node)
    }

    pub(crate) fn without_dependencies(&self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        Self::new(node)
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) enum ComputeMappingKind<SP: SessionParameters> {
    Simple {
        function: SimpleMappingFunction<SP>,
    },
    WithReveal {
        function: SenderAttributableWithRevealMappingFunction<SP>,
        verification: EvidenceVerificationFunction<SP>,
        verification_args: BTreeMap<String, ComputeMappingArg<SP>>,
    },
    ThirdPartyAttributable {
        function: ThirdPartyAttributableMappingFunction<SP>,
        verification: ThirdPartyAttributableVerificationFunction<SP>,
    },
}

impl<SP: SessionParameters> ComputeMappingKind<SP> {
    pub(crate) fn shallow_clone(&self) -> Self {
        match self {
            Self::Simple { function } => Self::Simple {
                function: function.clone(),
            },
            Self::WithReveal {
                function,
                verification,
                verification_args,
            } => Self::WithReveal {
                function: function.clone(),
                verification: verification.clone(),
                verification_args: args_to_owned(verification_args),
            },
            Self::ThirdPartyAttributable { function, verification } => Self::ThirdPartyAttributable {
                function: function.clone(),
                verification: verification.clone(),
            },
        }
    }

    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut kind = self.shallow_clone();
        match &mut kind {
            Self::Simple { .. } => {}
            Self::WithReveal { verification_args, .. } => {
                *verification_args = args_with_replacements(verification_args, replacements)?;
            }
            Self::ThirdPartyAttributable { .. } => {}
        }
        Ok(kind)
    }
}

#[derive_where::derive_where(Debug)]
pub struct ComputeMappingNode<SP: SessionParameters>(Arc<ComputeMapping<SP>>);

#[derive_where::derive_where(Debug)]
pub(crate) struct ComputeMapping<SP: SessionParameters> {
    pub(crate) store_in: ComputedMappingTag,
    pub(crate) args: BTreeMap<String, ComputeMappingArg<SP>>,
    pub(crate) kind: ComputeMappingKind<SP>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> SpecificNode for ComputeMappingNode<SP> {
    type Inner = ComputeMapping<SP>;
    fn as_arc(&self) -> &Arc<Self::Inner> {
        &self.0
    }
    fn from_arc(arc: Arc<Self::Inner>) -> Self {
        Self(arc)
    }
}

impl<SP: SessionParameters> ComputeMappingNode<SP> {
    pub(crate) fn shallow_clone(&self) -> ComputeMapping<SP> {
        ComputeMapping {
            store_in: self.0.store_in.clone(),
            args: args_to_owned(&self.0.args),
            kind: self.0.kind.shallow_clone(),
            dependencies: node_slice_to_owned(&self.0.dependencies),
        }
    }

    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self.shallow_clone();
        node.args = args_with_replacements(&node.args, replacements)?;
        node.kind = node.kind.with_replacements(replacements)?;
        node.dependencies = vec_with_replacements(&node.dependencies, replacements)?;
        Ok(Self::new(node))
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let mut node = self.shallow_clone();
        node.store_in = node.store_in.with_added_prefix(prefix);
        Self::new(node)
    }

    pub fn with_dependency(&self, dependency: impl Into<Dependency<SP>>) -> Self {
        let dependency = dependency.into();
        let mut node = self.shallow_clone();
        node.dependencies.push(dependency);
        Self::new(node)
    }

    pub(crate) fn without_dependencies(&self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        Self::new(node)
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for ComputeMappingNode<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeMapping(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub struct SerializeAndSignNode<SP: SessionParameters>(Arc<SerializeAndSign<SP>>);

#[derive_where::derive_where(Debug)]
pub(crate) struct SerializeAndSign<SP: SessionParameters> {
    pub(crate) store_in: LocalSignedTag,
    pub(crate) function: SerializeAndSignFunction<SP>,
    pub(crate) data: SerializeAndSignArg<SP>,
    pub(crate) serde_adapter: SerdeAdapter<SP::WireFormat>,
    pub(crate) message_name: FullName,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> SpecificNode for SerializeAndSignNode<SP> {
    type Inner = SerializeAndSign<SP>;
    fn as_arc(&self) -> &Arc<Self::Inner> {
        &self.0
    }
    fn from_arc(arc: Arc<Self::Inner>) -> Self {
        Self(arc)
    }
}

impl<SP: SessionParameters> SerializeAndSignNode<SP> {
    pub(crate) fn shallow_clone(&self) -> SerializeAndSign<SP> {
        SerializeAndSign {
            store_in: self.0.store_in.clone(),
            function: self.0.function.clone(),
            data: self.0.data.get_strong_ref(),
            serde_adapter: self.0.serde_adapter.clone(),
            message_name: self.0.message_name.clone(),
            dependencies: node_slice_to_owned(&self.0.dependencies),
        }
    }

    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self.shallow_clone();
        node.data = node_with_replacements(&node.data, replacements)?;
        node.dependencies = vec_with_replacements(&node.dependencies, replacements)?;
        Ok(Self::new(node))
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let mut node = self.shallow_clone();
        node.store_in = node.store_in.with_added_prefix(prefix);
        node.message_name = node.message_name.with_added_prefix(prefix);
        Self::new(node)
    }

    pub fn with_dependency(&self, dependency: impl Into<Dependency<SP>>) -> Self {
        let dependency = dependency.into();
        let mut node = self.shallow_clone();
        node.dependencies.push(dependency);
        Self::new(node)
    }

    pub(crate) fn without_dependencies(&self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        Self::new(node)
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for SerializeAndSignNode<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::SerializeAndSign(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub struct DeserializeAndCheckNode<SP: SessionParameters>(Arc<DeserializeAndCheck<SP>>);

#[derive_where::derive_where(Debug)]
pub(crate) struct DeserializeAndCheck<SP: SessionParameters> {
    pub(crate) store_in: ReceivedTag,
    pub(crate) function: DeserializeFunction<SP>,
    pub(crate) data: ReceiveNode<SP>,
    pub(crate) serde_adapter: SerdeAdapter<SP::WireFormat>,
    pub(crate) message_name: FullName,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> SpecificNode for DeserializeAndCheckNode<SP> {
    type Inner = DeserializeAndCheck<SP>;
    fn as_arc(&self) -> &Arc<Self::Inner> {
        &self.0
    }
    fn from_arc(arc: Arc<Self::Inner>) -> Self {
        Self(arc)
    }
}

impl<SP: SessionParameters> DeserializeAndCheckNode<SP> {
    pub(crate) fn shallow_clone(&self) -> DeserializeAndCheck<SP> {
        DeserializeAndCheck {
            store_in: self.0.store_in.clone(),
            function: self.0.function.clone(),
            data: self.0.data.get_strong_ref(),
            serde_adapter: self.0.serde_adapter.clone(),
            message_name: self.0.message_name.clone(),
            dependencies: node_slice_to_owned(&self.0.dependencies),
        }
    }

    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self.shallow_clone();
        node.data = node_with_replacements(&node.data, replacements)?;
        node.dependencies = vec_with_replacements(&node.dependencies, replacements)?;
        Ok(Self::new(node))
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let mut node = self.shallow_clone();
        node.store_in = node.store_in.with_added_prefix(prefix);
        node.message_name = node.message_name.with_added_prefix(prefix);
        Self::new(node)
    }

    pub fn with_dependency(&self, dependency: impl Into<Dependency<SP>>) -> Self {
        let dependency = dependency.into();
        let mut node = self.shallow_clone();
        node.dependencies.push(dependency);
        Self::new(node)
    }

    pub(crate) fn without_dependencies(&self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        Self::new(node)
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for DeserializeAndCheckNode<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::DeserializeAndCheck(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub struct DirectMessageNode<SP: SessionParameters>(Arc<DirectMessage<SP>>);

#[derive_where::derive_where(Debug)]
pub(crate) struct DirectMessage<SP: SessionParameters> {
    pub(crate) store_in: SentTag,
    pub(crate) data: SerializeAndSignNode<SP>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> SpecificNode for DirectMessageNode<SP> {
    type Inner = DirectMessage<SP>;
    fn as_arc(&self) -> &Arc<Self::Inner> {
        &self.0
    }
    fn from_arc(arc: Arc<Self::Inner>) -> Self {
        Self(arc)
    }
}

impl<SP: SessionParameters> DirectMessageNode<SP> {
    pub(crate) fn shallow_clone(&self) -> DirectMessage<SP> {
        DirectMessage {
            store_in: self.0.store_in.clone(),
            data: self.0.data.get_strong_ref(),
            dependencies: node_slice_to_owned(&self.0.dependencies),
        }
    }

    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self.shallow_clone();
        node.data = node_with_replacements(&node.data, replacements)?;
        node.dependencies = vec_with_replacements(&node.dependencies, replacements)?;
        Ok(Self::new(node))
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let mut node = self.shallow_clone();
        node.store_in = node.store_in.with_added_prefix(prefix);
        Self::new(node)
    }

    pub fn with_dependency(&self, dependency: impl Into<Dependency<SP>>) -> Self {
        let dependency = dependency.into();
        let mut node = self.shallow_clone();
        node.dependencies.push(dependency);
        Self::new(node)
    }

    pub(crate) fn without_dependencies(&self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        Self::new(node)
    }
}

#[derive_where::derive_where(Debug)]
pub struct ReceiveNode<SP: SessionParameters>(Arc<Receive<SP>>);

#[derive_where::derive_where(Debug)]
pub(crate) struct Receive<SP: SessionParameters> {
    pub(crate) store_in: RemoteSignedTag,
    pub(crate) message_name: FullName,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> SpecificNode for ReceiveNode<SP> {
    type Inner = Receive<SP>;
    fn as_arc(&self) -> &Arc<Self::Inner> {
        &self.0
    }
    fn from_arc(arc: Arc<Self::Inner>) -> Self {
        Self(arc)
    }
}

impl<SP: SessionParameters> ReceiveNode<SP> {
    pub(crate) fn shallow_clone(&self) -> Receive<SP> {
        Receive {
            store_in: self.0.store_in.clone(),
            message_name: self.0.message_name.clone(),
            dependencies: node_slice_to_owned(&self.0.dependencies),
        }
    }

    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self.shallow_clone();
        node.dependencies = vec_with_replacements(&node.dependencies, replacements)?;
        Ok(Self::new(node))
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let mut node = self.shallow_clone();
        node.store_in = node.store_in.with_added_prefix(prefix);
        node.message_name = node.message_name.with_added_prefix(prefix);
        Self::new(node)
    }

    pub fn with_dependency(&self, dependency: impl Into<Dependency<SP>>) -> Self {
        let dependency = dependency.into();
        let mut node = self.shallow_clone();
        node.dependencies.push(dependency);
        Self::new(node)
    }

    pub(crate) fn without_dependencies(&self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        Self::new(node)
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for ReceiveNode<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::Receive(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

#[derive(Debug)]
pub struct ScalarArgumentNode(Arc<ScalarArgument>);

#[derive(Debug)]
pub(crate) struct ScalarArgument {
    pub(crate) store_in: ScalarArgumentTag,
    pub(crate) name: String,
}

impl SpecificNode for ScalarArgumentNode {
    type Inner = ScalarArgument;
    fn as_arc(&self) -> &Arc<Self::Inner> {
        &self.0
    }
    fn from_arc(arc: Arc<Self::Inner>) -> Self {
        Self(arc)
    }
}

impl ScalarArgumentNode {
    pub(crate) fn shallow_clone(&self) -> ScalarArgument {
        ScalarArgument {
            store_in: self.0.store_in.clone(),
            name: self.0.name.clone(),
        }
    }

    pub(crate) fn with_replacements<SP: SessionParameters>(
        &self,
        _replacements: &BTreeMap<usize, AnyNode<SP>>,
    ) -> Result<Self, RuntimeError> {
        Ok(Self::new(self.shallow_clone()))
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let mut node = self.shallow_clone();
        node.store_in = node.store_in.with_added_prefix(prefix);
        Self::new(node)
    }

    pub(crate) fn without_dependencies(&self) -> Self {
        self.get_strong_ref()
    }
}

fn display_args<SP, T>(args: &BTreeMap<String, T>) -> String
where
    SP: SessionParameters,
    AnyNode<SP>: From<T>,
    T: GeneralizedNode,
{
    // TODO: we don't need `get_strong_ref()` if we have AnyNodeRef
    args.iter()
        .map(|(name, arg)| format!("{}={}", name, AnyNode::from(arg.get_strong_ref()).store_in()))
        .join(", ")
}

fn display_dependencies<SP, T>(dependencies: &[T]) -> String
where
    SP: SessionParameters,
    AnyNode<SP>: From<T>,
    T: GeneralizedNode,
{
    if dependencies.is_empty() {
        String::new()
    } else {
        // TODO: we don't need `get_strong_ref()` if we have AnyNodeRef
        format!(
            " when {}",
            dependencies
                .iter()
                .map(|dependency| AnyNode::from(dependency.get_strong_ref()).store_in().to_string())
                .join(", ")
        )
    }
}

impl<SP: SessionParameters> Display for ComputeScalarNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} = {}({}){}",
            self.0.store_in,
            self.0.function,
            display_args(&self.0.args),
            display_dependencies(&self.0.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for ComputeMappingNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = {}(*, {}){}",
            self.0.store_in,
            self.0.kind,
            display_args(&self.0.args),
            display_dependencies(&self.0.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for ComputeMappingKind<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Simple { function } => write!(f, "{function}"),
            Self::WithReveal { function, .. } => write!(f, "{function}"),
            Self::ThirdPartyAttributable { function, .. } => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters> Display for CollectNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} = collect({}){}",
            self.0.store_in,
            AnyNode::from(self.0.values.get_strong_ref()).store_in(),
            display_dependencies(&self.0.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for SerializeAndSignNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <serialize_and_sign>(*, {}){}",
            self.0.store_in,
            AnyNode::from(self.0.data.get_strong_ref()).store_in(),
            display_dependencies(&self.0.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for DeserializeAndCheckNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <deserialize_and_check>(*, {}){}",
            self.0.store_in,
            AnyNode::from(self.0.data.get_strong_ref()).store_in(),
            display_dependencies(&self.0.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for DirectMessageNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <send>(*, {}){}",
            self.0.store_in,
            AnyNode::from(self.0.data.get_strong_ref()).store_in(),
            display_dependencies(&self.0.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for ReceiveNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <receive {}>(*){}",
            self.0.store_in,
            self.0.message_name,
            display_dependencies(&self.0.dependencies)
        )
    }
}

impl Display for ScalarArgumentNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{} = <argument {}>", self.0.store_in, self.0.name,)
    }
}

// TODO: change name; it doesn't really mention args explicitly, it's just a mapping of BTreeMap
pub(crate) fn args_to_owned<T>(args: &BTreeMap<String, T>) -> BTreeMap<String, T>
where
    T: GeneralizedNode,
{
    args.iter()
        .map(|(name, arg)| (name.clone(), arg.get_strong_ref()))
        .collect()
}

fn node_slice_to_owned<T>(nodes: &[T]) -> Vec<T>
where
    T: GeneralizedNode,
{
    nodes.iter().map(|node| node.get_strong_ref()).collect()
}

fn node_with_replacements<SP, T>(node: &T, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<T, RuntimeError>
where
    SP: SessionParameters,
    T: GeneralizedNode + TryFrom<AnyNode<SP>>,
{
    if let Some(new_node) = replacements.get(&node.id()) {
        let new_node = new_node
            .get_strong_ref()
            .try_into()
            .map_err(|_| RuntimeError::new("Replacement of an unsupported type"))?;
        Ok(new_node)
    } else {
        Ok(node.get_strong_ref())
    }
}

// TODO: can we take `args` by value?
fn args_with_replacements<SP, T>(
    args: &BTreeMap<String, T>,
    replacements: &BTreeMap<usize, AnyNode<SP>>,
) -> Result<BTreeMap<String, T>, RuntimeError>
where
    SP: SessionParameters,
    T: GeneralizedNode + TryFrom<AnyNode<SP>>,
{
    let mut new_args = BTreeMap::new();
    for (name, arg) in args {
        new_args.insert(name.clone(), node_with_replacements(arg, replacements)?);
    }
    Ok(new_args)
}

fn vec_with_replacements<SP, T>(
    nodes: &Vec<T>,
    replacements: &BTreeMap<usize, AnyNode<SP>>,
) -> Result<Vec<T>, RuntimeError>
where
    SP: SessionParameters,
    T: GeneralizedNode + TryFrom<AnyNode<SP>>,
{
    let mut new_vec = Vec::new();
    for node in nodes {
        new_vec.push(node_with_replacements(node, replacements)?);
    }
    Ok(new_vec)
}
