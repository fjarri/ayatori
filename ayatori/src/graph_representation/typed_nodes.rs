use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    fmt::{self, Display},
    marker::PhantomData,
};

use itertools::Itertools;

use super::{
    any_node::AnyNode,
    unions::{BroadcastArg, CollectArg, ComputeMappingArg, ComputeScalarArg, Dependency, DirectMessageArg},
};
use crate::{
    entities::{
        CollectedTag, ComputedMappingTag, ComputedScalarTag, DeserializeFunction, FullName, LocalSignedBCTag,
        LocalSignedDMTag, MappingFunction, MergedScalarTag, PartyGroup, ReceivedTag, RemoteSignedTag, RuntimeError,
        ScalarArgumentTag, ScalarFunction, SenderAttributableVerificationFunction,
        SenderAttributableWithRevealMappingFunction, SentBCTag, SentDMTag, SerdeAdapter, SerializeAndSignBCFunction,
        SerializeAndSignDMFunction, SimpleMappingFunction, SimpleScalarFunction, ThirdPartyAttributableMappingFunction,
        ThirdPartyAttributableScalarFunction, ThirdPartyAttributableVerificationFunction, UnionCastError,
    },
    traced_error::TraceableResult,
    traits::SessionParameters,
};

/// A container for typed graph nodes.
#[derive(Debug)]
pub struct Node<T>(Arc<T>);

impl<T> Node<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self(Arc::new(inner))
    }

    pub(crate) fn as_ref(&self) -> &T {
        self.0.as_ref()
    }

    fn id(&self) -> NodeId {
        // Using the pointer adderss of `Arc` to uniquely identify nodes. A little hacky.
        Arc::as_ptr(&self.0).addr()
    }

    fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }

    fn unwrap_or_shallow_clone(self) -> T
    where
        T: ShallowClone,
    {
        Arc::try_unwrap(self.0).unwrap_or_else(|inner| inner.shallow_clone())
    }

    pub(crate) fn try_mutated(self, f: impl FnOnce(T) -> Result<T, RuntimeError>) -> Result<Self, RuntimeError>
    where
        T: ShallowClone,
    {
        Ok(Self::new(f(self.unwrap_or_shallow_clone())?))
    }

    pub(crate) fn mutated(self, f: impl FnOnce(T) -> T) -> Self
    where
        T: ShallowClone,
    {
        Self::new(f(self.unwrap_or_shallow_clone()))
    }

    pub(crate) fn with_replacements<SP>(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError>
    where
        SP: SessionParameters,
        T: ShallowClone + SpecificNode<SP>,
    {
        self.try_mutated(|inner| inner.with_replacements(replacements))
    }

    pub(crate) fn with_added_prefix<SP>(self, prefix: &str) -> Self
    where
        SP: SessionParameters,
        T: ShallowClone + SpecificNode<SP>,
    {
        self.mutated(|inner| inner.with_added_prefix(prefix))
    }

    /// Adds a dependency to the node.
    ///
    /// The node will not be evaluated before all its dependencies are evaluated.
    #[must_use]
    pub fn with_dependency<SP>(self, dependency: impl Into<Dependency<SP>>) -> Self
    where
        SP: SessionParameters,
        T: HasDependencies<SP>,
    {
        self.mutated(|inner| inner.with_dependency(dependency))
    }

    pub(crate) fn without_dependencies<SP>(self) -> Self
    where
        SP: SessionParameters,
        T: ShallowClone + SpecificNode<SP>,
    {
        self.mutated(SpecificNode::without_dependencies)
    }
}

pub(crate) type NodeId = usize;

pub(crate) trait SpecificNode<SP: SessionParameters>: Sized {
    fn dependencies(&self) -> &[Dependency<SP>];

    fn without_dependencies(self) -> Self;

    /// Returns an iterator over all arguments required to compute functions in this node.
    /// Arguments may repeat.
    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>>;

    fn with_added_prefix(self, prefix: &str) -> Self;

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError>;
}

// We want the user to see which nodes can have dependencies (and can have `with_dependency()` called on them),
// but we don't want to expose the specifics of what the trait does.
// So it has to be sealed here (along with ShallowClone it depends on).
mod sealed {
    use super::{Dependency, SessionParameters};

    // We don't want to expose Clone to users because its behavior is not intuitive when applied to a graph node.
    // So we have this method instead that is crate-private and has more defined semantics.
    pub trait ShallowClone {
        /// Clones the node contents but not the child nodes it might have (arguments/dependencies).
        fn shallow_clone(&self) -> Self;
    }

    pub trait HasDependenciesInner<SP: SessionParameters>: ShallowClone {
        fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self;
    }
}

pub(crate) use sealed::ShallowClone;

pub trait HasDependencies<SP: SessionParameters>: sealed::HasDependenciesInner<SP> {}

impl<SP: SessionParameters, T: sealed::HasDependenciesInner<SP>> HasDependencies<SP> for T {}

pub(crate) trait GeneralizedNode {
    fn id(&self) -> NodeId;
    fn get_strong_ref(&self) -> Self;
}

impl<T> GeneralizedNode for Node<T> {
    fn id(&self) -> NodeId {
        self.id()
    }
    fn get_strong_ref(&self) -> Self {
        self.get_strong_ref()
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ComputeScalarKind<SP: SessionParameters> {
    Simple {
        function: SimpleScalarFunction<SP>,
    },
    ThirdPartyAttributable {
        function: ThirdPartyAttributableScalarFunction<SP>,
        verification: ThirdPartyAttributableVerificationFunction<SP>,
    },
}

impl<SP: SessionParameters> ComputeScalarKind<SP> {
    fn shallow_clone(&self) -> Self {
        match self {
            Self::Simple { function } => Self::Simple {
                function: function.clone(),
            },
            Self::ThirdPartyAttributable { function, verification } => Self::ThirdPartyAttributable {
                function: function.clone(),
                verification: verification.clone(),
            },
        }
    }

    fn with_replacements(self, _store_in: &ComputedScalarTag, _replacements: &BTreeMap<usize, AnyNode<SP>>) -> Self {
        self
    }
}

/// A node that executes a user-provided function to compute a scalar value.
#[derive_where::derive_where(Debug)]
pub struct ComputeScalar<SP: SessionParameters> {
    pub(crate) store_in: ComputedScalarTag,
    pub(crate) kind: ComputeScalarKind<SP>,
    pub(crate) args: BTreeMap<String, ComputeScalarArg<SP>>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ComputeScalar<SP> {
    pub(crate) fn function(&self) -> ScalarFunction<SP> {
        match &self.kind {
            ComputeScalarKind::Simple { function } => ScalarFunction::from(function.clone()),
            ComputeScalarKind::ThirdPartyAttributable { function, .. } => {
                ScalarFunction::ThirdPartyAttributable(function.clone())
            }
        }
    }
}

impl<SP: SessionParameters> ShallowClone for ComputeScalar<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            kind: self.kind.shallow_clone(),
            args: args_to_owned(&self.args),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for ComputeScalar<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self;
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        arg_map_to_any_iter(&self.args)
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_btreemap(&mut node.args, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the arguments of node `{}`", node.store_in))?;
        node.kind = node.kind.with_replacements(&node.store_in, replacements);
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for ComputeScalar<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<ComputeScalar<SP>> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

/// A node that collects mapping value elements into a scalar value.
#[derive_where::derive_where(Debug)]
pub struct Collect<SP: SessionParameters> {
    pub(crate) store_in: CollectedTag,
    pub(crate) values: CollectArg<SP>,
    pub(crate) group: Box<dyn PartyGroup<SP::Verifier>>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ShallowClone for Collect<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            values: self.values.get_strong_ref(),
            group: self.group.clone_box(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for Collect<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self;
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        one_arg_to_any_iter(&self.values)
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_node(&mut node.values, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the argument of node `{}`", node.store_in))?;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for Collect<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

/// A node that collects virtual values corresponding to sent direct messages into a scalar value.
#[derive_where::derive_where(Debug)]
pub struct SendAll<SP: SessionParameters> {
    // TODO: a separate tag?
    pub(crate) store_in: CollectedTag,
    pub(crate) values: Node<SendDM<SP>>,
    pub(crate) destinations: BTreeSet<SP::Verifier>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ShallowClone for SendAll<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            values: self.values.get_strong_ref(),
            destinations: self.destinations.clone(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for SendAll<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self;
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        one_arg_to_any_iter(&self.values)
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_node(&mut node.values, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the argument of node `{}`", node.store_in))?;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for SendAll<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) enum ComputeMappingKind<SP: SessionParameters> {
    Simple {
        function: SimpleMappingFunction<SP>,
    },
    WithReveal {
        function: SenderAttributableWithRevealMappingFunction<SP>,
        verification: SenderAttributableVerificationFunction<SP>,
        verification_args: BTreeMap<String, ComputeMappingArg<SP>>,
    },
    ThirdPartyAttributable {
        function: ThirdPartyAttributableMappingFunction<SP>,
        verification: ThirdPartyAttributableVerificationFunction<SP>,
    },
}

impl<SP: SessionParameters> ComputeMappingKind<SP> {
    fn shallow_clone(&self) -> Self {
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

    fn with_replacements(
        self,
        store_in: &ComputedMappingTag,
        replacements: &BTreeMap<usize, AnyNode<SP>>,
    ) -> Result<Self, RuntimeError> {
        let mut kind = self;
        match &mut kind {
            Self::Simple { .. } | Self::ThirdPartyAttributable { .. } => {}
            Self::WithReveal { verification_args, .. } => {
                replace_in_btreemap(verification_args, replacements).or_with_context(|| {
                    format!("Failed to replace nodes in the verification arguments of node `{store_in}`")
                })?;
            }
        }
        Ok(kind)
    }
}

/// A node that executes a user-provided function to compute elements of a mapping value.
#[derive_where::derive_where(Debug)]
pub struct ComputeMapping<SP: SessionParameters> {
    pub(crate) store_in: ComputedMappingTag,
    pub(crate) args: BTreeMap<String, ComputeMappingArg<SP>>,
    pub(crate) kind: ComputeMappingKind<SP>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ComputeMapping<SP> {
    pub(crate) fn function(&self) -> MappingFunction<SP> {
        match &self.kind {
            ComputeMappingKind::Simple { function } => MappingFunction::from(function.clone()),
            ComputeMappingKind::WithReveal { function, .. } => {
                MappingFunction::SenderAttributableWithReveal(function.clone())
            }
            ComputeMappingKind::ThirdPartyAttributable { function, .. } => {
                MappingFunction::ThirdPartyAttributable(function.clone())
            }
        }
    }
}

impl<SP: SessionParameters> ShallowClone for ComputeMapping<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            args: args_to_owned(&self.args),
            kind: self.kind.shallow_clone(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for ComputeMapping<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        let more_args = match &self.kind {
            ComputeMappingKind::Simple { .. } | ComputeMappingKind::ThirdPartyAttributable { .. } => None,
            ComputeMappingKind::WithReveal { verification_args, .. } => Some(verification_args),
        };
        arg_map_to_any_iter(&self.args).chain(more_args.into_iter().flat_map(arg_map_to_any_iter))
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_btreemap(&mut node.args, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the arguments of node `{}`", node.store_in))?;
        node.kind = node.kind.with_replacements(&node.store_in, replacements)?;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for ComputeMapping<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<ComputeMapping<SP>> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeMapping(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

/// A subtype of mapping computation node that serializes and signs values before sending them to other parties.
#[derive_where::derive_where(Debug)]
pub struct SerializeAndSignBC<SP: SessionParameters> {
    pub(crate) store_in: LocalSignedBCTag,
    pub(crate) function: SerializeAndSignBCFunction<SP>,
    pub(crate) data: BroadcastArg<SP>,
    pub(crate) serde_adapter: SerdeAdapter<SP::WireFormat>,
    pub(crate) message_name: FullName,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ShallowClone for SerializeAndSignBC<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            function: self.function.clone(),
            data: self.data.get_strong_ref(),
            serde_adapter: self.serde_adapter.clone(),
            message_name: self.message_name.clone(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for SerializeAndSignBC<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self;
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        one_arg_to_any_iter(&self.data)
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node.message_name = node.message_name.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_node(&mut node.data, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the argument of node `{}`", node.store_in))?;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for SerializeAndSignBC<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<SerializeAndSignBC<SP>> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::SerializeAndSignBC(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

/// A subtype of mapping computation node that serializes and signs values before sending them to other parties.
#[derive_where::derive_where(Debug)]
pub struct SerializeAndSignDM<SP: SessionParameters> {
    pub(crate) store_in: LocalSignedDMTag,
    pub(crate) function: SerializeAndSignDMFunction<SP>,
    pub(crate) data: DirectMessageArg<SP>,
    pub(crate) serde_adapter: SerdeAdapter<SP::WireFormat>,
    pub(crate) message_name: FullName,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ShallowClone for SerializeAndSignDM<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            function: self.function.clone(),
            data: self.data.get_strong_ref(),
            serde_adapter: self.serde_adapter.clone(),
            message_name: self.message_name.clone(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for SerializeAndSignDM<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self;
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        one_arg_to_any_iter(&self.data)
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node.message_name = node.message_name.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_node(&mut node.data, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the argument of node `{}`", node.store_in))?;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for SerializeAndSignDM<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<SerializeAndSignDM<SP>> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::SerializeAndSignDM(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

/// A subtype of mapping computation node that deserializes and checks values coming from other parties.
#[derive_where::derive_where(Debug)]
pub struct DeserializeAndCheck<SP: SessionParameters> {
    pub(crate) store_in: ReceivedTag,
    pub(crate) function: DeserializeFunction<SP>,
    pub(crate) data: Node<Receive<SP>>,
    pub(crate) serde_adapter: SerdeAdapter<SP::WireFormat>,
    pub(crate) message_name: FullName,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ShallowClone for DeserializeAndCheck<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            function: self.function.clone(),
            data: self.data.get_strong_ref(),
            serde_adapter: self.serde_adapter.clone(),
            message_name: self.message_name.clone(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for DeserializeAndCheck<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self;
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        one_arg_to_any_iter(&self.data)
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node.message_name = node.message_name.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_node(&mut node.data, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the argument of node `{}`", node.store_in))?;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for DeserializeAndCheck<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<DeserializeAndCheck<SP>> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::DeserializeAndCheck(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

/// A node that denotes sending a direct message to other parties.
#[derive_where::derive_where(Debug)]
pub struct SendDM<SP: SessionParameters> {
    pub(crate) store_in: SentDMTag,
    pub(crate) data: Node<SerializeAndSignDM<SP>>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ShallowClone for SendDM<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            data: self.data.get_strong_ref(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for SendDM<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        one_arg_to_any_iter(&self.data)
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_node(&mut node.data, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the argument of node `{}`", node.store_in))?;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for SendDM<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<SendDM<SP>> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::SendDM(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

/// A node that denotes sending a direct message to other parties.
#[derive_where::derive_where(Debug)]
pub struct SendBC<SP: SessionParameters> {
    pub(crate) store_in: SentBCTag,
    pub(crate) data: Node<SerializeAndSignBC<SP>>,
    pub(crate) destinations: BTreeSet<SP::Verifier>,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ShallowClone for SendBC<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            data: self.data.get_strong_ref(),
            destinations: self.destinations.clone(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for SendBC<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self.shallow_clone();
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        one_arg_to_any_iter(&self.data)
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_node(&mut node.data, replacements)
            .or_with_context(|| format!("Failed to replace nodes in the argument of node `{}`", node.store_in))?;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for SendBC<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<SendBC<SP>> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::SendBC(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

/// A nodes that denotes an expected message from other parties.
#[derive_where::derive_where(Debug)]
pub struct Receive<SP: SessionParameters> {
    pub(crate) store_in: RemoteSignedTag,
    pub(crate) message_name: FullName,
    pub(crate) dependencies: Vec<Dependency<SP>>,
}

impl<SP: SessionParameters> ShallowClone for Receive<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            message_name: self.message_name.clone(),
            dependencies: node_slice_to_owned(&self.dependencies),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for Receive<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &self.dependencies
    }

    fn without_dependencies(self) -> Self {
        let mut node = self;
        node.dependencies = Vec::new();
        node
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        core::iter::empty()
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node.message_name = node.message_name.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_slice(&mut node.dependencies, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the dependencies of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

impl<SP: SessionParameters> sealed::HasDependenciesInner<SP> for Receive<SP> {
    fn with_dependency(self, dependency: impl Into<Dependency<SP>>) -> Self {
        let mut node = self;
        let dependency = dependency.into();
        node.dependencies.push(dependency);
        node
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<Receive<SP>> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::Receive(node) => Ok(node),
            _ => Err(UnionCastError),
        }
    }
}

/// A leaf node denoting an input argument to the computation graph.
#[derive_where::derive_where(Debug)]
pub struct ScalarArgument<SP> {
    pub(crate) store_in: ScalarArgumentTag,
    pub(crate) name: String,
    pub(crate) phantom: PhantomData<fn() -> SP>,
}

impl<SP: SessionParameters> ShallowClone for ScalarArgument<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            name: self.name.clone(),
            phantom: PhantomData,
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for ScalarArgument<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &[]
    }

    fn without_dependencies(self) -> Self {
        self
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        core::iter::empty()
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, _replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        Ok(self)
    }
}

/// A node that is reached when one or both of its inputs are available,
/// and merges them into a single value.
#[derive_where::derive_where(Debug)]
pub struct MergeScalars<SP: SessionParameters> {
    pub(crate) store_in: MergedScalarTag,
    pub(crate) left: ComputeScalarArg<SP>,
    pub(crate) right: ComputeScalarArg<SP>,
}

impl<SP: SessionParameters> ShallowClone for MergeScalars<SP> {
    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            left: self.left.get_strong_ref(),
            right: self.right.get_strong_ref(),
        }
    }
}

impl<SP: SessionParameters> SpecificNode<SP> for MergeScalars<SP> {
    fn dependencies(&self) -> &[Dependency<SP>] {
        &[]
    }

    fn without_dependencies(self) -> Self {
        self
    }

    fn all_args(&self) -> impl Iterator<Item = AnyNode<SP>> {
        one_arg_to_any_iter(&self.left).chain(one_arg_to_any_iter(&self.right))
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut node = self;
        node.store_in = node.store_in.with_added_prefix(prefix);
        node
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<Self, RuntimeError> {
        let mut node = self;
        replace_in_node(&mut node.left, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the left argument of node `{}`",
                node.store_in
            )
        })?;
        replace_in_node(&mut node.right, replacements).or_with_context(|| {
            format!(
                "Failed to replace nodes in the right argument of node `{}`",
                node.store_in
            )
        })?;
        Ok(node)
    }
}

fn display_args<SP, T>(args: &BTreeMap<String, T>) -> String
where
    SP: SessionParameters,
    AnyNode<SP>: From<T>,
    T: GeneralizedNode,
{
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
        format!(
            " when {}",
            dependencies
                .iter()
                .map(|dependency| AnyNode::from(dependency.get_strong_ref()).store_in().to_string())
                .join(", ")
        )
    }
}

impl<T: Display> Display for Node<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl<SP: SessionParameters> Display for ComputeScalar<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} = {}({}){}",
            self.store_in,
            self.kind,
            display_args(&self.args),
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for ComputeScalarKind<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Simple { function } => write!(f, "{function}"),
            Self::ThirdPartyAttributable { function, .. } => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters> Display for ComputeMapping<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = {}(*, {}){}",
            self.store_in,
            self.kind,
            display_args(&self.args),
            display_dependencies(&self.dependencies)
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

impl<SP: SessionParameters> Display for Collect<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} = collect({}){}",
            self.store_in,
            self.values.store_in(),
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for SendAll<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} = send_all({}){}",
            self.store_in,
            self.values.as_ref().store_in,
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for SerializeAndSignBC<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <serialize_and_sign_bc>(*, {}){}",
            self.store_in,
            self.data.store_in(),
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for SerializeAndSignDM<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <serialize_and_sign_dm>(*, {}){}",
            self.store_in,
            self.data.store_in(),
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for DeserializeAndCheck<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <deserialize_and_check>(*, {}){}",
            self.store_in,
            self.data.as_ref().store_in,
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for SendDM<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <send>(*, {}){}",
            self.store_in,
            self.data.as_ref().store_in,
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for SendBC<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} = <broadcast>({}){}",
            self.store_in,
            self.data.as_ref().store_in,
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for Receive<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[*] = <receive {}>(*){}",
            self.store_in,
            self.message_name,
            display_dependencies(&self.dependencies)
        )
    }
}

impl<SP: SessionParameters> Display for ScalarArgument<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{} = <argument {}>", self.store_in, self.name)
    }
}

impl<SP: SessionParameters> Display for MergeScalars<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} = <merge {} {}>",
            self.store_in,
            self.left.store_in(),
            self.right.store_in()
        )
    }
}

fn one_arg_to_any_iter<SP, N>(arg: &N) -> impl Iterator<Item = AnyNode<SP>>
where
    SP: SessionParameters,
    N: GeneralizedNode,
    AnyNode<SP>: From<N>,
{
    core::iter::once(AnyNode::from(arg.get_strong_ref()))
}

fn arg_map_to_any_iter<SP, N>(args: &BTreeMap<String, N>) -> impl Iterator<Item = AnyNode<SP>>
where
    SP: SessionParameters,
    N: GeneralizedNode,
    AnyNode<SP>: From<N>,
{
    args.values().map(|node| AnyNode::from(node.get_strong_ref()))
}

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
    nodes.iter().map(GeneralizedNode::get_strong_ref).collect()
}

fn replace_in_node<SP, T>(node: &mut T, replacements: &BTreeMap<usize, AnyNode<SP>>) -> Result<(), RuntimeError>
where
    SP: SessionParameters,
    T: GeneralizedNode + TryFrom<AnyNode<SP>>,
{
    if let Some(new_node) = replacements.get(&node.id()) {
        *node = new_node
            .get_strong_ref()
            .try_into()
            .map_err(|_| RuntimeError::new("Replacement of an unsupported type"))?;
    }
    Ok(())
}

fn replace_in_btreemap<SP, T>(
    collection: &mut BTreeMap<String, T>,
    replacements: &BTreeMap<usize, AnyNode<SP>>,
) -> Result<(), RuntimeError>
where
    SP: SessionParameters,
    T: GeneralizedNode + TryFrom<AnyNode<SP>>,
{
    for node in collection.values_mut() {
        replace_in_node(node, replacements)?;
    }
    Ok(())
}

fn replace_in_slice<SP, T>(
    collection: &mut [T],
    replacements: &BTreeMap<usize, AnyNode<SP>>,
) -> Result<(), RuntimeError>
where
    SP: SessionParameters,
    T: GeneralizedNode + TryFrom<AnyNode<SP>>,
{
    for node in collection.iter_mut() {
        replace_in_node(node, replacements)?;
    }
    Ok(())
}
