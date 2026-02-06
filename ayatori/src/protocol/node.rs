use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display},
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::fmt::Debug;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    args::{Args, ProtocolArgs},
    function::{
        ArrayFunction, ComputeError, ScalarFunction, WrappedArrayFunction, WrappedArrayFunctionPrivate,
        WrappedScalarFunction, WrappedScalarFunctionPrivate,
    },
    party::PartyGroup,
    tag::{FullName, Tag},
    traits::{InnerProtocol, SessionParameters},
    value::{Erasable, SerdeAdapter, SerializedValue, Value},
};
use crate::{error::LocalError, session::SignedValue};

// `Node` intentionally does not implement `Clone` - our clones are shallow, which may be confusing for the user.
#[derive(Debug)]
pub struct Node<SP: SessionParameters>(Arc<TypedNode<SP>>);

impl<SP: SessionParameters> Node<SP> {
    pub(crate) fn new(typed_node: TypedNode<SP>) -> Self {
        Self(Arc::new(typed_node))
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.0.group()
    }

    #[must_use]
    pub fn with_dependencies(self, dependencies: &[&Self]) -> Self {
        Self::new(self.unwrap_or_shallow_clone().with_dependencies(dependencies))
    }

    #[must_use]
    pub fn with_store_in(self, name: &str) -> Self {
        Self::new(self.unwrap_or_shallow_clone().with_store_in(name))
    }

    pub(crate) fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }

    pub(crate) fn id(&self) -> usize {
        // A little hacky. Is there a better way?
        Arc::as_ptr(&self.0) as usize
    }

    pub(crate) fn store_in(&self) -> &Tag {
        self.0.store_in()
    }

    pub(crate) fn dependencies(&self) -> &[Node<SP>] {
        self.0.dependencies()
    }

    pub(crate) fn kind(&self) -> &NodeKind<SP> {
        self.0.kind()
    }

    pub(crate) fn all_dependencies(&self) -> Box<dyn Iterator<Item = &Node<SP>> + '_> {
        self.0.all_dependencies()
    }

    pub(crate) fn unwrap_or_shallow_clone(self) -> TypedNode<SP> {
        Arc::try_unwrap(self.0).unwrap_or_else(|arc| arc.shallow_clone())
    }

    pub(crate) fn with_replacements(self, replacements: &BTreeMap<usize, Node<SP>>) -> Node<SP> {
        Self::new(self.unwrap_or_shallow_clone().with_replacements(replacements))
    }

    pub(crate) fn with_prefix(self, prefix: &str) -> Self {
        Self::new(self.unwrap_or_shallow_clone().with_prefix(prefix))
    }

    pub fn shallow_display(&self) -> String {
        format!("{}", self.0.as_ref())
    }
}

impl<SP: SessionParameters> Display for Node<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let mut nodes_to_process = vec![self.get_strong_ref()];
        let mut nodes_seen = BTreeSet::<usize>::new();

        while let Some(node) = nodes_to_process.pop() {
            writeln!(f, "{}", node.shallow_display())?;
            nodes_seen.insert(node.id());
            nodes_to_process.extend(node.all_dependencies().filter_map(|dependency| {
                if nodes_seen.contains(&dependency.id()) {
                    None
                } else {
                    Some(dependency.get_strong_ref())
                }
            }));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct TypedNode<SP: SessionParameters> {
    store_in: Tag,
    kind: NodeKind<SP>,
    dependencies: Vec<Node<SP>>,
}

impl<SP: SessionParameters> TypedNode<SP> {
    pub fn store_in(&self) -> &Tag {
        &self.store_in
    }

    pub fn dependencies(&self) -> &[Node<SP>] {
        &self.dependencies
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.kind.group()
    }

    pub fn kind(&self) -> &NodeKind<SP> {
        &self.kind
    }

    #[must_use]
    pub fn with_dependencies(self, dependencies: &[&Node<SP>]) -> Self {
        let mut new_node = self;
        new_node
            .dependencies
            .extend(dependencies.iter().map(|dependency| dependency.get_strong_ref()));
        new_node
    }

    #[must_use]
    pub fn with_store_in(self, name: &str) -> Self {
        let mut new_node = self;
        new_node.store_in = new_node.store_in.with_name(name);
        new_node
    }

    pub fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            dependencies: nodes_to_owned(self.dependencies.iter()),
            kind: self.kind.shallow_clone(),
        }
    }

    pub fn all_dependencies(&self) -> Box<dyn Iterator<Item = &Node<SP>> + '_> {
        Box::new(self.dependencies.iter().chain(self.kind.all_dependencies()))
    }

    pub fn with_replacements(self, replacements: &BTreeMap<usize, Node<SP>>) -> Self {
        let mut new_node = self;
        maybe_replace_slice(&mut new_node.dependencies, replacements);
        new_node.kind.replace(replacements);
        new_node
    }

    pub fn with_prefix(self, prefix: &str) -> Self {
        let mut new_node = self;
        new_node.store_in = new_node.store_in.with_added_prefix(prefix);
        new_node
    }
}

impl<SP: SessionParameters> Display for TypedNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{} = {}", self.store_in, self.kind)?;
        if !self.dependencies.is_empty() {
            write!(
                f,
                " <- {}",
                self.dependencies
                    .iter()
                    .map(|dependency| dependency.store_in().to_string())
                    .join(", ")
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum NodeKind<SP: SessionParameters> {
    ComputeScalar {
        function: ScalarFunction<SP>,
        args: Vec<Node<SP>>,
    },
    ComputeArray {
        function: ArrayFunction<SP>,
        group: PartyGroup<SP::Verifier>,
        args: Vec<Node<SP>>,
    },
    Serialize {
        data: Node<SP>,
        group: PartyGroup<SP::Verifier>,
        adapter: SerdeAdapter<SP::WireFormat>,
    },
    DirectMessage {
        data: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Collect {
        values: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Receive {
        group: PartyGroup<SP::Verifier>,
    },
}

impl<SP: SessionParameters> Display for NodeKind<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ComputeScalar { function, args } => {
                write!(
                    f,
                    "{function}({})",
                    args.iter().map(|arg| arg.store_in().to_string()).join(", ")
                )
            }
            Self::ComputeArray {
                function,
                group: _group,
                args,
            } => {
                write!(
                    f,
                    "{function}[]({})",
                    args.iter().map(|arg| arg.store_in().to_string()).join(", ")
                )
            }
            Self::DirectMessage { data, group: _group } => {
                write!(f, "direct_message({})", data.store_in())
            }
            Self::Collect { values, group: _group } => {
                write!(f, "collect({})", values.store_in())
            }
            Self::Receive { group: _group } => write!(f, "receive()"),
            Self::Serialize {
                data,
                group: _group,
                adapter: _adapter,
            } => write!(f, "serialize({})", data.store_in()),
        }
    }
}

fn nodes_to_owned<'a, SP: SessionParameters>(nodes: impl Iterator<Item = &'a Node<SP>>) -> Vec<Node<SP>> {
    nodes.map(|node| node.get_strong_ref()).collect()
}

impl<SP: SessionParameters> NodeKind<SP> {
    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        match self {
            Self::ComputeArray { group, .. }
            | Self::DirectMessage { group, .. }
            | Self::Receive { group, .. }
            | Self::Serialize { group, .. } => Some(group),
            Self::Collect { .. } | Self::ComputeScalar { .. } => None,
        }
    }

    pub fn shallow_clone(&self) -> Self {
        match self {
            Self::ComputeScalar { function, args } => Self::ComputeScalar {
                function: function.clone(),
                args: nodes_to_owned(args.iter()),
            },
            Self::ComputeArray { function, group, args } => Self::ComputeArray {
                function: function.clone(),
                group: group.clone(),
                args: nodes_to_owned(args.iter()),
            },
            Self::DirectMessage { data, group } => Self::DirectMessage {
                data: data.get_strong_ref(),
                group: group.clone(),
            },
            Self::Collect { values, group } => Self::Collect {
                values: values.get_strong_ref(),
                group: group.clone(),
            },
            Self::Receive { group } => Self::Receive { group: group.clone() },
            Self::Serialize { data, group, adapter } => Self::Serialize {
                data: data.get_strong_ref(),
                group: group.clone(),
                adapter: adapter.clone(),
            },
        }
    }

    pub fn all_dependencies(&self) -> Box<dyn Iterator<Item = &Node<SP>> + '_> {
        match self {
            Self::ComputeScalar { args, .. } | Self::ComputeArray { args, .. } => Box::new(args.iter()),
            Self::Collect { values, .. } => Box::new(core::iter::once(values)),
            Self::Serialize { data, .. } => Box::new(core::iter::once(data)),
            Self::DirectMessage { data, .. } => Box::new(core::iter::once(data)),
            Self::Receive { .. } => Box::new(core::iter::empty()),
        }
    }

    pub fn replace(&mut self, replacements: &BTreeMap<usize, Node<SP>>) {
        match self {
            Self::ComputeScalar { args, .. } => maybe_replace_slice(args, replacements),
            Self::ComputeArray { args, .. } => maybe_replace_slice(args, replacements),
            Self::Collect { values, .. } => maybe_replace(values, replacements),
            Self::Serialize { data, .. } => maybe_replace(data, replacements),
            Self::DirectMessage { data, .. } => maybe_replace(data, replacements),
            Self::Receive { .. } => {}
        }
    }
}

fn maybe_replace<SP: SessionParameters>(node: &mut Node<SP>, replacements: &BTreeMap<usize, Node<SP>>) {
    if let Some(replacement) = replacements.get(&node.id()) {
        *node = replacement.get_strong_ref()
    }
}

fn maybe_replace_slice<SP: SessionParameters>(nodes: &mut [Node<SP>], replacements: &BTreeMap<usize, Node<SP>>) {
    for node in nodes {
        maybe_replace(node, replacements)
    }
}

pub(crate) fn constant<SP: SessionParameters, Ret: Erasable>(name: &str, value: Ret) -> Node<SP> {
    let erased_value = Value::new(value);
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new_pre_erased(name, move |_args| {
                Ok(erased_value.clone())
            })),
            args: Vec::new(),
        },
    };
    Node::new(inner)
}

pub(crate) fn alias<SP: SessionParameters>(name: &str, node: &Node<SP>) -> Node<SP> {
    let orig_tag = node.store_in().clone();
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new_pre_erased("alias", move |args| {
                args.get_value(orig_tag.name()).cloned().map_err(ComputeError::Local)
            })),
            args: [node.get_strong_ref()].into(),
        },
    };
    Node::new(inner)
}

pub fn compute_scalar<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(Args<SP>) -> Result<Ret, ComputeError>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new(function)),
            args: nodes_to_owned(args.iter().cloned()),
        },
    };
    Ok(Node::new(inner))
}

pub fn compute_scalar_private<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, Args<SP>) -> Result<Ret, ComputeError>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Private(WrappedScalarFunctionPrivate::new(function)),
            args: nodes_to_owned(args.iter().cloned()),
        },
    };
    Ok(Node::new(inner))
}

pub fn compute_array<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            function: ArrayFunction::Public(WrappedArrayFunction::new(function)),
            group: group.clone(),
            args: nodes_to_owned(args.iter().cloned()),
        },
    };
    Ok(Node::new(inner))
}

pub fn compute_array_private<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new(function)),
            group: group.clone(),
            args: nodes_to_owned(args.iter().cloned()),
        },
    };
    Ok(Node::new(inner))
}

pub fn verify<SP: SessionParameters>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<(), ComputeError>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    let groups = args.iter().filter_map(|arg| arg.group()).collect::<Vec<_>>();
    // TODO (#29): support compute-array with only scalar args (the group needs to be given explicitly)
    let group = *groups
        .first()
        .ok_or_else(|| LocalError::new("There must be at least one array argument"))?;
    if groups.iter().any(|g| g != &group) {
        return Err(LocalError::new("The group of all arguments must be the same"));
    }

    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            function: ArrayFunction::Public(WrappedArrayFunction::new(function)),
            group: group.clone(),
            args: nodes_to_owned(args.iter().cloned()),
        },
    };
    Ok(Node::new(inner))
}

/// A wrapper to convert `dyn CryptoRngCore` to a sized `impl CryptoRngCore`,
/// since some RustCrypto libraries don't accept a `?Sized` RNG.
struct Rng<'a>(&'a mut dyn CryptoRngCore);

impl signature::rand_core::RngCore for Rng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), signature::rand_core::Error> {
        self.0.try_fill_bytes(bytes)
    }
}

impl signature::rand_core::CryptoRng for Rng<'_> {}

fn serialize<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    id: &SP::Verifier,
    args: Args<SP>,
    value_name: &str,
    message_name: &FullName,
    serde_adapter: &SerdeAdapter<SP::WireFormat>,
) -> Result<Value, ComputeError> {
    let value = args.get_value(value_name)?;
    let serialized_value = serde_adapter.serialize(value)?;
    let mut typed_rng = Rng(rng);
    let signed_value = SignedValue::<SP>::new(&mut typed_rng, args.signer(), message_name, id, serialized_value)?;
    Ok(Value::new(signed_value))
}

pub(crate) fn serialize_function<SP: SessionParameters>(
    store_in: &Tag,
    data: &Node<SP>,
    adapter: &SerdeAdapter<SP::WireFormat>,
) -> ArrayFunction<SP> {
    let adapter = adapter.clone();
    let value_name = data.store_in().name().to_string();
    let message_name = store_in.full_name().clone();
    ArrayFunction::Private(WrappedArrayFunctionPrivate::new_pre_erased(
        "serialize",
        move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>| {
            serialize::<SP>(rng, id, args, &value_name, &message_name, &adapter)
        },
    ))
}

pub fn broadcast<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
    scalar: &Node<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, LocalError> {
    if scalar.group().is_some() {
        return Err(LocalError::new(
            "`scalar` argument of `broadcast()` must be a scalar node",
        ));
    }

    let serialize_and_sign = Node::new(TypedNode {
        store_in: Tag::signed(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::Serialize {
            data: scalar.get_strong_ref(),
            group: group.clone(),
            adapter: message.serde_adapter.clone(),
        },
    });

    let send_node = Node::new(TypedNode {
        store_in: Tag::sent(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::DirectMessage {
            data: serialize_and_sign,
            group: group.clone(),
        },
    });

    collect(&send_node)
}

pub fn send<SP: SessionParameters>(message: &ProtocolMessage<SP>, array: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let group = array
        .group()
        .ok_or_else(|| LocalError::new("`array` argument of `send()` must be an array node"))?
        .clone();

    let serialize_and_sign = Node::new(TypedNode {
        store_in: Tag::signed(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::Serialize {
            data: array.get_strong_ref(),
            group: group.clone(),
            adapter: message.serde_adapter.clone(),
        },
    });

    let send_node = Node::new(TypedNode {
        store_in: Tag::sent(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::DirectMessage {
            data: serialize_and_sign,
            group,
        },
    });

    collect(&send_node)
}

fn deserialize<SP: SessionParameters>(args: Args<SP>, message: &ProtocolMessage<SP>) -> Result<Value, ComputeError> {
    let received = args.get::<SerializedValue>(&message.name)?;
    message
        .serde_adapter
        .deserialize(received)
        .map_err(|_err| ComputeError::Data)
}

pub fn receive<SP: SessionParameters>(message: &ProtocolMessage<SP>, group: &PartyGroup<SP::Verifier>) -> Node<SP> {
    let received = Node::new(TypedNode {
        store_in: Tag::received(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::Receive { group: group.clone() },
    });

    let cloned_message = message.clone();

    Node::new(TypedNode {
        store_in: Tag::deserialized(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [received].into(),
            function: ArrayFunction::Public(WrappedArrayFunction::new_pre_erased(
                "deserialize",
                move |_id: &SP::Verifier, args: Args<SP>| deserialize::<SP>(args, &cloned_message),
            )),
            group: group.clone(),
        },
    })
}

pub fn collect<SP: SessionParameters>(values: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let group = values
        .group()
        .ok_or_else(|| LocalError::new("`values` argument of `collect()` must be an array node"))?
        .clone();

    Ok(Node::new(TypedNode {
        store_in: values.store_in().collected(),
        dependencies: Vec::new(),
        kind: NodeKind::Collect {
            values: values.get_strong_ref(),
            group,
        },
    }))
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub struct ProtocolMessage<SP: SessionParameters> {
    name: String,
    serde_adapter: SerdeAdapter<SP::WireFormat>,
}

impl<SP: SessionParameters> ProtocolMessage<SP> {
    pub fn new<T: Erasable + Serialize + for<'de> Deserialize<'de>>(name: &str) -> Self {
        Self {
            name: name.into(),
            serde_adapter: SerdeAdapter::new::<T>(),
        }
    }
}

fn prefix_nodes<SP: SessionParameters>(prefix: &str, root: Node<SP>, terminate_at: Vec<Node<SP>>) -> Node<SP> {
    let root_id = root.id();
    let mut nodes_to_process: Vec<_> = [root].into();
    let mut replacement_nodes = terminate_at
        .iter()
        .map(|node| (node.id(), node.get_strong_ref()))
        .collect::<BTreeMap<_, _>>();

    while let Some(node) = nodes_to_process.pop() {
        if replacement_nodes.contains_key(&node.id()) {
            continue;
        }

        if node
            .all_dependencies()
            .all(|dependency| replacement_nodes.contains_key(&dependency.id()))
        {
            let old_id = node.id();
            let new_node = node.with_replacements(&replacement_nodes).with_prefix(prefix);
            replacement_nodes.insert(old_id, new_node);
            continue;
        }

        nodes_to_process.push(node.get_strong_ref());
        nodes_to_process.extend(node.all_dependencies().filter_map(|dependency| {
            if replacement_nodes.contains_key(&dependency.id()) {
                None
            } else {
                Some(dependency.get_strong_ref())
            }
        }));
    }

    replacement_nodes.remove(&root_id).expect("The root node was processed")
}

// TODO: can we avoid passing `my_id` explicitly?
pub fn call_protocol<SP: SessionParameters, P: InnerProtocol<SP>>(
    prefix: &str,
    my_id: &SP::Verifier,
    build_data: &P::BuildData,
    args: ProtocolArgs<SP>,
) -> Result<Node<SP>, LocalError> {
    let signature = P::signature();
    let (aliased_args, original_nodes) = args.with_aliases(signature)?;
    let output = P::build(my_id, build_data, aliased_args)?;
    Ok(prefix_nodes(prefix, output, original_nodes))
}
