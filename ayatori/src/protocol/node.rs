use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    args::Args,
    function::{
        ArrayFunction, ComputeError, ScalarFunction, WrappedArrayFunction, WrappedArrayFunctionPrivate,
        WrappedScalarFunction, WrappedScalarFunctionPrivate,
    },
    party::PartyGroup,
    tag::Tag,
    traits::{Protocol, SessionParameters},
    value::{Erasable, SerdeAdapter, SerializedValue, Value},
};
use crate::{error::LocalError, session::SignedValue};

fn nodes_to_owned<'a, SP: SessionParameters>(nodes: impl Iterator<Item = &'a Node<SP>>) -> Vec<Node<SP>> {
    nodes.map(|node| node.get_strong_ref()).collect()
}

fn with_replacements<'a, SP: SessionParameters>(
    nodes: impl Iterator<Item = &'a Node<SP>>,
    replacements: &BTreeMap<usize, Node<SP>>,
) -> Vec<Node<SP>> {
    nodes
        .map(|node| replacements.get(&node.id()).unwrap_or(node).get_strong_ref())
        .collect()
}

// `Node` intentionally does not implement `Clone` - our clones are shallow, which may be confusing for the user.
#[derive(Debug)]
pub struct Node<SP: SessionParameters>(Arc<TypedNode<SP>>);

impl<SP: SessionParameters> Node<SP> {
    pub(crate) fn new(typed_node: TypedNode<SP>) -> Self {
        Self(Arc::new(typed_node))
    }

    #[must_use]
    pub fn with_dependencies(self, dependencies: &[&Node<SP>]) -> Self {
        let new_node = TypedNode {
            store_in: self.0.store_in.clone(),
            kind: self.0.kind.shallow_clone(),
            dependencies: nodes_to_owned(dependencies.iter().cloned()),
        };
        Self::new(new_node)
    }

    #[must_use]
    pub fn with_store_in(self, name: &str) -> Self {
        let typed_node = TypedNode {
            store_in: self.0.store_in.with_name(name),
            kind: self.0.kind.shallow_clone(),
            dependencies: nodes_to_owned(self.0.dependencies.iter()),
        };
        Self::new(typed_node)
    }

    pub fn with_shared_data(self) -> Result<Self, LocalError> {
        let typed_node = TypedNode {
            store_in: self.0.store_in.clone(),
            kind: self.0.kind.with_shared_data()?,
            dependencies: nodes_to_owned(self.0.dependencies.iter()),
        };
        Ok(Self::new(typed_node))
    }

    pub(crate) fn id(&self) -> usize {
        // A little hacky. Is there a better way?
        Arc::as_ptr(&self.0) as usize
    }

    pub(crate) fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.0.group()
    }

    pub(crate) fn kind(&self) -> &NodeKind<SP> {
        self.0.kind()
    }

    pub(crate) fn store_in(&self) -> &Tag {
        self.0.store_in()
    }

    pub fn dependencies(&self) -> &[Node<SP>] {
        self.0.dependencies()
    }

    pub(crate) fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }

    pub(crate) fn all_dependencies(&self) -> Vec<Self> {
        self.0.all_dependencies()
    }

    pub(crate) fn with_replacements(&self, replacements: &BTreeMap<usize, Self>) -> Self {
        let typed_node = self.0.with_replacements(replacements);
        Self::new(typed_node)
    }

    pub(crate) fn finalize(&self, shared_data: &Self) -> Self {
        let typed_node = self.0.finalize(shared_data);
        Self::new(typed_node)
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

    pub fn all_dependencies(&self) -> Vec<Node<SP>> {
        let mut all_dependencies = nodes_to_owned(self.dependencies.iter());
        all_dependencies.extend(self.kind.all_dependencies());
        all_dependencies
    }

    pub fn with_replacements(&self, replacements: &BTreeMap<usize, Node<SP>>) -> Self {
        let mut kind = self.kind.shallow_clone();
        kind.replace_nodes(replacements);
        Self {
            store_in: self.store_in.clone(),
            kind,
            dependencies: with_replacements(self.dependencies.iter(), replacements),
        }
    }

    pub fn finalize(&self, shared_data: &Node<SP>) -> Self {
        Self {
            store_in: self.store_in.clone(),
            kind: self.kind.finalize(shared_data),
            dependencies: nodes_to_owned(self.dependencies.iter()),
        }
    }
}

#[derive(Debug)]
pub(crate) enum NodeKind<SP: SessionParameters> {
    ComputeScalarWithPlaceholders {
        function: ScalarFunction<SP>,
        args: Vec<Node<SP>>,
        uses_shared_data: bool,
    },
    ComputeArrayWithPlaceholders {
        function: ArrayFunction<SP>,
        group: PartyGroup<SP::Verifier>,
        args: Vec<Node<SP>>,
        uses_shared_data: bool,
    },
    ComputeScalar {
        function: ScalarFunction<SP>,
        args: Vec<Node<SP>>,
        shared_data: Option<Node<SP>>,
    },
    ComputeArray {
        function: ArrayFunction<SP>,
        group: PartyGroup<SP::Verifier>,
        args: Vec<Node<SP>>,
        shared_data: Option<Node<SP>>,
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

impl<SP: SessionParameters> NodeKind<SP> {
    pub fn shallow_clone(&self) -> Self {
        match self {
            Self::ComputeScalarWithPlaceholders {
                function,
                args,
                uses_shared_data,
            } => Self::ComputeScalarWithPlaceholders {
                function: function.clone(),
                args: nodes_to_owned(args.iter()),
                uses_shared_data: *uses_shared_data,
            },
            Self::ComputeArrayWithPlaceholders {
                function,
                group,
                args,
                uses_shared_data,
            } => Self::ComputeArrayWithPlaceholders {
                function: function.clone(),
                group: group.clone(),
                args: nodes_to_owned(args.iter()),
                uses_shared_data: *uses_shared_data,
            },
            Self::ComputeScalar {
                function,
                args,
                shared_data,
            } => Self::ComputeScalar {
                function: function.clone(),
                args: nodes_to_owned(args.iter()),
                shared_data: shared_data.as_ref().map(Node::get_strong_ref),
            },
            Self::ComputeArray {
                function,
                group,
                args,
                shared_data,
            } => Self::ComputeArray {
                function: function.clone(),
                group: group.clone(),
                args: nodes_to_owned(args.iter()),
                shared_data: shared_data.as_ref().map(Node::get_strong_ref),
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
        }
    }

    pub fn all_dependencies(&self) -> Vec<Node<SP>> {
        match self {
            Self::ComputeScalar { args, .. }
            | Self::ComputeArray { args, .. }
            | Self::ComputeScalarWithPlaceholders { args, .. }
            | Self::ComputeArrayWithPlaceholders { args, .. } => nodes_to_owned(args.iter()),
            Self::Collect { values, .. } => [values.get_strong_ref()].into(),
            Self::DirectMessage { data, .. } => [data.get_strong_ref()].into(),
            Self::Receive { .. } => Vec::new(),
        }
    }

    pub fn replace_nodes(&mut self, replacements: &BTreeMap<usize, Node<SP>>) {
        match self {
            Self::ComputeScalar { args, .. } => *args = with_replacements(args.iter(), replacements),
            Self::ComputeArray { args, .. } => *args = with_replacements(args.iter(), replacements),
            Self::ComputeScalarWithPlaceholders { args, .. } => *args = with_replacements(args.iter(), replacements),
            Self::ComputeArrayWithPlaceholders { args, .. } => *args = with_replacements(args.iter(), replacements),
            Self::Collect { values, .. } => *values = replacements.get(&values.id()).unwrap_or(values).get_strong_ref(),
            Self::DirectMessage { data, .. } => *data = replacements.get(&data.id()).unwrap_or(data).get_strong_ref(),
            Self::Receive { .. } => {}
        }
    }

    pub fn finalize(&self, shared_data: &Node<SP>) -> Self {
        match self {
            Self::ComputeScalarWithPlaceholders {
                uses_shared_data,
                args,
                function,
            } => {
                let shared_data = if *uses_shared_data {
                    Some(shared_data.get_strong_ref())
                } else {
                    None
                };
                Self::ComputeScalar {
                    shared_data,
                    args: nodes_to_owned(args.iter()),
                    function: function.clone(),
                }
            }
            Self::ComputeArrayWithPlaceholders {
                uses_shared_data,
                args,
                function,
                group,
            } => {
                let shared_data = if *uses_shared_data {
                    Some(shared_data.get_strong_ref())
                } else {
                    None
                };
                Self::ComputeArray {
                    shared_data,
                    args: nodes_to_owned(args.iter()),
                    function: function.clone(),
                    group: group.clone(),
                }
            }
            _ => self.shallow_clone(),
        }
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        match self {
            Self::ComputeArrayWithPlaceholders { group, .. }
            | Self::ComputeArray { group, .. }
            | Self::DirectMessage { group, .. }
            | Self::Receive { group, .. } => Some(group),
            Self::Collect { .. } | Self::ComputeScalar { .. } | Self::ComputeScalarWithPlaceholders { .. } => None,
        }
    }

    pub fn with_shared_data(&self) -> Result<Self, LocalError> {
        // TODO: disallow double call to `with_shared_data()`
        match self {
            Self::ComputeScalarWithPlaceholders {
                function,
                args,
                uses_shared_data: _uses_shared_data,
            } => Ok(Self::ComputeScalarWithPlaceholders {
                function: function.clone(),
                args: nodes_to_owned(args.iter()),
                uses_shared_data: true,
            }),
            Self::ComputeArrayWithPlaceholders {
                function,
                group,
                args,
                uses_shared_data: _uses_shared_data,
            } => Ok(Self::ComputeArrayWithPlaceholders {
                function: function.clone(),
                group: group.clone(),
                args: nodes_to_owned(args.iter()),
                uses_shared_data: true,
            }),
            _ => Err(LocalError::new("This node does not use shared data")),
        }
    }
}

pub(crate) fn constant<SP: SessionParameters, Ret: Erasable>(name: &str, value: Ret) -> Node<SP> {
    let erased_value = Value::new(value);
    Node::new(TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new_pre_erased(name, move |_args| {
                Ok(erased_value.clone())
            })),
            args: Vec::new(),
            shared_data: None,
        },
    })
}

pub fn compute_scalar<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(Args<SP>) -> Result<Ret, ComputeError>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalarWithPlaceholders {
            function: ScalarFunction::Public(WrappedScalarFunction::new(function)),
            args: nodes_to_owned(args.iter().cloned()),
            uses_shared_data: false,
        },
    }))
}

pub fn compute_scalar_private<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, Args<SP>) -> Result<Ret, ComputeError>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalarWithPlaceholders {
            function: ScalarFunction::Private(WrappedScalarFunctionPrivate::new(function)),
            args: nodes_to_owned(args.iter().cloned()),
            uses_shared_data: false,
        },
    }))
}

pub fn compute_array<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArrayWithPlaceholders {
            function: ArrayFunction::Public(WrappedArrayFunction::new(function)),
            group: group.clone(),
            args: nodes_to_owned(args.iter().cloned()),
            uses_shared_data: false,
        },
    }))
}

pub fn compute_array_private<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArrayWithPlaceholders {
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new(function)),
            group: group.clone(),
            args: nodes_to_owned(args.iter().cloned()),
            uses_shared_data: false,
        },
    }))
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

    compute_array(name, function, group, args)
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
    value_name: String,
    args: Args<SP>,
    message: &ProtocolMessage<SP>,
) -> Result<Value, ComputeError> {
    let value = args.get_value(&value_name)?;
    let serialized_value = message.serde_adapter.serialize(value)?;
    let mut typed_rng = Rng(rng);
    let signed_value = SignedValue::<SP>::new(&mut typed_rng, args.signer(), &message.name, id, serialized_value)?;
    Ok(Value::new(signed_value))
}

pub fn broadcast<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
    scalar: &Node<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, LocalError> {
    let cloned_message = message.clone();
    let value_name = scalar.store_in().name().to_string();

    if scalar.group().is_some() {
        return Err(LocalError::new(
            "`scalar` argument of `broadcast()` must be a scalar node",
        ));
    }

    let serialize_and_sign = Node::new(TypedNode {
        store_in: Tag::signed(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [scalar.get_strong_ref()].into(),
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new_pre_erased(
                "serialize",
                move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>| {
                    serialize::<SP>(rng, id, value_name.to_string(), args, &cloned_message)
                },
            )),
            shared_data: None,
            group: group.clone(),
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
    let cloned_message = message.clone();
    let value_name = array.store_in().name().to_string();

    let group = array
        .group()
        .ok_or_else(|| LocalError::new("`array` argument of `send()` must be an array node"))?
        .clone();

    let serialize_and_sign = Node::new(TypedNode {
        store_in: Tag::signed(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [array.get_strong_ref()].into(),
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new_pre_erased(
                "serialize",
                move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>| {
                    serialize::<SP>(rng, id, value_name.clone(), args, &cloned_message)
                },
            )),
            shared_data: None,
            group: group.clone(),
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
            shared_data: None,
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
        store_in: Tag::collected(values.store_in()),
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

fn finalize_nodes<SP: SessionParameters>(root: Node<SP>, shared_data: &Node<SP>) -> Node<SP> {
    let root_id = root.id();
    let mut nodes_to_process: Vec<_> = [root.get_strong_ref()].into();
    let mut replacement_nodes = BTreeMap::new();

    while let Some(node) = nodes_to_process.pop() {
        if replacement_nodes.contains_key(&node.id()) {
            continue;
        }

        let all_dependencies = node.all_dependencies();

        if all_dependencies
            .iter()
            .all(|dependency| replacement_nodes.contains_key(&dependency.id()))
        {
            let new_node = node.with_replacements(&replacement_nodes);
            let new_node = new_node.finalize(shared_data);

            // TODO: or only save modified nodes?
            replacement_nodes.insert(node.id(), new_node);
        } else {
            nodes_to_process.push(node);
            nodes_to_process.extend(all_dependencies.iter().filter_map(|dependency| {
                if replacement_nodes.contains_key(&dependency.id()) {
                    None
                } else {
                    Some(dependency.get_strong_ref())
                }
            }));
        }
    }

    replacement_nodes.get(&root_id).expect("we processed the root node").get_strong_ref()
}

pub(crate) fn build_protocol<SP: SessionParameters, P: Protocol<SP>>(
    my_id: &SP::Verifier,
    build_data: &P::BuildData,
    shared_data: &Node<SP>,
) -> Result<Node<SP>, LocalError> {
    let node = P::build(my_id, build_data)?;
    Ok(finalize_nodes(node, shared_data))
}
