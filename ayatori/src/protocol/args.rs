use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use itertools::Itertools;

use super::{
    node::{Node, alias, constant},
    tag::Tag,
    traits::SessionParameters,
    value::{Erasable, Value},
};
use crate::error::LocalError;

#[derive(Debug)]
pub struct Args<SP: SessionParameters> {
    signer: Arc<SP::Signer>,
    my_id: SP::Verifier,
    values: BTreeMap<String, Value>,
}

impl<SP: SessionParameters> Args<SP> {
    pub(crate) fn new(
        signer: &Arc<SP::Signer>,
        my_id: &SP::Verifier,
        values: BTreeMap<Tag, Value>,
    ) -> Result<Self, LocalError> {
        // TODO (#11): for now checking if there are name clashes.
        // If we encounter a situation where we do need arguments with the same name but different TagKind,
        // we need to rethink this.
        let duplicates = values.keys().duplicates_by(|tag| tag.short_name()).collect::<Vec<_>>();
        if !duplicates.is_empty() {
            return Err(LocalError::new(format!("Duplicate names of arguments: {duplicates:?}")));
        }

        Ok(Self {
            my_id: my_id.clone(),
            signer: signer.clone(),
            values: values
                .into_iter()
                .map(|(tag, value)| (tag.short_name().to_string(), value))
                .collect(),
        })
    }

    pub(crate) fn signer(&self) -> &SP::Signer {
        self.signer.as_ref()
    }

    pub fn my_id(&self) -> &SP::Verifier {
        &self.my_id
    }

    pub(crate) fn get_value(&self, name: &str) -> Result<&Value, LocalError> {
        self.values.get(name).ok_or_else(|| {
            LocalError::new(format!(
                "Value {name} is not present in the Args (have: {})",
                self.values.keys().join(", ")
            ))
        })
    }

    pub fn get<T: Erasable>(&self, name: &str) -> Result<&T, LocalError> {
        self.get_value(name)?.downcast_ref::<T>()
    }

    pub fn get_map<T: Clone + Erasable>(&self, name: &str) -> Result<BTreeMap<&SP::Verifier, &T>, LocalError> {
        let value_map = self.get::<BTreeMap<SP::Verifier, Value>>(name)?;
        value_map
            .iter()
            .map(|(id, value)| value.downcast_ref::<T>().map(|value_ref| (id, value_ref)))
            .collect()
    }

    pub fn get_shared_data<T: Erasable>(&self) -> Result<&T, LocalError> {
        self.get_value("shared_data")?.downcast_ref::<T>()
    }
}

#[derive(Debug, Default)]
pub struct ProtocolArgs<SP: SessionParameters>(BTreeMap<String, Node<SP>>);

impl<SP: SessionParameters> ProtocolArgs<SP> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn input<T: Erasable>(self, name: &str, value: T) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), constant(name, value));
        Self(args)
    }

    pub fn input_node(self, name: &str, value: &Node<SP>) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), value.get_strong_ref());
        Self(args)
    }

    pub fn get(&self, name: &str) -> Result<&Node<SP>, LocalError> {
        self.0
            .get(name)
            .ok_or_else(|| LocalError::new(format!("Argument {name} was not found")))
    }

    pub(crate) fn with_aliases(self, signature: ProtocolSignature) -> Result<(Self, Vec<Node<SP>>), LocalError> {
        let mut new_nodes = BTreeMap::new();
        for name in signature.0.iter() {
            let node = self.0.get(name).ok_or_else(|| {
                LocalError::new(format!("{name} is in the signature but not among the given arguments"))
            })?;
            let alias = alias(name, node);
            new_nodes.insert(name.to_string(), alias);
        }
        Ok((Self(new_nodes), self.0.into_values().collect()))
    }
}

#[derive(Debug, Default)]
pub struct ProtocolSignature(BTreeSet<String>);

impl ProtocolSignature {
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    pub fn input(self, name: &str) -> Self {
        let mut args = self.0;
        args.insert(name.to_string());
        Self(args)
    }
}
