use alloc::{collections::BTreeMap, format, string::String};

use super::ruleset::Arg;
use crate::{
    error::LocalError,
    protocol::{PartyId, PrivateInputs, PublicInputs, Tag, Value},
};

#[derive(Debug)]
pub(crate) struct Storage<Id> {
    scalars: BTreeMap<Tag, Value>,
    mappings: BTreeMap<Tag, BTreeMap<Id, Value>>,
}

impl<Id: PartyId> Storage<Id> {
    pub fn new(public_inputs: PublicInputs, private_inputs: PrivateInputs) -> Self {
        let mut scalars = BTreeMap::new();
        scalars.extend(
            private_inputs
                .into_inner()
                .into_iter()
                .map(|(name, value)| (Tag::computed(&name), value)),
        );
        scalars.extend(
            public_inputs
                .into_inner()
                .into_iter()
                .map(|(name, value)| (Tag::computed(&name), value)),
        );
        Self {
            scalars,
            mappings: BTreeMap::new(),
        }
    }

    pub fn contains(&self, tag: &Tag) -> bool {
        self.scalars.contains_key(tag)
    }

    pub fn get(&self, tag: &Tag) -> Result<Value, LocalError> {
        Ok(self
            .scalars
            .get(tag)
            .ok_or_else(|| LocalError::new(format!("Scalar {tag} not found in storage")))?
            .clone())
    }

    pub fn set(&mut self, tag: &Tag, value: Value) -> Result<(), LocalError> {
        match self.scalars.insert(tag.clone(), value) {
            None => Ok(()),
            Some(_) => Err(LocalError::new(format!("Scalar {tag} already has an associated value"))),
        }
    }

    pub fn get_dict(&self, tag: &Tag) -> Result<&BTreeMap<Id, Value>, LocalError> {
        self.mappings
            .get(tag)
            .ok_or_else(|| LocalError::new(format!("Array {tag} not found in storage")))
    }

    pub fn get_dict_as_value(&self, tag: &Tag) -> Result<Value, LocalError> {
        let dict = self.get_dict(tag)?.clone();
        Ok(Value::new(dict))
    }

    pub fn get_elem(&self, tag: &Tag, id: &Id) -> Result<Value, LocalError> {
        Ok(self
            .get_dict(tag)?
            .get(id)
            .ok_or_else(|| LocalError::new(format!("{tag}[{id:?}] not found in storage")))?
            .clone())
    }

    pub fn set_elem(&mut self, tag: &Tag, id: &Id, value: Value) -> Result<(), LocalError> {
        let mapping = self.mappings.entry(tag.clone()).or_default();
        match mapping.insert(id.clone(), value) {
            None => Ok(()),
            Some(_) => Err(LocalError::new(format!(
                "{tag}[{id:?}] already has an associated value"
            ))),
        }
    }

    pub fn get_scalar_args(&self, tags: BTreeMap<String, Tag>) -> Result<BTreeMap<String, Value>, LocalError> {
        tags.into_iter()
            .map(|(name, tag)| self.get(&tag).map(|value| (name, value)))
            .collect::<Result<BTreeMap<_, _>, LocalError>>()
    }

    pub fn get_scalar_or_array_args(
        &self,
        index: &Id,
        tags: BTreeMap<String, Arg>,
    ) -> Result<BTreeMap<String, Value>, LocalError> {
        tags.into_iter()
            .map(|(name, arg)| match arg {
                Arg::Scalar(tag) => self.get(&tag).map(|value| (name.clone(), value)),
                Arg::ArrayElem(tag) => self.get_elem(&tag, index).map(|value| (name.clone(), value)),
            })
            .collect::<Result<BTreeMap<_, _>, LocalError>>()
    }
}
