use alloc::{collections::BTreeMap, format};

use crate::{
    error::LocalError,
    protocol::{PartyId, Tag, Value},
};

#[derive(Debug)]
pub(crate) struct Storage<Id> {
    scalars: BTreeMap<Tag, Value>,
    mappings: BTreeMap<Tag, BTreeMap<Id, Value>>,
}

impl<Id: PartyId> Storage<Id> {
    pub fn new() -> Self {
        Self {
            scalars: BTreeMap::new(),
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
}
