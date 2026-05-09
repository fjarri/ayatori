use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
};

use crate::{
    entities::{AnyTag, MappingTag, OneOrBoth, RuntimeError, ScalarTag, Value},
    error::{IntoTraced, TResult},
    traits::PartyId,
};

#[derive(Debug)]
pub(crate) struct Storage<Id> {
    scalars: BTreeMap<ScalarTag, Value>,
    mappings: BTreeMap<MappingTag, BTreeMap<Id, Value>>,
}

impl<Id: PartyId> Storage<Id> {
    pub fn new() -> Self {
        Self {
            scalars: BTreeMap::new(),
            mappings: BTreeMap::new(),
        }
    }

    pub fn get_scalar(&self, tag: &ScalarTag) -> TResult<Value, RuntimeError> {
        Ok(self
            .scalars
            .get(tag)
            .ok_or_else(|| RuntimeError::new(format!("Scalar {tag} not found in storage")))?
            .clone())
    }

    pub fn set_scalar(&mut self, tag: &ScalarTag, value: Value) -> TResult<(), RuntimeError> {
        match self.scalars.insert(tag.clone(), value) {
            None => Ok(()),
            Some(_) => Err(RuntimeError::new(format!(
                "Scalar {tag} already has an associated value"
            )))
            .into_traced(),
        }
    }

    pub fn get_mapping(&self, tag: &MappingTag) -> TResult<&BTreeMap<Id, Value>, RuntimeError> {
        self.mappings
            .get(tag)
            .ok_or_else(|| RuntimeError::new(format!("Mapping {tag} not found in storage")))
            .into_traced()
    }

    pub fn get_mapping_as_value(&self, tag: &MappingTag, indices: &BTreeSet<Id>) -> TResult<Value, RuntimeError> {
        let dict = self.get_mapping(tag)?;
        let filtered_dict = indices
            .iter()
            .map(|id| {
                dict.get(id)
                    .ok_or_else(|| RuntimeError::new(format!("{tag}[{id:?}] not found in storage")))
                    .map(|val| (id.clone(), val.clone()))
                    .into_traced()
            })
            .collect::<TResult<BTreeMap<_, _>, _>>()?;
        Ok(Value::new(filtered_dict))
    }

    pub fn get_one_or_both_as_value(&self, left: &ScalarTag, right: &ScalarTag) -> TResult<Value, RuntimeError> {
        let maybe_left = self.scalars.get(left).cloned();
        let maybe_right = self.scalars.get(right).cloned();
        let result = match (maybe_left, maybe_right) {
            (None, None) => {
                return Err(RuntimeError::expect(format!(
                    "Expected either {left} or {right} to be in storage"
                )))
                .into_traced();
            }
            (Some(left), None) => OneOrBoth::Left(left),
            (None, Some(right)) => OneOrBoth::Right(right),
            (Some(left), Some(right)) => OneOrBoth::Both { left, right },
        };
        Ok(Value::new(result))
    }

    pub fn get_elem(&self, tag: &MappingTag, id: &Id) -> TResult<Value, RuntimeError> {
        Ok(self
            .get_mapping(tag)?
            .get(id)
            .ok_or_else(|| RuntimeError::new(format!("{tag}[{id:?}] not found in storage")))?
            .clone())
    }

    pub fn set_elem(&mut self, tag: &MappingTag, id: &Id, value: Value) -> TResult<(), RuntimeError> {
        let mapping = self.mappings.entry(tag.clone()).or_default();
        match mapping.insert(id.clone(), value) {
            None => Ok(()),
            Some(_) => Err(RuntimeError::new(format!(
                "{tag}[{id:?}] already has an associated value"
            )))
            .into_traced(),
        }
    }

    pub fn get_scalar_args(&self, tags: BTreeMap<String, ScalarTag>) -> TResult<BTreeMap<String, Value>, RuntimeError> {
        tags.into_iter()
            .map(|(name, tag)| self.get_scalar(&tag).map(|value| (name, value)))
            .collect::<TResult<BTreeMap<_, _>, RuntimeError>>()
    }

    pub fn get_scalar_or_mapping_args(
        &self,
        index: &Id,
        tags: BTreeMap<String, AnyTag>,
    ) -> TResult<BTreeMap<String, Value>, RuntimeError> {
        tags.into_iter()
            .map(|(name, arg)| match arg {
                AnyTag::Scalar(tag) => self.get_scalar(&tag).map(|value| (name.clone(), value)),
                AnyTag::Mapping(tag) => self.get_elem(&tag, index).map(|value| (name.clone(), value)),
            })
            .collect::<TResult<BTreeMap<_, _>, RuntimeError>>()
    }
}
