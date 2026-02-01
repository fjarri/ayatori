use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use itertools::Itertools;

use super::{
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
        let duplicates = values.keys().duplicates_by(|tag| tag.name()).collect::<Vec<_>>();
        if !duplicates.is_empty() {
            return Err(LocalError::new(format!("Duplicate names of arguments: {duplicates:?}")));
        }

        Ok(Self {
            my_id: my_id.clone(),
            signer: signer.clone(),
            values: values
                .into_iter()
                .map(|(tag, value)| (tag.name().to_string(), value))
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
        self.values
            .get(name)
            .ok_or_else(|| LocalError::new(format!("Value {name} is present in the Args")))
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
