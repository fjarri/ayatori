use alloc::{collections::BTreeMap, format, string::String, sync::Arc};

use itertools::Itertools;

use super::{
    tag::FullName,
    value::{Erasable, SerdeAdapter, Value},
};
use crate::{
    errors::LocalError,
    execution::{SessionData, SessionId},
    traits::SessionParameters,
};

#[derive(Debug)]
pub struct SerializeArgs<SP: SessionParameters> {
    signer: Arc<SP::Signer>,
    session_id: SessionId<SP>,
    message_name: FullName,
    serde_adapter: SerdeAdapter<SP::WireFormat>,
    value: Value,
}

impl<SP: SessionParameters> SerializeArgs<SP> {
    pub(crate) fn new(
        signer: &Arc<SP::Signer>,
        session_data: &SessionData<SP>,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        value: Value,
    ) -> Self {
        Self {
            signer: signer.clone(),
            session_id: session_data.id.clone(),
            message_name,
            serde_adapter,
            value,
        }
    }

    pub fn signer(&self) -> &SP::Signer {
        &self.signer
    }

    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_id
    }

    pub fn message_name(&self) -> &FullName {
        &self.message_name
    }

    pub fn serde_adapter(&self) -> &SerdeAdapter<SP::WireFormat> {
        &self.serde_adapter
    }

    pub(crate) fn value(&self) -> &Value {
        &self.value
    }
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub struct Args<SP: SessionParameters> {
    // TODO (#63): this is only needed for serialization/deserialization closures.
    // Seems like a crutch. Can we somehow avoid it?
    store_in_name: FullName,
    session_data: Arc<SessionData<SP>>,
    my_id: SP::Verifier,
    values: BTreeMap<String, Value>,
}

impl<SP: SessionParameters> Args<SP> {
    pub(crate) fn new(
        store_in_name: &FullName,
        session_data: &Arc<SessionData<SP>>,
        my_id: &SP::Verifier,
        values: BTreeMap<String, Value>,
    ) -> Result<Self, LocalError> {
        Ok(Self {
            store_in_name: store_in_name.clone(),
            session_data: session_data.clone(),
            my_id: my_id.clone(),
            values,
        })
    }

    pub(crate) fn store_in_name(&self) -> &FullName {
        &self.store_in_name
    }

    pub(crate) fn session_data(&self) -> &SessionData<SP> {
        &self.session_data
    }

    pub fn my_id(&self) -> &SP::Verifier {
        &self.my_id
    }

    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_data.id
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
}
