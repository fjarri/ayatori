use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
};

use itertools::Itertools;

use super::{
    message::VerifiedValue,
    tag::FullName,
    value::{Erasable, SerdeAdapter, Value},
};
use crate::{
    errors::LocalError,
    execution::{SessionData, SessionId},
    traits::SessionParameters,
};

#[derive_where::derive_where(Debug)]
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

#[derive_where::derive_where(Debug)]
pub struct DeserializeArgs<SP: SessionParameters> {
    serde_adapter: SerdeAdapter<SP::WireFormat>,
    value: Value,
    expected_senders: Option<BTreeSet<SP::Verifier>>,
}

impl<SP: SessionParameters> DeserializeArgs<SP> {
    pub(crate) fn new(
        session_data: &SessionData<SP>,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        value: Value,
    ) -> Result<Self, LocalError> {
        let message_name = value.downcast_ref::<VerifiedValue<SP>>()?.metadata().full_name();
        let expected_senders = session_data.expected_senders(message_name);
        Ok(Self {
            serde_adapter,
            value,
            expected_senders,
        })
    }

    pub fn expected_senders(&self) -> Option<&BTreeSet<SP::Verifier>> {
        self.expected_senders.as_ref()
    }

    pub fn serde_adapter(&self) -> &SerdeAdapter<SP::WireFormat> {
        &self.serde_adapter
    }

    pub(crate) fn verified_value(&self) -> &VerifiedValue<SP> {
        self.value
            .downcast_ref::<VerifiedValue<SP>>()
            .expect("the value type was already checked in the constructor")
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub struct Args<SP: SessionParameters> {
    session_id: SessionId<SP>,
    my_id: SP::Verifier,
    values: BTreeMap<String, Value>,
}

impl<SP: SessionParameters> Args<SP> {
    pub(crate) fn new(
        session_id: &SessionId<SP>,
        my_id: &SP::Verifier,
        values: BTreeMap<String, Value>,
    ) -> Result<Self, LocalError> {
        Ok(Self {
            session_id: session_id.clone(),
            my_id: my_id.clone(),
            values,
        })
    }

    pub fn my_id(&self) -> &SP::Verifier {
        &self.my_id
    }

    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_id
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
