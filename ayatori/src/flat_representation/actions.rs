use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
};

use super::rules::OnError;
use crate::{
    entities::{
        AnyTag, ComputedMappingTag, ComputedScalarTag, DeserializeFunction, FullName, LocalSignedBCTag,
        LocalSignedDMTag, MappingFunction, MappingTag, MergedScalarTag, ReceivedTag, RemoteSignedTag, ScalarFunction,
        ScalarTag, SentBCTag, SentDMTag, SerdeAdapter, SerializeAndSignBCFunction, SerializeAndSignDMFunction,
    },
    traits::SessionParameters,
};

#[derive_where::derive_where(Debug)]
pub(crate) struct ComputeScalarAction<SP: SessionParameters> {
    pub(crate) store_in: ComputedScalarTag,
    pub(crate) function: ScalarFunction<SP>,
    pub(crate) args: BTreeMap<String, ScalarTag>,
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ComputeMappingElementAction<SP: SessionParameters> {
    pub(crate) store_in: ComputedMappingTag,
    pub(crate) index: SP::Verifier,
    pub(crate) function: MappingFunction<SP>,
    pub(crate) args: BTreeMap<String, AnyTag>,
    pub(crate) on_error: OnError,
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ComputeSerializeAndSignScalarAction<SP: SessionParameters> {
    pub(crate) store_in: LocalSignedBCTag,
    pub(crate) function: SerializeAndSignBCFunction<SP>,
    pub(crate) data: ScalarTag,
    pub(crate) message_name: FullName,
    pub(crate) serde_adapter: SerdeAdapter<SP::WireFormat>,
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ComputeSerializeAndSignElementAction<SP: SessionParameters> {
    pub(crate) store_in: LocalSignedDMTag,
    pub(crate) index: SP::Verifier,
    pub(crate) function: SerializeAndSignDMFunction<SP>,
    pub(crate) data: AnyTag,
    pub(crate) message_name: FullName,
    pub(crate) serde_adapter: SerdeAdapter<SP::WireFormat>,
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ComputeDeserializeElementAction<SP: SessionParameters> {
    pub(crate) store_in: ReceivedTag,
    pub(crate) index: SP::Verifier,
    pub(crate) function: DeserializeFunction<SP>,
    pub(crate) data: RemoteSignedTag,
    pub(crate) serde_adapter: SerdeAdapter<SP::WireFormat>,
    pub(crate) expected_senders: BTreeSet<SP::Verifier>,
    pub(crate) on_error: OnError,
}

#[derive_where::derive_where(Debug)]
pub(crate) struct SendBCAction<SP: SessionParameters> {
    pub(crate) store_in: SentBCTag,
    pub(crate) to_send: LocalSignedBCTag,
    pub(crate) destinations: BTreeSet<SP::Verifier>,
}

#[derive_where::derive_where(Debug)]
pub(crate) struct SendDMAction<SP: SessionParameters> {
    pub(crate) store_in: SentDMTag,
    pub(crate) to_send: LocalSignedDMTag,
    pub(crate) destination: SP::Verifier,
}

#[derive_where::derive_where(Debug)]
pub(crate) struct CollectAction<SP: SessionParameters> {
    pub(crate) store_in: ScalarTag,
    pub(crate) values: MappingTag,
    pub(crate) sources: BTreeSet<SP::Verifier>,
}

#[derive(Debug)]
pub(crate) struct MergeScalarAction {
    pub(crate) store_in: MergedScalarTag,
    pub(crate) left: ScalarTag,
    pub(crate) right: ScalarTag,
}

#[derive_where::derive_where(Debug)]
pub(crate) enum Action<SP: SessionParameters> {
    ComputeScalar(ComputeScalarAction<SP>),
    ComputeMappingElement(ComputeMappingElementAction<SP>),
    ComputeSerializeAndSignScalar(ComputeSerializeAndSignScalarAction<SP>),
    ComputeSerializeAndSignElement(ComputeSerializeAndSignElementAction<SP>),
    ComputeDeserializeElement(ComputeDeserializeElementAction<SP>),
    SendBC(SendBCAction<SP>),
    SendDM(SendDMAction<SP>),
    Collect(CollectAction<SP>),
    MergeScalar(MergeScalarAction),
}
